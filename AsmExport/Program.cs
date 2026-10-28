using System.Data;
using System.Globalization;
using System.Net.Http.Headers;
using System.Text;
using System.Text.Json;
using ClosedXML.Excel;
using Microsoft.Data.SqlClient;
using Npgsql;
using NpgsqlTypes;

namespace AsmExport;

// ───────────────────────── Logging ─────────────────────────
public sealed class Logger : IDisposable
{
    private readonly StreamWriter _file;
    private readonly StreamWriter _sql;
    private readonly object _lock = new();

    public Logger()
    {
        const string dir = "logs";
        Directory.CreateDirectory(dir);
        var ts = DateTime.Now.ToString("yyyyMMdd_HHmmss");
        var logFile = Path.Combine(dir, $"asm_export_{ts}.log");
        var sqlFile = Path.Combine(dir, $"sql_queries_{ts}.log");
        _file = new StreamWriter(logFile, true, new UTF8Encoding(false)) { AutoFlush = true };
        _sql = new StreamWriter(sqlFile, true, new UTF8Encoding(false)) { AutoFlush = true };
        Info($"Logging initialized. Log file: {logFile}");
        Info($"SQL log file: {sqlFile}");
    }

    private void Write(string level, string msg, bool console)
    {
        lock (_lock)
        {
            _file.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {level} - {msg}");
            if (console) Console.WriteLine($"{level}: {msg}");
        }
    }

    public void Debug(string m) => Write("DEBUG", m, false);
    public void Info(string m) => Write("INFO", m, true);
    public void Warning(string m) => Write("WARNING", m, true);
    public void Error(string m) => Write("ERROR", m, true);

    public void Sql(string m)
    {
        lock (_lock) _sql.WriteLine($"{DateTime.Now:yyyy-MM-dd HH:mm:ss} - {m}");
    }

    public void Dispose()
    {
        _file.Dispose();
        _sql.Dispose();
    }
}

// ───────────────────────── Config (.ini) ─────────────────────────
public sealed class IniConfig
{
    private readonly Dictionary<string, Dictionary<string, string>> _data =
        new(StringComparer.OrdinalIgnoreCase);

    public static IniConfig Load(string path)
    {
        var cfg = new IniConfig();
        if (!File.Exists(path)) return cfg;

        Dictionary<string, string>? current = null;
        foreach (var raw in File.ReadAllLines(path))
        {
            var line = raw.Trim();
            if (line.Length == 0 || line.StartsWith('#') || line.StartsWith(';')) continue;

            if (line.StartsWith('[') && line.EndsWith(']'))
            {
                var name = line[1..^1].Trim();
                current = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                cfg._data[name] = current;
                continue;
            }

            var idx = line.IndexOf('=');
            if (idx <= 0 || current == null) continue;
            current[line[..idx].Trim()] = line[(idx + 1)..].Trim();
        }
        return cfg;
    }

    public bool HasSection(string s) => _data.ContainsKey(s);

    public string Get(string section, string key, string def = "") =>
        _data.TryGetValue(section, out var sec) && sec.TryGetValue(key, out var v) ? v : def;

    public bool Has(string section, string key) =>
        _data.TryGetValue(section, out var sec) && sec.ContainsKey(key);

    public void Set(string section, string key, string value)
    {
        if (!_data.TryGetValue(section, out var sec))
            _data[section] = sec = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        sec[key] = value;
    }
}

// ───────────────────────── Column mapping ─────────────────────────
public enum ColType { Text, Int, Timestamp }

public record ColDef(string Sql, string Pg, ColType Type = ColType.Text);

public static class Schema
{
    public static readonly ColDef[] Columns =
    {
        new("Alias", "alias"),
        new("DeviceName", "device_name"),
        new("IPAddress", "ip_address"),
        new("OwnerID", "owner_id"),
        new("SerialNumber", "serial_number"),
        new("DomainName", "domain_name"),
        new("LogonUser", "logon_user"),
        new("Model", "model"),
        new("SystemType", "system_type"),
        new("AgentVersion", "agent_version"),
        new("LastRespond", "last_respond", ColType.Timestamp),
        new("encrypted", "encrypted"),
        new("GroupName", "group_name"),
        new("ComputerType", "computer_type"),
        new("FIRSTNAME", "firstname"),
        new("LASTNAME", "lastname"),
        new("ADDRESS", "address"),
        new("Remark", "remark"),
        new("MonitorType", "monitor_type"),
        new("Answer", "answer"),
        new("ResponseBy", "response_by"),
        new("WindowOS", "window_os"),
        new("WindowOSFull", "window_os_full"),
        new("NessusAgent", "nessus_agent"),
        new("AssetNumber", "asset_number"),
        new("AgentID", "agent_id"),
        new("StaffID", "staff_id"),
        new("OverMonth", "over_month", ColType.Int),
    };

    public const string SqlServerQuery = """
SELECT         s.Alias,s.DeviceName,s.IPAddress,s.OwnerID,c.SerialNumber,c.DomainName,c.LogonUser,i.Model,'' AS SystemType,c.AgentVersion,s.LastRespond, '' AS encrypted
                ,g.GroupName,c.ComputerType,
                u.FIRSTNAME,u.LASTNAME,u.ADDRESS
                ,'' AS Remark,'' AS MonitorType, '' AS Answer, '' AS ResponseBy,
                o.Version AS WindowOS, o.VersionFull AS WindowOSFull,
                CASE WHEN ck.AgentID IS NULL THEN 'Not Install' ELSE 'Installed' END AS NessusAgent,
                s.AssetNumber,s.AgentID,e.FieldTxt1 as StaffID
                ,datediff(m,s.LastRespond,GETDATE()) AS OverMonth
FROM TB_SYSTEMDEVICE s (NOLOCK)
LEFT JOIN TB_COMPUTER c (NOLOCK) ON c.AgentID=s.AgentID
LEFT JOIN TB_INV_SYSTEM i (NOLOCK) ON i.AgentID=s.AgentID
LEFT JOIN TB_DEVICEGROUP g (NOLOCK) ON g.GroupId=s.GroupID
LEFT JOIN TB_USER u (NOLOCK) ON u.USER_ID=s.OwnerID
LEFT JOIN TB_INV_OS o (NOLOCK)ON o.AgentID=s.AgentID
LEFT JOIN
(
        select distinct c.AgentID
        from [TB_COMPUTER] c
        left join [TB_INV_APPLICATION] a on a.AgentID=c.AgentID
        LEFT JOIN [TB_SOFTWARE] s oN s.id=a.Id
        LEFT JOIN TB_SYSTEMDEVICE p ON p.AgentID=c.AgentID
        LEFT JOIN TB_INV_SYSTEM i ON i.AgentID=c.AgentID
        where s.SoftwareName like '%nessus%'
) ck ON ck.AgentID=s.AgentID
LEFT JOIN TB_Extention e ON e.AgentID=s.AgentID
where s.GroupID not in ('1')
order by s.GroupID,c.ComputerType
""";
}

// ───────────────────────── Program ─────────────────────────
public static class Program
{
    public static async Task<int> Main()
    {
        using var log = new Logger();

        log.Sql(new string('=', 80));
        log.Sql("SQL Query Executed:");
        log.Sql(Schema.SqlServerQuery);
        log.Sql(new string('=', 80));

        try
        {
            log.Info("Starting ASM Data Export Process");

            var config = ReadConfig("conf.ini", log);

            // SQL Server
            log.Info("Connecting to SQL Server...");
            DataTable dt;
            using (var sqlConn = new SqlConnection(BuildSqlServerConnectionString(config, log)))
            {
                sqlConn.Open();
                log.Info("Connected to SQL Server successfully");
                dt = ExecuteQuery(sqlConn, Schema.SqlServerQuery, log);
            }
            log.Info($"Retrieved {dt.Rows.Count} rows from SQL Server");
            log.Info("SQL Server connection closed");

            // Text
            log.Info("Exporting to text file...");
            ExportToText(dt, config.Get("EXPORT", "txt_file"), log);

            // Excel
            log.Info("Exporting to Excel...");
            ExportToExcel(dt, config.Get("EXPORT", "excel_file"), config.Get("EXPORT", "sheet_name"), log);

            // Feishu webhook
            var webhookEnabled = config.Get("WEBHOOK", "enabled", "false")
                .Equals("true", StringComparison.OrdinalIgnoreCase);
            var webhookUrl = config.Get("WEBHOOK", "url");
            log.Info($"Webhook enabled: {webhookEnabled}");
            log.Info($"Webhook URL configured: {!string.IsNullOrEmpty(webhookUrl)}");

            if (webhookEnabled && !string.IsNullOrEmpty(webhookUrl))
            {
                log.Info("Posting to Feishu webhook...");
                await PostToFeishuAsync(dt, webhookUrl, config.Get("WEBHOOK", "csrf_token"), log);
            }
            else
            {
                log.Info("Webhook posting skipped (not enabled or no URL configured)");
            }

            // PostgreSQL (optional)
            try
            {
                log.Info("Connecting to PostgreSQL...");
                using var pg = new NpgsqlConnection(BuildPgConnectionString(config, log));
                pg.Open();
                log.Info("Connected to PostgreSQL successfully");

                var table = config.Get("POSTGRESQL", "table");
                log.Info($"Verifying table {table} in PostgreSQL...");
                CreatePostgresTable(pg, table, log);

                log.Info("Inserting data into PostgreSQL...");
                UpsertPostgresData(pg, dt, table, log);
                log.Info("PostgreSQL connection closed");
            }
            catch (Exception pgEx)
            {
                log.Error($"PostgreSQL export failed: {pgEx.Message}");
                log.Error(pgEx.ToString());
                log.Info("Continuing with text and Excel exports only...");
            }

            log.Info(new string('=', 50));
            log.Info("Data export completed successfully!");
            log.Info(new string('=', 50));
            return 0;
        }
        catch (Exception ex)
        {
            log.Error($"Error occurred: {ex.Message}");
            log.Error(ex.ToString());
            return 1;
        }
    }

    // ───────── Config ─────────
    private static IniConfig ReadConfig(string path, Logger log)
    {
        log.Info($"Reading configuration from {path}");
        var cfg = IniConfig.Load(path);

        void Require(string section, params string[] keys)
        {
            if (!cfg.HasSection(section))
            {
                var m = $"Missing required section [{section}] in configuration file";
                log.Error(m);
                throw new InvalidOperationException(m);
            }
            foreach (var k in keys)
            {
                if (!cfg.Has(section, k))
                {
                    var m = $"Missing required key '{k}' in [{section}] section";
                    log.Error(m);
                    throw new InvalidOperationException(m);
                }
            }
        }

        Require("SQLSERVER", "server", "database", "username", "password");
        Require("POSTGRESQL", "host", "port", "username", "password");
        Require("EXPORT");

        if (!cfg.Has("POSTGRESQL", "database"))
        {
            cfg.Set("POSTGRESQL", "database", "linebot");
            log.Info("Using default PostgreSQL database: linebot");
        }
        if (!cfg.Has("POSTGRESQL", "table"))
        {
            cfg.Set("POSTGRESQL", "table", "asm_data");
            log.Info("Using default PostgreSQL table: asm_data");
        }
        if (!cfg.Has("EXPORT", "txt_file")) cfg.Set("EXPORT", "txt_file", "output.txt");
        if (!cfg.Has("EXPORT", "excel_file")) cfg.Set("EXPORT", "excel_file", "output.xlsx");
        if (!cfg.Has("EXPORT", "sheet_name")) cfg.Set("EXPORT", "sheet_name", "Sheet1");
        if (!cfg.Has("WEBHOOK", "enabled")) cfg.Set("WEBHOOK", "enabled", "false");
        if (!cfg.Has("WEBHOOK", "url")) cfg.Set("WEBHOOK", "url", "");

        log.Info("Configuration loaded successfully");
        log.Debug($"SQL Server: {cfg.Get("SQLSERVER", "server")}/{cfg.Get("SQLSERVER", "database")}");
        log.Debug($"PostgreSQL: {cfg.Get("POSTGRESQL", "host")}/{cfg.Get("POSTGRESQL", "database")}");
        log.Debug($"Webhook enabled: {cfg.Get("WEBHOOK", "enabled")}");
        return cfg;
    }

    // ───────── Connections ─────────
    private static string BuildSqlServerConnectionString(IniConfig c, Logger log)
    {
        var b = new SqlConnectionStringBuilder
        {
            DataSource = c.Get("SQLSERVER", "server"),
            InitialCatalog = c.Get("SQLSERVER", "database"),
            UserID = c.Get("SQLSERVER", "username"),
            Password = c.Get("SQLSERVER", "password"),
            TrustServerCertificate = true,
            Encrypt = SqlConnectionEncryptOption.Optional, // ให้ใกล้เคียง ODBC driver เดิม; เปลี่ยนเป็น Mandatory ถ้าต้องการ
            ConnectTimeout = 30,
        };
        log.Debug($"SQL Server connection (password hidden): SERVER={b.DataSource}; DATABASE={b.InitialCatalog}");
        return b.ConnectionString;
    }

    private static string BuildPgConnectionString(IniConfig c, Logger log)
    {
        var b = new NpgsqlConnectionStringBuilder
        {
            Host = c.Get("POSTGRESQL", "host"),
            Port = int.Parse(c.Get("POSTGRESQL", "port"), CultureInfo.InvariantCulture),
            Database = c.Get("POSTGRESQL", "database"),
            Username = c.Get("POSTGRESQL", "username"),
            Password = c.Get("POSTGRESQL", "password"),
        };
        log.Debug($"PostgreSQL connection: host={b.Host}, port={b.Port}, database={b.Database}");
        return b.ConnectionString;
    }

    // ───────── SQL Server query ─────────
    private static DataTable ExecuteQuery(SqlConnection conn, string query, Logger log)
    {
        log.Debug("Executing SQL query...");
        using var cmd = new SqlCommand(query, conn) { CommandTimeout = 0 };
        using var reader = cmd.ExecuteReader();
        var dt = new DataTable("asm");
        dt.Load(reader);
        log.Info($"Query executed successfully. Retrieved {dt.Rows.Count} rows");
        if (dt.Rows.Count > 0)
        {
            var first = dt.Columns.Cast<DataColumn>()
                .ToDictionary(c => c.ColumnName, c => dt.Rows[0][c]);
            log.Debug($"First row data: {JsonSerializer.Serialize(first)}");
        }
        return dt;
    }

    // ───────── PostgreSQL ─────────
    private static string Q(string id) => "\"" + id.Replace("\"", "\"\"") + "\"";

    private static void Exec(NpgsqlConnection conn, string sql)
    {
        using var cmd = new NpgsqlCommand(sql, conn);
        cmd.ExecuteNonQuery();
    }

    private static void CreatePostgresTable(NpgsqlConnection conn, string table, Logger log)
    {
        var t = Q(table);
        var seq = Q($"{table}_id_seq");

        log.Info($"Dropping existing table {table} if exists...");
        Exec(conn, $"DROP TABLE IF EXISTS {t} CASCADE");
        Exec(conn, $"DROP SEQUENCE IF EXISTS {seq} CASCADE");

        log.Info($"Creating sequence {table}_id_seq...");
        Exec(conn, $"CREATE SEQUENCE {seq}");

        log.Info($"Creating table {table}...");
        Exec(conn, $"""
            CREATE TABLE {t} (
                id INTEGER PRIMARY KEY DEFAULT nextval('{seq}'::regclass),
                alias VARCHAR(255),
                device_name VARCHAR(255) UNIQUE,
                ip_address VARCHAR(50),
                owner_id VARCHAR(50),
                serial_number VARCHAR(255),
                domain_name VARCHAR(255),
                logon_user VARCHAR(255),
                model VARCHAR(255),
                system_type VARCHAR(100),
                agent_version VARCHAR(50),
                last_respond TIMESTAMP,
                "encrypted" VARCHAR(50),
                group_name VARCHAR(255),
                computer_type VARCHAR(100),
                firstname VARCHAR(255),
                lastname VARCHAR(255),
                address TEXT,
                remark TEXT,
                monitor_type VARCHAR(100),
                answer TEXT,
                response_by VARCHAR(255),
                window_os VARCHAR(100),
                window_os_full VARCHAR(255),
                nessus_agent VARCHAR(50),
                asset_number VARCHAR(255),
                agent_id VARCHAR(255),
                staff_id VARCHAR(255),
                over_month INTEGER,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """);

        log.Info("Creating indexes...");
        Exec(conn, $"CREATE INDEX {Q($"idx_{table}_agent_id")} ON {t}(agent_id)");
        Exec(conn, $"CREATE INDEX {Q($"idx_{table}_device_name")} ON {t}(device_name)");

        log.Info($"Table {table} created successfully with UNIQUE constraint on device_name");
    }

    private static void UpsertPostgresData(NpgsqlConnection conn, DataTable dt, string table, Logger log)
    {
        var cols = Schema.Columns;
        var t = Q(table);
        var seq = Q($"{table}_id_seq");

        var colList = string.Join(", ", cols.Select(c => Q(c.Pg)));
        var placeholders = string.Join(", ", cols.Select((_, i) => $"@p{i}"));
        var updateClause = string.Join(", ",
            cols.Where(c => c.Pg != "device_name").Select(c => $"{Q(c.Pg)} = EXCLUDED.{Q(c.Pg)}"))
            + ", updated_at = CURRENT_TIMESTAMP";

        var upsertSql = $"""
            INSERT INTO {t} (id, {colList})
            VALUES (nextval('{seq}'::regclass), {placeholders})
            ON CONFLICT (device_name)
            DO UPDATE SET {updateClause}
            """;
        log.Debug($"UPSERT SQL prepared with {cols.Length} columns");

        // device_name ที่มีอยู่แล้ว
        var deviceNames = dt.Rows.Cast<DataRow>()
            .Select(r => r["DeviceName"] as string)
            .ToList();
        log.Info($"Total device_names to process: {deviceNames.Count}");
        log.Debug($"Sample device_names: {string.Join(", ", deviceNames.Take(5))}");

        var valid = deviceNames.Where(d => !string.IsNullOrEmpty(d)).Select(d => d!).Distinct().ToArray();
        log.Debug($"Valid device_names (not None/empty): {valid.Length}");

        var existing = new HashSet<string>();
        if (valid.Length > 0)
        {
            using var chk = new NpgsqlCommand($"SELECT device_name FROM {t} WHERE device_name = ANY(@names)", conn);
            chk.Parameters.AddWithValue("names", valid);
            using var rd = chk.ExecuteReader();
            while (rd.Read()) existing.Add(rd.GetString(0));
            log.Info($"Existing devices in database: {existing.Count}");
        }
        else
        {
            log.Warning("No valid device_names found");
        }

        const int batchSize = 1000;
        int insertCount = 0, updateCount = 0, errorCount = 0;

        for (int start = 0; start < dt.Rows.Count; start += batchSize)
        {
            var end = Math.Min(start + batchSize, dt.Rows.Count);

            using var tx = conn.BeginTransaction();
            using var cmd = new NpgsqlCommand(upsertSql, conn, tx);
            for (int i = 0; i < cols.Length; i++)
            {
                cmd.Parameters.Add(new NpgsqlParameter($"p{i}", cols[i].Type switch
                {
                    ColType.Int => NpgsqlDbType.Integer,
                    ColType.Timestamp => NpgsqlDbType.Timestamp,
                    _ => NpgsqlDbType.Text,
                }));
            }

            for (int r = start; r < end; r++)
            {
                var row = dt.Rows[r];
                var deviceName = row["DeviceName"] as string;

                for (int i = 0; i < cols.Length; i++)
                {
                    var v = row[cols[i].Sql];
                    cmd.Parameters[i].Value = v is DBNull ? DBNull.Value : Convert.ChangeType(v, TargetType(cols[i].Type), CultureInfo.InvariantCulture);
                }

                // savepoint: ให้ error แถวเดียวไม่ทำให้ทั้ง batch พัง
                Exec2(conn, tx, "SAVEPOINT row_sp");
                try
                {
                    cmd.ExecuteNonQuery();
                    Exec2(conn, tx, "RELEASE SAVEPOINT row_sp");

                    if (deviceName != null && existing.Contains(deviceName)) updateCount++;
                    else
                    {
                        insertCount++;
                        if (deviceName != null) existing.Add(deviceName);
                    }
                }
                catch (Exception ex)
                {
                    errorCount++;
                    Exec2(conn, tx, "ROLLBACK TO SAVEPOINT row_sp");
                    if (errorCount <= 3)
                        log.Error($"Error processing row {r} for device {deviceName}: {ex.Message}");
                    else if (errorCount == 4)
                        log.Info("Suppressing further error details (too many errors)...");
                }
            }

            tx.Commit();
            log.Info($"Processed {end} / {dt.Rows.Count} rows");
        }

        if (errorCount > 0) log.Warning($"{errorCount} rows had errors during processing");
        log.Info($"Successfully processed {dt.Rows.Count} rows in PostgreSQL");
        log.Info($"  - Inserted: {insertCount}");
        log.Info($"  - Updated: {updateCount}");
    }

    private static Type TargetType(ColType t) => t switch
    {
        ColType.Int => typeof(int),
        ColType.Timestamp => typeof(DateTime),
        _ => typeof(string),
    };

    private static void Exec2(NpgsqlConnection conn, NpgsqlTransaction tx, string sql)
    {
        using var cmd = new NpgsqlCommand(sql, conn, tx);
        cmd.ExecuteNonQuery();
    }

    // ───────── File exports ─────────
    private static string Timestamped(string filename)
    {
        var ts = DateTime.Now.ToString("yyyyMMddHHmmss");
        var dir = Path.GetDirectoryName(filename);
        var name = Path.GetFileNameWithoutExtension(filename);
        var ext = Path.GetExtension(filename);
        var result = $"{name}_{ts}{ext}";
        return string.IsNullOrEmpty(dir) ? result : Path.Combine(dir, result);
    }

    private static void EnsureDirectory(string filename, Logger log)
    {
        var dir = Path.GetDirectoryName(filename);
        if (!string.IsNullOrEmpty(dir) && !Directory.Exists(dir))
        {
            Directory.CreateDirectory(dir);
            log.Info($"Created directory: {dir}");
        }
    }

    private static string FormatValue(object? v) => v switch
    {
        null or DBNull => "",
        DateTime d => d.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
        IFormattable f => f.ToString(null, CultureInfo.InvariantCulture),
        _ => v.ToString() ?? "",
    };

    private static string Tsv(string s) =>
        s.IndexOfAny(new[] { '\t', '"', '\r', '\n' }) >= 0 ? "\"" + s.Replace("\"", "\"\"") + "\"" : s;

    private static void ExportToText(DataTable dt, string filename, Logger log)
    {
        var path = Timestamped(filename);
        EnsureDirectory(path, log);

        using var w = new StreamWriter(path, false, new UTF8Encoding(false));
        w.WriteLine(string.Join('\t', dt.Columns.Cast<DataColumn>().Select(c => Tsv(c.ColumnName))));
        foreach (DataRow row in dt.Rows)
            w.WriteLine(string.Join('\t', row.ItemArray.Select(v => Tsv(FormatValue(v)))));

        log.Info($"Data exported to {path}");
    }

    private static void ExportToExcel(DataTable dt, string filename, string sheetName, Logger log)
    {
        var path = Timestamped(filename);
        EnsureDirectory(path, log);

        using var wb = new XLWorkbook();
        var ws = wb.Worksheets.Add(sheetName);
        ws.Cell(1, 1).InsertTable(dt, false); // false = ไม่ทำเป็น Excel Table (เหมือน pandas)
        wb.SaveAs(path);

        log.Info($"Data exported to {path}");
    }

    // ───────── Feishu webhook ─────────
    private static async Task PostToFeishuAsync(DataTable dt, string url, string? csrfToken, Logger log)
    {
        try
        {
            using var http = new HttpClient { Timeout = TimeSpan.FromSeconds(30) };
            int success = 0, error = 0, total = dt.Rows.Count;

            for (int idx = 0; idx < total; idx++)
            {
                var row = dt.Rows[idx];
                var record = new Dictionary<string, object?>();
                foreach (var c in Schema.Columns)
                {
                    var v = row[c.Sql];
                    record[c.Pg] = v switch
                    {
                        DBNull => null,
                        DateTime d => d.ToString("yyyy-MM-dd HH:mm:ss", CultureInfo.InvariantCulture),
                        _ => v,
                    };
                }

                if (idx == 0) log.Debug($"First record sample: {JsonSerializer.Serialize(record)}");

                try
                {
                    using var req = new HttpRequestMessage(HttpMethod.Post, url)
                    {
                        Content = new StringContent(JsonSerializer.Serialize(record), Encoding.UTF8, "application/json"),
                    };
                    if (!string.IsNullOrEmpty(csrfToken))
                        req.Headers.TryAddWithoutValidation("Cookie", $"_csrf_token={csrfToken}");

                    using var resp = await http.SendAsync(req);
                    if (resp.IsSuccessStatusCode && (int)resp.StatusCode == 200)
                    {
                        success++;
                        if ((idx + 1) % 100 == 0)
                            log.Info($"Posted {idx + 1}/{total} records to Feishu webhook");
                    }
                    else
                    {
                        error++;
                        log.Error($"Failed to post record {idx + 1}. Status code: {(int)resp.StatusCode}");
                        log.Error($"Response: {await resp.Content.ReadAsStringAsync()}");
                    }
                }
                catch (Exception ex)
                {
                    error++;
                    log.Error($"Error posting record {idx + 1}: {ex.Message}");
                }
            }

            log.Info($"Successfully posted {success}/{total} records to Feishu webhook");
            if (error > 0) log.Warning($"Failed to post {error} records");
        }
        catch (Exception ex)
        {
            log.Error($"Error posting to Feishu webhook: {ex.Message}");
            log.Error(ex.ToString());
        }
    }
}