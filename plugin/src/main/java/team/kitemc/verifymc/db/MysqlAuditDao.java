package team.kitemc.verifymc.db;

import com.zaxxer.hikari.HikariConfig;
import com.zaxxer.hikari.HikariDataSource;
import org.bukkit.plugin.Plugin;
import java.sql.*;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;
import java.util.logging.Level;

public class MysqlAuditDao implements AuditDao, AutoCloseable {
    private final HikariDataSource dataSource;
    private final Plugin plugin;

    public MysqlAuditDao(Properties mysqlConfig, Plugin plugin) throws SQLException {
        this.plugin = plugin;
        
        HikariConfig config = new HikariConfig();
        String useSSL = mysqlConfig.getProperty("useSSL", "true");
        String allowPublicKeyRetrieval = mysqlConfig.getProperty("allowPublicKeyRetrieval", "false");
        String url = "jdbc:mysql://" + mysqlConfig.getProperty("host") + ":" +
                mysqlConfig.getProperty("port") + "/" +
                mysqlConfig.getProperty("database") +
                "?useSSL=" + useSSL +
                "&allowPublicKeyRetrieval=" + allowPublicKeyRetrieval +
                "&characterEncoding=utf8&autoReconnect=true";
                
        config.setJdbcUrl(url);
        config.setUsername(mysqlConfig.getProperty("user"));
        config.setPassword(mysqlConfig.getProperty("password"));
        config.setMaximumPoolSize(10);
        config.setMinimumIdle(2);
        config.setConnectionTimeout(30000);
        
        this.dataSource = new HikariDataSource(config);
        
        try (Connection conn = dataSource.getConnection(); Statement stmt = conn.createStatement()) {
            stmt.executeUpdate("CREATE TABLE IF NOT EXISTS audits (" +
                    "id INT AUTO_INCREMENT PRIMARY KEY," +
                    "action VARCHAR(32)," +
                    "operator VARCHAR(32)," +
                    "target VARCHAR(32)," +
                    "detail TEXT," +
                    "timestamp BIGINT)");
        }
    }

    @Override
    public void addAudit(AuditRecord audit) {
        String sql = "INSERT INTO audits (action, operator, target, detail, timestamp) VALUES (?, ?, ?, ?, ?)";
        try (Connection conn = dataSource.getConnection(); PreparedStatement ps = conn.prepareStatement(sql)) {
            ps.setString(1, audit.action());
            ps.setString(2, audit.operator());
            ps.setString(3, audit.target());
            ps.setString(4, audit.detail());
            ps.setLong(5, audit.timestamp());
            ps.executeUpdate();
        } catch (SQLException e) {
            plugin.getLogger().log(Level.WARNING, "Failed to add audit record", e);
        }
    }

    @Override
    public List<AuditRecord> getAllAudits() {
        List<AuditRecord> result = new ArrayList<>();
        String sql = "SELECT * FROM audits";
        try (Connection conn = dataSource.getConnection(); Statement stmt = conn.createStatement(); ResultSet rs = stmt.executeQuery(sql)) {
            while (rs.next()) {
                result.add(new AuditRecord(
                        rs.getLong("id"),
                        rs.getString("action"),
                        rs.getString("operator"),
                        rs.getString("target"),
                        rs.getString("detail"),
                        rs.getLong("timestamp")
                ));
            }
        } catch (SQLException e) {
            plugin.getLogger().log(Level.WARNING, "Failed to get all audits", e);
        }
        return result;
    }

    @Override
    public void save() {
        // MySQL storage: save() called (no-op)
    }

    @Override
    public void close() {
        if (dataSource != null && !dataSource.isClosed()) {
            dataSource.close();
        }
    }
}
