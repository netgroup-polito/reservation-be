package it.polito.cloudresources.be.config.persist;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

@Component
@Order(4) // Runs after initialization and legacy migration
@RequiredArgsConstructor
@Slf4j
public class WebhookLogMigrationRunner implements CommandLineRunner {

    private final JdbcTemplate jdbcTemplate;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        log.info("--- Starting WebhookLogs Migration (Checking for VARCHAR to TEXT conversion) ---");

        try {
            // 0. Check if the table exists first (to prevent errors on empty databases)
            String checkTableSql = "SELECT count(*) FROM information_schema.tables WHERE table_name = 'webhook_logs'";
            Integer tableExists = jdbcTemplate.queryForObject(checkTableSql, Integer.class);

            if (tableExists == null || tableExists == 0) {
                log.info("Table 'webhook_logs' does not exist yet. Skipping migration.");
                return;
            }

            // 1. Check the CURRENT data type of the 'payload' column
            String checkDataTypeSql = "SELECT data_type FROM information_schema.columns " +
                                      "WHERE table_name = 'webhook_logs' AND column_name = 'payload'";
            
            String currentType = jdbcTemplate.queryForObject(checkDataTypeSql, String.class);

            // In Postgres, VARCHAR is returned as "character varying"
            if ("text".equalsIgnoreCase(currentType)) {
                log.info("Column 'payload' is already of type TEXT. Migration already completed. Skipping.");
                return; // Clean exit
            }

            // 2. If it's not TEXT (likely character varying), execute the migration
            log.info("Column 'payload' is of type '{}'. Proceeding with ALTER TABLE to TEXT...", currentType);
            
            jdbcTemplate.execute("ALTER TABLE webhook_logs ALTER COLUMN payload TYPE TEXT");
            jdbcTemplate.execute("ALTER TABLE webhook_logs ALTER COLUMN response TYPE TEXT");
            
            log.info("--- WebhookLogs Migration Completed Successfully. The 4000 chars limit is removed! ---");

        } catch (Exception e) {
            // Catching any unexpected errors so it doesn't crash the application startup
            log.error("Critical error during WebhookLogs Migration: {}", e.getMessage(), e);
        }
    }
}