package it.polito.cloudresources.be.config.persist;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.Map;

@Component
@Order(2)
@RequiredArgsConstructor
@Slf4j
public class LegacyReservationMigrationRunner implements CommandLineRunner {

    private final JdbcTemplate jdbcTemplate;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        log.info("--- Starting Legacy Reservation Migration (Linking Events to SSH Keys) ---");

        try {
            // 0. CHECK INTELLIGENTE: La colonna esiste ancora?
            String checkColumnSql = "SELECT count(*) FROM information_schema.columns " +
                                    "WHERE table_name = 'events' AND column_name = 'ssh_key_id'";
            
            Integer columnExists = jdbcTemplate.queryForObject(checkColumnSql, Integer.class);

            if (columnExists == null || columnExists == 0) {
                log.info("Column 'ssh_key_id' does not exist in 'events' table. Migration already completed or fresh database. Skipping.");
                return; // Usciamo puliti, senza errori!
            }

            // 1. Se la colonna esiste, procediamo con la migrazione
            String findLegacyEventsSql = "SELECT id, keycloak_id FROM events WHERE ssh_key_id IS NULL";
            List<Map<String, Object>> legacyEvents = jdbcTemplate.queryForList(findLegacyEventsSql);
            
            if (legacyEvents.isEmpty()) {
                log.info("No legacy events found requiring migration.");
                return;
            }

            log.info("Found {} legacy events to migrate.", legacyEvents.size());
            int updatedCount = 0;

            for (Map<String, Object> eventRow : legacyEvents) {
                Long eventId = (Long) eventRow.get("id");
                String userId = (String) eventRow.get("keycloak_id");

                // 2. Trova la chiave adatta
                String findKeySql = "SELECT id FROM ssh_keys WHERE user_id = ? ORDER BY CASE WHEN label = 'Default' THEN 0 ELSE 1 END, id LIMIT 1";
                
                try {
                    List<Long> keyIds = jdbcTemplate.query(findKeySql, (rs, rowNum) -> rs.getLong("id"), userId);
                    
                    if (!keyIds.isEmpty()) {
                        Long keyId = keyIds.get(0);
                        // 3. Aggiorna l'evento
                        int rows = jdbcTemplate.update("UPDATE events SET ssh_key_id = ? WHERE id = ?", keyId, eventId);
                        if (rows > 0) {
                            updatedCount++;
                        }
                    } else {
                        log.debug("User {} has no SSH keys in wallet. Event {} remains with null key.", userId, eventId);
                    }
                } catch (Exception e) {
                    log.error("Error migrating event {}: {}", eventId, e.getMessage());
                }
            }

            log.info("--- Migration Completed. Updated {} events out of {}. ---", updatedCount, legacyEvents.size());
            
        } catch (Exception e) {
            log.error("Critical error during Legacy Reservation Migration: {}", e.getMessage(), e);
        }
    }
}