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

/**
 * Migration runner to link legacy reservations (which have ssh_key_id = NULL)
 * to the user's Default SSH key.
 * * This ensures that existing reservations continue to work with the new wallet system.
 */
@Component
@Order(2) // Run after SshKeyMigrationRunner (which is Order 1)
@RequiredArgsConstructor
@Slf4j
public class LegacyReservationMigrationRunner implements CommandLineRunner {

    private final JdbcTemplate jdbcTemplate;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        log.info("--- Starting Legacy Reservation Migration (Linking Events to SSH Keys) ---");

        // 1. Find all events with NULL ssh_key_id
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

            // 2. Find a suitable key for this user 
            // Priority: Label='Default' -> Any Key (ordered by ID)
            String findKeySql = "SELECT id FROM ssh_keys WHERE user_id = ? ORDER BY CASE WHEN label = 'Default' THEN 0 ELSE 1 END, id LIMIT 1";
            
            try {
                List<Long> keyIds = jdbcTemplate.query(findKeySql, (rs, rowNum) -> rs.getLong("id"), userId);
                
                if (!keyIds.isEmpty()) {
                    Long keyId = keyIds.get(0);
                    // 3. Update the event
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
    }
}