package it.polito.cloudresources.be.config.persist;

import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.CommandLineRunner;
import org.springframework.core.annotation.Order;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.stereotype.Component;
import org.springframework.transaction.annotation.Transactional;

/**
 * Automatically migrates the database schema for the Events table.
 * Specifically adds the 'deleted' column required for asynchronous deprovisioning,
 * ensuring backwards compatibility with existing rows in production.
 */
@Component
@Order(2) // Eseguiamo assieme alle altre migrazioni DDL
@RequiredArgsConstructor
@Slf4j
public class EventTableMigrationRunner implements CommandLineRunner {

    private final JdbcTemplate jdbcTemplate;

    @Override
    @Transactional
    public void run(String... args) throws Exception {
        log.info("Checking Events table database schema migration...");

        try {
            // Aggiungiamo la colonna se non esiste. 
            // Usiamo DEFAULT FALSE così le righe esistenti (prenotazioni vecchie) 
            // non violano il constraint NOT NULL che Hibernate si aspetta.
            String addColumnSql = "ALTER TABLE events ADD COLUMN IF NOT EXISTS deleted BOOLEAN DEFAULT FALSE";
            
            jdbcTemplate.execute(addColumnSql);
            
            log.info("Column 'deleted' check/add completed for table 'events'.");
        } catch (Exception e) {
            log.error("Error ensuring column 'deleted' exists on events table: {}", e.getMessage());
            // Non rilanciamo l'eccezione per non far crashare brutalmente l'avvio, 
            // ma l'errore verrà loggato.
        }

        log.info("Events table schema migration check completed.");
    }
}