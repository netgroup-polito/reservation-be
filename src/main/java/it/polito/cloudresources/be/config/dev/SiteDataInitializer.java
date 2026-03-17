package it.polito.cloudresources.be.config.dev;

import java.util.HashSet;
import java.util.List;
import java.util.Set;

import org.springframework.boot.CommandLineRunner;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.context.annotation.Profile;

import it.polito.cloudresources.be.dto.users.UserDTO;
import it.polito.cloudresources.be.service.MockKeycloakService;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

/**
 * Initializes sites and users with sample data for development
 */
@Configuration
@RequiredArgsConstructor
@Slf4j
@Profile("dev")
public class SiteDataInitializer {
    private final MockKeycloakService keycloakService;

    @Bean(name = "initSites")
    public CommandLineRunner initSites() {
        return arg -> {
            log.info("Initializing sample sites and users...");

            try {
                // Ensure core roles exist
                keycloakService.ensureRealmRoles("GLOBAL_ADMIN", "USER");

                // Create sample sites
                String poliToId = keycloakService.setupNewKeycloakGroup("polito", "Turin Technical University", false);
                String uniRomaId = keycloakService.setupNewKeycloakGroup("uniroma", "Rome University", false);
                String uniMiId = keycloakService.setupNewKeycloakGroup("unimi", "Milan University", false);

                log.info("Created sites with IDs: {}, {}, {}", poliToId, uniRomaId, uniMiId);

                // Create global admin user directly via KeycloakService
                String adminUsername = "admin1";
                String adminPassword = "admin123";
                Set<String> adminRoles = new HashSet<>(List.of("GLOBAL_ADMIN", "USER"));
                
                // Create admin user directly with Keycloak 
                UserDTO adminDto = UserDTO.builder()
                        .username(adminUsername)
                        .email("admin@example.com")
                        .firstName("Global")
                        .lastName("Admin")
                        .avatar("GA")
                        .roles(adminRoles)
                        .build();
                
                String globalAdminId = keycloakService.createUser(adminDto, adminPassword);
                log.info("Created global admin user: {} with ID {}", adminUsername, globalAdminId);

                // Add global admin to all sites
                keycloakService.addUserToKeycloakGroup(globalAdminId, poliToId);
                keycloakService.addUserToKeycloakGroup(globalAdminId, uniRomaId);
                keycloakService.addUserToKeycloakGroup(globalAdminId, uniMiId);

                // Create site admins for each university
                String poliToAdminId = createSiteAdmin("polito_admin", "Polito", "Admin", poliToId);
                String uniRomaAdminId = createSiteAdmin("uniroma_admin", "Uniroma", "Admin", uniRomaId);
                String uniMiAdminId = createSiteAdmin("unimi_admin", "Unimi", "Admin", uniMiId);

                

                // Make sure admin roles are correctly assigned
                ensureAdminRoles(globalAdminId, adminRoles);
                ensureSiteAdminRole(poliToAdminId, "polito");
                ensureSiteAdminRole(uniRomaAdminId, "uniroma");
                ensureSiteAdminRole(uniMiAdminId, "unimi");

                log.info("Sample sites and users initialized successfully.");
            } catch (Exception e) {
                log.error("Error initializing sites and users: {}", e.getMessage(), e);
                throw e;
            }
        };
    }

    /**
     * Create site admin user directly with Keycloak service
     */
    private String createSiteAdmin(String username, String firstName, String lastName, String siteId) {
        try {
            // Check if admin already exists
            String password = "admin123";
            Set<String> roles = new HashSet<>(List.of("USER"));

            // Create user directly with Keycloak
            UserDTO userDto = UserDTO.builder()
                    .username(username)
                    .email(username + "@example.com")
                    .firstName(firstName)
                    .lastName(lastName)
                    .avatar(firstName.substring(0, 1).toUpperCase() + "A")
                    .roles(roles)
                    .build();
            
            String userId = keycloakService.createUser(userDto, password);
            log.info("Created user: {} with ID {}", username, userId);
            
            // Add to site
            keycloakService.addUserToKeycloakGroup(userId, siteId);
            
            // Get the site name from the ID
            String siteName = keycloakService.getGroupById(siteId)
                    .map(group -> group.getName())
                    .orElseThrow(() -> new RuntimeException("Site not found with ID: " + siteId));

            // Assign site admin role
            keycloakService.assignSiteAdminRole(userId, siteName);
            
            log.info("Created site admin {} with role {}_site_admin", username, siteName.toLowerCase());
            
            return userId;
        } catch (Exception e) {
            log.error("Error creating site admin user: {}", e.getMessage());
            throw new RuntimeException("Failed to create site admin user", e);
        }
    }

    /**
     * Create regular user directly with Keycloak service
     
    private String createRegularUser(String username, String firstName, String lastName, String siteId) {
        try {
            // Check if user already exists
            String password = "user123";
            Set<String> roles = new HashSet<>(List.of("USER"));

            // Create user directly with Keycloak
            UserDTO userDto = UserDTO.builder()
                    .username(username)
                    .email(username + "@example.com")
                    .firstName(firstName)
                    .lastName(lastName)
                    .avatar(firstName.substring(0, 1).toUpperCase() + lastName.substring(0, 1).toUpperCase())
                    .roles(roles)
                    .build();
            
            String userId = keycloakService.createUser(userDto, password);
            log.info("Created user: {} with ID {}", username, userId);

            // Add user to site
            keycloakService.addUserToKeycloakGroup(userId, siteId);
            log.info("Added user {} to site {}", username, siteId);
            
            return userId;
        } catch (Exception e) {
            log.error("Error creating regular user {}: {}", username, e.getMessage());
            throw new RuntimeException("Failed to create regular user", e);
        }
    }*/
    
    /**
     * Ensure admin roles are correctly assigned
     */
    private void ensureAdminRoles(String userId, Set<String> roles) {
        try {
            // Make sure GLOBAL_ADMIN role exists
            keycloakService.ensureRealmRoles("GLOBAL_ADMIN");
            
            // Assign roles to user
            for (String role : roles) {
                boolean assigned = keycloakService.assignRoleToUser(userId, role);
                log.info("Role {} assigned to user {}: {}", role, userId, assigned);
            }
        } catch (Exception e) {
            log.error("Error ensuring admin roles: {}", e.getMessage());
        }
    }
    
    /**
     * Ensure site admin role is correctly assigned
     */
    private void ensureSiteAdminRole(String userId, String siteName) {
        try {
            // Make sure role exists
            String rolePrefix = siteName.toLowerCase().replace(' ', '_');
            keycloakService.ensureRealmRoles(rolePrefix + "_site_admin");
            
            // Assign role
            boolean assigned = keycloakService.assignSiteAdminRole(userId, siteName);
            log.info("Site admin role for {} assigned to user {}: {}", siteName, userId, assigned);
        } catch (Exception e) {
            log.error("Error ensuring site admin role: {}", e.getMessage());
        }
    }
}