package it.polito.cloudresources.be.service;

import it.polito.cloudresources.be.dto.users.UserDTO;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.core.Response;     // FIX: updated to Jakarta for Keycloak 26+
import jakarta.ws.rs.NotFoundException; // FIX: updated to Jakarta for Keycloak 26+
import lombok.extern.slf4j.Slf4j;

import org.keycloak.OAuth2Constants;
import org.keycloak.admin.client.Keycloak;
import org.keycloak.admin.client.KeycloakBuilder;
import org.keycloak.admin.client.resource.GroupResource;
import org.keycloak.admin.client.resource.RealmResource;
import org.keycloak.admin.client.resource.UserResource;
import org.keycloak.admin.client.resource.UsersResource;
import org.keycloak.representations.idm.CredentialRepresentation;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.RoleRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.cache.annotation.CacheEvict;
import org.springframework.cache.annotation.Cacheable;
import org.springframework.cache.annotation.Caching;
import org.springframework.context.annotation.Profile;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;

import jakarta.annotation.PreDestroy;
import java.util.*;
import java.util.stream.Collectors;

/**
 * Enhanced service for interacting with Keycloak as the single source of truth for user data
 * Now with caching to improve performance and reduce API calls to Keycloak
 */
@Service
@Profile("!dev") // Active in all profiles except dev
@Slf4j
public class KeycloakService {

    public static final String ATTR_SSH_KEY = "ssh_key";
    public static final String ATTR_AVATAR = "avatar";

    // Cache names
    public static final String USERS_CACHE = "keycloak_users";
    public static final String USER_BY_ID_CACHE = "keycloak_users_by_id";
    public static final String USER_BY_USERNAME_CACHE = "keycloak_users_by_username";
    public static final String USER_BY_EMAIL_CACHE = "keycloak_users_by_email";
    public static final String USER_ROLES_CACHE = "keycloak_user_roles";
    public static final String USER_ATTRIBUTES_CACHE = "keycloak_user_attributes";
    public static final String USER_GROUPS_CACHE = "keycloak_user_groups";
    public static final String GROUPS_CACHE = "keycloak_groups";
    public static final String GROUP_BY_ID_CACHE = "keycloak_groups_by_id";
    public static final String GROUP_BY_NAME_CACHE = "keycloak_groups_by_name";
    public static final String GROUP_MEMBERS_CACHE = "keycloak_group_members";
    public static final String USERS_IN_GROUP_CACHE = "keycloak_users_in_group";
    public static final String USER_ADMIN_GROUPS_CACHE = "keycloak_user_admin_groups";
    public static final String USER_SITES_CACHE = "keycloak_user_sites";
    public static final String USER_BY_ROLE_CACHE = "keycloak_users_by_role";
    public static final String USER_SITE_ADMIN_STATUS = "keycloak_site_admin_status";

    @Value("${keycloak.auth-server-url}")
    private String authServerUrl;

    @Value("${keycloak.realm}")
    private String realm;

    @Value("${keycloak.resource}")
    private String clientId;

    @Value("${keycloak.credentials.secret}")
    private String clientSecret;

    // FIX: Lazily-initialized singleton to avoid creating a new HTTP client on every method call
    private volatile Keycloak keycloakClient;

    /**
     * Creates an admin Keycloak client
     */
    protected Keycloak getKeycloakClient() {
        if (keycloakClient == null) {
            synchronized (this) {
                if (keycloakClient == null) {
                    keycloakClient = KeycloakBuilder.builder()
                            .serverUrl(authServerUrl)
                            .realm(realm)
                            .clientId(clientId)
                            .clientSecret(clientSecret)
                            .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                            .build();
                }
            }
        }
        return keycloakClient;
    }

    @PreDestroy
    public void closeKeycloakClient() {
        if (keycloakClient != null) {
            keycloakClient.close();
        }
    }

    /**
     * Get the realm resource
     */
    protected RealmResource getRealmResource() {
        return getKeycloakClient().realm(realm);
    }

    /**
     * Get all Keycloak users
     */
    @Cacheable(value = USERS_CACHE, unless = "#result.isEmpty()")
    public List<UserRepresentation> getUsers() {
        try {
            log.debug("Cache miss: Fetching all users from Keycloak");
            // FIX: explicit pagination to avoid the server-side default limit (typically 100) in KC 26
            return getRealmResource().users().list(0, Integer.MAX_VALUE);
        } catch (Exception e) {
            log.error("Error fetching users from Keycloak", e);
            return Collections.emptyList();
        }
    }

    /**
     * Get a user by username
     */
    @Cacheable(value = USER_BY_USERNAME_CACHE, key = "#username", unless = "#result == null")
    public Optional<UserRepresentation> getUserByUsername(String username) {
        try {
            log.debug("Cache miss: Fetching user by username '{}'", username);
            // FIX: KC 26 supports the exact-match convenience overload search(username, exact)
            List<UserRepresentation> users = getRealmResource().users().search(username, true);
            return users.isEmpty() ? Optional.empty() : Optional.of(users.get(0));
        } catch (Exception e) {
            log.error("Error fetching user from Keycloak by username", e);
            return Optional.empty();
        }
    }

    /**
     * Get a user by email
     */
    @Cacheable(value = USER_BY_EMAIL_CACHE, key = "#email", unless = "#result == null")
    public Optional<UserRepresentation> getUserByEmail(String email) {
        try {
            log.debug("Cache miss: Fetching user by email '{}'", email);
            List<UserRepresentation> users = getRealmResource().users().search(null, null, null, email, 0, 1);
            return users.isEmpty() ? Optional.empty() : Optional.of(users.get(0));
        } catch (Exception e) {
            log.error("Error fetching user from Keycloak by email", e);
            return Optional.empty();
        }
    }

    /**
     * Get a user by ID
     */
    @Cacheable(value = USER_BY_ID_CACHE, key = "#id", unless = "#result == null")
    public Optional<UserRepresentation> getUserById(String id) {
        try {
            log.debug("Cache miss: Fetching user by ID '{}'", id);
            UserRepresentation user = getRealmResource().users().get(id).toRepresentation();
            return Optional.ofNullable(user);
        } catch (Exception e) {
            log.error("Error fetching user from Keycloak", e);
            return Optional.empty();
        }
    }

    /**
     * Creates a new user in Keycloak from a UserDTO
     *
     * @param userDTO the user data transfer object
     * @param password the user's password
     * @param roles the roles to assign to the user
     * @return the ID of the created user, or null if creation failed
     */
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = USERS_CACHE, allEntries = true),
            @CacheEvict(value = USER_BY_ROLE_CACHE, allEntries = true)
    })
    public String createUser(UserDTO userDTO, String password) {
        try {
            log.debug("Attempting to create user: username={}, email={}, firstName={}, lastName={}",
                    userDTO.getUsername(), userDTO.getEmail(), userDTO.getFirstName(), userDTO.getLastName());

            // Create user representation
            UserRepresentation user = createUserRepresentation(userDTO);

            // Create user in Keycloak
            String userId = createUserInKeycloak(user);
            if (userId == null) {
                return null;
            }

            // Set user password
            if (!setUserPassword(userId, password)) {
                log.warn("Password could not be set for user: {}", userId);
                // Continue anyway as the user has been created
            }

            assignGroupsToUser(userId);
            Set<String> roles = userDTO.getRoles();
            // Assign roles to user
            if (Objects.nonNull(roles) && !roles.isEmpty()) {
                for (String role : roles) {
                    log.info("Assegno il ruolo {} all'utente {}", role, userId);
                    assignRoleToUser(userId, role.toLowerCase());
                }
            }

            return userId;
        } catch (Exception e) {
            log.error("Error creating user in Keycloak", e);
            return null;
        }
    }

    /**
     * Update an existing user in Keycloak
     */
    @Transactional
    @Caching(evict = {
            @CacheEvict(value = USER_BY_ID_CACHE, key = "#userId"),
            @CacheEvict(value = USERS_CACHE, allEntries = true),
            // FIX: Spring Cache does not support wildcard keys; allEntries = true evicts all attribute entries for all users.
            // This is a safe over-eviction — the alternative would be a per-attribute key or a custom CacheManager.
            @CacheEvict(value = USER_ATTRIBUTES_CACHE, allEntries = true),
            @CacheEvict(value = USER_ROLES_CACHE, key = "#userId"),
            @CacheEvict(value = USER_BY_USERNAME_CACHE, allEntries = true),
            @CacheEvict(value = USER_BY_EMAIL_CACHE, allEntries = true),
            @CacheEvict(value = USER_BY_ROLE_CACHE, allEntries = true)
    })
    public boolean updateUser(String userId, Map<String, Object> attributes) {
        try {
            UserResource userResource = getRealmResource().users().get(userId);
            UserRepresentation user = userResource.toRepresentation();

            if (attributes.containsKey("email")) {
                user.setEmail((String) attributes.get("email"));
            }

            if (attributes.containsKey("firstName")) {
                user.setFirstName((String) attributes.get("firstName"));
            }

            if (attributes.containsKey("lastName")) {
                user.setLastName((String) attributes.get("lastName"));
            }

            if (attributes.containsKey("username")) {
                user.setUsername((String) attributes.get("username"));
            }

            if (attributes.containsKey("enabled")) {
                user.setEnabled((Boolean) attributes.get("enabled"));
            }

            // Handle SSH key and avatar attributes
            Map<String, List<String>> userAttributes = user.getAttributes();
            if (userAttributes == null) {
                userAttributes = new HashMap<>();
            }

            if (attributes.containsKey(ATTR_SSH_KEY)) {
                String sshKey = (String) attributes.get(ATTR_SSH_KEY);
                if (sshKey != null && !sshKey.isEmpty()) {
                    userAttributes.put(ATTR_SSH_KEY, Collections.singletonList(sshKey));
                } else {
                    userAttributes.remove(ATTR_SSH_KEY);
                }
            }

            if (attributes.containsKey(ATTR_AVATAR)) {
                String avatar = (String) attributes.get(ATTR_AVATAR);
                if (avatar != null && !avatar.isEmpty()) {
                    userAttributes.put(ATTR_AVATAR, Collections.singletonList(avatar));
                } else {
                    userAttributes.remove(ATTR_AVATAR);
                }
            }

            if (attributes.containsKey("roles")) {
                @SuppressWarnings("unchecked")
                List<String> newRoleNames = (List<String>) attributes.get("roles");
                
                // Normalize site_admin role names to ensure consistency
                List<String> normalizedNewRoleNames = newRoleNames.stream()
                    .map(roleName -> {
                        if (roleName.endsWith("_site_admin")) {
                            // Extract site name and normalize it
                            String siteName = roleName.substring(0, roleName.length() - "_site_admin".length());
                            return getSiteAdminRoleName(siteName);
                        }
                        return roleName;
                    })
                    .collect(Collectors.toList());
                
                List<RoleRepresentation> currentRoles = userResource.roles().realmLevel().listAll();
                List<String> currentRoleNames = currentRoles.stream()
                    .map(RoleRepresentation::getName)
                    .collect(Collectors.toList());
                
                // Find roles to add (in new list but not in current)
                List<String> rolesToAdd = normalizedNewRoleNames.stream()
                    .filter(roleName -> !currentRoleNames.contains(roleName))
                    .collect(Collectors.toList());
                
                // Find roles to remove (in current but not in new list)
                List<String> rolesToRemove = currentRoleNames.stream()
                    .filter(roleName -> !normalizedNewRoleNames.contains(roleName))
                    .collect(Collectors.toList());
                
                // Add new roles
                for (String roleName : rolesToAdd) {
                    assignRoleToUser(userId, roleName);
                }
                
                // Remove old roles
                for (String roleName : rolesToRemove) {
                    removeRoleFromUser(userId, roleName);
                }
                
                log.info("Updated roles for user {}: added {}, removed {}", userId, rolesToAdd, rolesToRemove);
            }

            user.setAttributes(userAttributes);

            // Update basic user info first
            userResource.update(user);
            log.debug("Basic user info updated for user: {}", userId);

            // Update password if provided
            if (attributes.containsKey("password")) {
                CredentialRepresentation credential = new CredentialRepresentation();
                credential.setType(CredentialRepresentation.PASSWORD);
                credential.setValue((String) attributes.get("password"));
                credential.setTemporary(false);

                userResource.resetPassword(credential);
                log.debug("Password updated for user: {}", userId);
            }

            log.info("User updated in Keycloak: {}", userId);
            return true;
        } catch (Exception e) {
            log.error("Error updating user in Keycloak", e);
            log.error(e.getMessage());
            return false;
        }
    }

    /**
     * Delete a user from Keycloak
     */
    @Caching(evict = {
            @CacheEvict(value = USER_BY_ID_CACHE, key = "#userId"),
            @CacheEvict(value = USERS_CACHE, allEntries = true),
            // FIX: Spring Cache does not support wildcard keys; see comment in updateUser()
            @CacheEvict(value = USER_ATTRIBUTES_CACHE, allEntries = true),
            @CacheEvict(value = USER_ROLES_CACHE, key = "#userId"),
            @CacheEvict(value = USER_GROUPS_CACHE, key = "#userId"),
            @CacheEvict(value = USER_ADMIN_GROUPS_CACHE, key = "#userId"),
            @CacheEvict(value = USER_SITES_CACHE, key = "#userId"),
            @CacheEvict(value = USER_BY_USERNAME_CACHE, allEntries = true),
            @CacheEvict(value = USER_BY_EMAIL_CACHE, allEntries = true),
            @CacheEvict(value = USERS_IN_GROUP_CACHE, allEntries = true),
            @CacheEvict(value = GROUP_MEMBERS_CACHE, allEntries = true),
            @CacheEvict(value = USER_BY_ROLE_CACHE, allEntries = true)
    })
    public boolean deleteUser(String userId) {
        try {
            getRealmResource().users().get(userId).remove();
            log.info("User deleted from Keycloak: {}", userId);
            return true;
        } catch (Exception e) {
            log.error("Error deleting user from Keycloak", e);
            return false;
        }
    }

    /**
     * Get roles of a user
     */
    @Cacheable(value = USER_ROLES_CACHE, key = "#userId")
    public List<String> getUserRoles(String userId) {
        try {
            log.debug("Cache miss: Fetching roles for user '{}'", userId);
            List<RoleRepresentation> roles = getRealmResource().users().get(userId).roles().realmLevel().listAll();
            return roles.stream().map(RoleRepresentation::getName).toList();
        } catch (Exception e) {
            log.error("Error fetching user roles from Keycloak", e);
            return Collections.emptyList();
        }
    }

    /**
     * Get specific attribute for a user
     */
    @Cacheable(value = USER_ATTRIBUTES_CACHE, key = "#userId + '_' + #attributeName")
    public Optional<String> getUserAttribute(String userId, String attributeName) {
        try {
            log.debug("Cache miss: Fetching attribute '{}' for user '{}'", attributeName, userId);
            UserRepresentation user = getRealmResource().users().get(userId).toRepresentation();
            Map<String, List<String>> attributes = user.getAttributes();
            
            if (attributes != null && attributes.containsKey(attributeName)) {
                List<String> values = attributes.get(attributeName);
                if (!values.isEmpty()) {
                    return Optional.of(values.get(0));
                }
            }
            return Optional.empty();
        } catch (Exception e) {
            log.error("Error fetching user attribute from Keycloak", e);
            return Optional.empty();
        }
    }

    /**
     * Get SSH key for a user
     */
    public Optional<String> getUserSshKey(String userId) {
        return getUserAttribute(userId, ATTR_SSH_KEY);
    }

    /**
     * Get avatar for a user
     */
    public Optional<String> getUserAvatar(String userId) {
        return getUserAttribute(userId, ATTR_AVATAR);
    }

    /**
     * Create realm roles in Keycloak if they don't exist
     */
    public void ensureRealmRoles(String... roleNames) {
        RealmResource realmResource = getRealmResource(); // Cache realm resource for multiple calls
        for (String roleName : roleNames) {
            try {
                // Attempt to get the role.
                // In Keycloak 26, if the role doesn't exist, .toRepresentation() throws NotFoundException (Jakarta).
                realmResource.roles().get(roleName).toRepresentation(); // This line checks existence
                log.debug("Role {} already exists in Keycloak.", roleName);
            } catch (NotFoundException e) {
                // Role does not exist, so create it
                log.info("Role {} not found in Keycloak. Creating...", roleName);
                createRoleInKeycloakInternal(realmResource, roleName);
            } catch (Exception e) {
                // Catch other potential errors during role check or creation
                log.error("Error ensuring realm role {} in Keycloak: {}", roleName, e.getMessage(), e);
            }
        }
    }

    // Helper method to create a role, used by ensureRealmRoles
    private void createRoleInKeycloakInternal(RealmResource realmResource, String roleName) {
        try {
            RoleRepresentation role = new RoleRepresentation();
            role.setName(roleName);
            realmResource.roles().create(role);
            log.info("Created role in Keycloak: {}", roleName);
        } catch (Exception e) {
            // Log creation-specific error
            log.error("Error creating role {} in Keycloak: {}", roleName, e.getMessage(), e);
            // Depending on error handling strategy, might rethrow or handle differently
        }
    }

    /**
     * Find users by role
     */
    @Cacheable(value = USER_BY_ROLE_CACHE, key = "#roleName")
    public List<UserRepresentation> getUsersByRole(String roleName) {
        try {
            log.debug("Cache miss: Fetching users by role '{}'", roleName);
            List<UserRepresentation> allUsers = getUsers();
            List<UserRepresentation> usersWithRole = new ArrayList<>();
            
            for (UserRepresentation user : allUsers) {
                List<String> userRoles = getUserRoles(user.getId());
                if (userRoles.contains(roleName) || userRoles.contains(roleName.toUpperCase()) || 
                    userRoles.contains(roleName.toLowerCase())) {
                    usersWithRole.add(user);
                }
            }
            
            return usersWithRole;
        } catch (Exception e) {
            log.error("Error finding users by role from Keycloak", e);
            return Collections.emptyList();
        }
    }

    @Cacheable(value = GROUPS_CACHE)
    public List<GroupRepresentation> getAllGroups() {
        log.debug("Cache miss: Fetching all groups");
        // FIX: explicit pagination to avoid the server-side default limit in KC 26
        return getRealmResource().groups().groups(0, Integer.MAX_VALUE);
    }
    
    @Cacheable(value = GROUP_BY_ID_CACHE, key = "#groupId"/*,  unless = "#result.isEmpty()" */)
    public Optional<GroupRepresentation> getGroupById(String groupId) {
        try {
            log.debug("Cache miss: Fetching group by ID '{}'", groupId);
            GroupRepresentation group = getRealmResource().groups().group(groupId).toRepresentation();
            return Optional.of(group);
        } catch (Exception e) {
            log.error("Error fetching site", e);
            return Optional.empty();
        }
    }

    @Cacheable(value = GROUP_BY_NAME_CACHE, key = "#groupName"/*,  unless = "#result.isEmpty()" */)
    public Optional<GroupRepresentation> getGroupByName(String groupName) {
        try {
            log.debug("Cache miss: Fetching group by name '{}'", groupName);
            // FIX: explicit pagination to avoid the server-side default limit in KC 26
            return getRealmResource().groups().groups(0, Integer.MAX_VALUE).stream()
                    .filter(group -> group.getName().equals(groupName))
                    .findFirst();
        } catch (Exception e) {
            log.error("Error fetching site", e);
            return Optional.empty();
        }
    }
    
    /**
     * Create a site from a GroupRepresentation
     */
    @Caching(evict = {
            @CacheEvict(value = GROUPS_CACHE, allEntries = true),
            @CacheEvict(value = GROUP_BY_NAME_CACHE, allEntries = true)
    })
    public String setupNewKeycloakGroup(GroupRepresentation group) {
        try {
            Response response = getRealmResource().groups().add(group);
            if (response.getStatus() == 201) {
                String locationPath = response.getLocation().getPath();
                String siteId = locationPath.substring(locationPath.lastIndexOf('/') + 1);
                log.info("Created group with ID: {}", siteId);
                return siteId;
            } else {
                log.error("Failed to create group. Status: {}", response.getStatus());
            }
        } catch (Exception e) {
            log.error("Error creating group", e);
        }
        return null;
    }

    /**
     * Creates a new site
     */
    @Caching(evict = {        
        @CacheEvict(value = USERS_CACHE, allEntries = true),
        @CacheEvict(value = USER_GROUPS_CACHE, allEntries = true),
        @CacheEvict(value = USER_SITES_CACHE, allEntries = true),
        @CacheEvict(value = USERS_IN_GROUP_CACHE, allEntries = true),
        @CacheEvict(value = GROUP_MEMBERS_CACHE, allEntries = true),
        @CacheEvict(value = GROUPS_CACHE, allEntries = true),
        @CacheEvict(value = GROUP_BY_NAME_CACHE, allEntries = true)
    })
    public String setupNewKeycloakGroup(String name, String description, boolean privateSite) {
        GroupRepresentation group = new GroupRepresentation();
        group.setName(name);

        // Set attributes for the description
        Map<String, List<String>> attributes = new HashMap<>();
        if (description != null && !description.isEmpty()) {
            attributes.put("description", Collections.singletonList(description));
            group.setAttributes(attributes);
        }

        String groupId = setupNewKeycloakGroup(group);

        // Create the site admin role
        if (groupId != null) {
            createSiteAdminRole(name);
            log.debug("Creating group in private mode: {}", privateSite);
            if(!privateSite) {
                //Add all user to the site
                List<UserRepresentation> allUsers = getUsers();
                for (UserRepresentation user : allUsers) {
                    addUserToKeycloakGroup(user.getId(), groupId);
                }
            }
        }

        return groupId;
    }
    
    /**
     * Update an existing site
     */
    @Caching(evict = {
            @CacheEvict(value = GROUP_BY_ID_CACHE, key = "#groupId"),
            @CacheEvict(value = GROUPS_CACHE, allEntries = true),
            @CacheEvict(value = GROUP_BY_NAME_CACHE, allEntries = true)
    })
    public boolean updateGroup(String groupId, GroupRepresentation updatedGroup) {
        try {
            // First get the current group to ensure it exists
            GroupResource groupResource = getRealmResource().groups().group(groupId);
            GroupRepresentation currentGroup = groupResource.toRepresentation();
            
            // We want to preserve the ID when updating
            updatedGroup.setId(groupId);
            
            // For subgroups, preserve the existing ones if not specified in the update
            if (updatedGroup.getSubGroups() == null && currentGroup.getSubGroups() != null) {
                updatedGroup.setSubGroups(currentGroup.getSubGroups());
            }
            
            // Update the group
            groupResource.update(updatedGroup);
            log.info("Updated site with ID: {}", groupId);
            return true;
        } catch (Exception e) {
            log.error("Error updating site with ID: {}", groupId, e);
            return false;
        }
    }
    
    /**
     * Delete a site
     * @param groupId
     */
    @Caching(evict = {
            @CacheEvict(value = GROUP_BY_ID_CACHE, key = "#groupId"),
            @CacheEvict(value = GROUPS_CACHE, allEntries = true),
            @CacheEvict(value = GROUP_BY_NAME_CACHE, allEntries = true),
            @CacheEvict(value = GROUP_MEMBERS_CACHE, allEntries = true),
            @CacheEvict(value = USERS_IN_GROUP_CACHE, key = "#groupId"),
            @CacheEvict(value = USER_GROUPS_CACHE, allEntries = true),
            @CacheEvict(value = USER_ADMIN_GROUPS_CACHE, allEntries = true),
            @CacheEvict(value = USER_SITES_CACHE, allEntries = true)
    })
    public boolean deleteGroup(String groupId) {
        try {
            RealmResource realmResource = getRealmResource();
            GroupResource groupResource = realmResource.groups().group(groupId);
            GroupRepresentation group = groupResource.toRepresentation(); // This will throw NotFoundException if group doesn't exist
            
            String roleToRemove = getSiteAdminRoleName(group.getName());

            // Delete the group
            groupResource.remove();
            log.info("Deleted group with ID: {}", groupId);

            // Attempt to delete the associated role
            try {
                realmResource.roles().deleteRole(roleToRemove);
                log.info("Deleted role: {}", roleToRemove);
            } catch (NotFoundException e) {
                log.warn("Role {} not found, could not delete it or it was already deleted.", roleToRemove);
            } catch (Exception e) {
                log.error("Error deleting role {}: {}", roleToRemove, e.getMessage(), e);
                // Decide if this failure should cause the whole operation to return false
            }
            return true;
        } catch (NotFoundException e) {
            log.warn("Group with ID {} not found for deletion.", groupId);
            return false; // Group didn't exist, so deletion is effectively false from a "did I delete it now?" perspective
        } catch (Exception e) {
            log.error("Error deleting group with ID: {}", groupId, e);
            return false;
        }
    }

    /**
     * Check if a user is a member of a specific site (group)
     */
    @Cacheable(value = GROUP_MEMBERS_CACHE, key = "#groupId + '_' + #userId")
    public boolean isUserInGroup(String userId, String groupId) {
        try {
            log.debug("Cache miss: Checking if user '{}' is in group '{}'", userId, groupId);
            UserResource userResource = getRealmResource().users().get(userId);
            List<GroupRepresentation> userGroups = userResource.groups();
            
            // Check if any of the user's groups matches the site ID
            return userGroups.stream()
                .anyMatch(group -> group.getId().equals(groupId));
        } catch (Exception e) {
            log.error("Error checking if user {} is in group {}", userId, groupId, e);
            return false;
        }
    }

    /**
     * Adds a user to a site
     *
     * @param userId the user ID
     * @param groupId the site ID
     * @return true if user was added to site successfully, false otherwise
     */
    @Caching(evict = {
            @CacheEvict(value = GROUP_MEMBERS_CACHE, key = "#groupId + '_' + #userId"),
            @CacheEvict(value = USERS_IN_GROUP_CACHE, key = "#groupId"),
            @CacheEvict(value = USER_GROUPS_CACHE, key = "#userId"),
            @CacheEvict(value = USER_SITES_CACHE, key = "#userId")
    })
    public boolean addUserToKeycloakGroup(String userId, String groupId) {
        try {
            // Check if user is already in the site
            if (isUserInGroup(userId, groupId)) {
                log.info("User {} is already in site {}", userId, groupId);
                return true;
            }
            
            // Add user to site group
            UserResource userResource = getRealmResource().users().get(userId);
            userResource.joinGroup(groupId);
            
            log.info("Added user {} to site {}", userId, groupId);
            return true;
        } catch (Exception e) {
            log.error("Error adding user {} to site {}", userId, groupId, e);
            return false;
        }
    }

    /**
     * Generates a standardized site admin role name
     */
    public String getSiteAdminRoleName(String siteName) {
        return siteName.toLowerCase().replace(' ', '_') + "_site_admin";
    }

    /**
     * Creates a site user role when a new site is created
     */
    public boolean createSiteAdminRole(String siteName) {
        RealmResource realmResource = getRealmResource();
        String roleName = getSiteAdminRoleName(siteName);
        try {
            realmResource.roles().get(roleName).toRepresentation();
            log.info("Site admin role {} already exists.", roleName);
            return true; // Role already exists, consider it successful for this context
        } catch (NotFoundException e) {
            // Role does not exist, proceed to create
            log.debug("Site admin role {} does not exist. Creating...", roleName);
            try {
                RoleRepresentation role = new RoleRepresentation();
                role.setName(roleName);
                role.setDescription("User role for site: " + siteName);
                realmResource.roles().create(role);
                log.info("Created site admin role: {}", roleName);
                return true;
            } catch (Exception creationEx) {
                log.error("Error creating site admin role {}: {}", roleName, creationEx.getMessage(), creationEx);
                return false;
            }
        } catch (Exception ex) {
            // Other errors during role check
            log.error("Error checking existence of site admin role {}: {}", roleName, ex.getMessage(), ex);
            return false;
        }
    }

    /**
     * Assigns the site admin role to a user
     */
    @CacheEvict(value = USER_ROLES_CACHE, key = "#userId")
    public boolean assignSiteAdminRole(String userId, String siteName) {
        try {
            // Then assign it to the user
            String roleName = getSiteAdminRoleName(siteName);
            return assignRoleToUser(userId, roleName);
        } catch (Exception e) {
            log.error("Error assigning site role to user {}: {}", userId, e.getMessage(), e);
            return false;
        }
    }

    private String getGroupNameById(String groupId) {
        return getRealmResource().groups().group(groupId).toRepresentation().getName();
    }

    /**
     * Removes the site admin role from a user
     */
    @CacheEvict(value = {
            USER_ROLES_CACHE, 
            USER_ADMIN_GROUPS_CACHE
    }, key = "#userId")
    public void removeSiteAdminRole(String userId, String siteId, String requesterUserId) throws AccessDeniedException {
        if (!hasGlobalAdminRole(requesterUserId) &&
                !isUserSiteAdmin(requesterUserId, siteId)) {
            throw new AccessDeniedException("User can't remove site admin role in this site");
        }

        String roleName = getSiteAdminRoleName(getGroupNameById(siteId)); // This can throw if group not found
        UserResource userResource = getRealmResource().users().get(userId);
        
        try {
            RoleRepresentation roleToRemove = getRealmResource().roles().get(roleName).toRepresentation();
            if (roleToRemove == null) {
                 log.warn("Role {} to remove was found but its representation is null. Cannot remove.", roleName);
                 throw new RuntimeException("Error removing site admin role: Role representation is null.");
            }
            userResource.roles().realmLevel().remove(Collections.singletonList(roleToRemove));
            log.info("Removed site admin role {} from user {}", roleName, userId);
        } catch (NotFoundException e) {
            log.warn("Role {} not found, so it cannot be removed from user {}. Assuming effectively removed.", roleName, userId);
            // Role to remove doesn't exist, so user effectively doesn't have it.
        } catch (Exception e) {
            log.error("Error removing site admin role {} from user {}: {}", roleName, userId, e.getMessage(), e);
            throw new RuntimeException("Error removing site admin role, please try again", e);
        }
    }

    /**
     * Checks if a user is an admin of a site
     */
    @Cacheable(value = USER_SITE_ADMIN_STATUS, key = "#userId + '_' + #siteId")
    public boolean isUserSiteAdmin(String userId, String siteId) {
        // Global admins are implicitly site admins
        if (hasGlobalAdminRole(userId)) {
            return true;
        }

        try {
            log.debug("Cache miss: Checking if user '{}' is admin for site '{}'", userId, siteId);
            // Get the site name for the site ID
            Optional<GroupRepresentation> site = getGroupById(siteId);
            if (site.isEmpty()) {
                return false;
            }

            // Check if user has the site admin role
            String roleName = getSiteAdminRoleName(site.get().getName());
            List<String> userRoles = getUserRoles(userId);
            return userRoles.contains(roleName);
        } catch (Exception e) {
            log.error("Error checking if user is site admin: {}", e.getMessage(), e);
            return false;
        }
    }

    /**
     * Get sites where user is an admin
     */
    @Cacheable(value = USER_ADMIN_GROUPS_CACHE, key = "#userId")
    public List<String> getUserAdminGroups(String userId) {
        try {
            log.debug("Cache miss: Fetching admin groups for user '{}'", userId);
            // First check if the user exists by trying to fetch their representation.
            // This will throw an exception if the user doesn't exist, which is caught below.
            getRealmResource().users().get(userId).toRepresentation(); 
            
            // We need to get the user's roles directly instead of relying on groups
            List<String> roles = getUserRoles(userId);
            
            // Filter roles that match the site admin pattern: {sitename}_site_admin
            return roles.stream()
                .filter(role -> role.endsWith("_site_admin"))
                .map(role -> {
                    // Extract site name from the role name
                    // The format is {sitename}_site_admin, so we remove "_site_admin"
                    return role.substring(0, role.length() - "_site_admin".length());
                })
                .collect(Collectors.toList());
                
        } catch (NotFoundException e) {
            log.warn("User with ID {} not found when trying to fetch admin groups.", userId);
            return new ArrayList<>(); // User not found, so no admin groups
        } catch (Exception e) {
            log.error("Error getting admin sites for user {}", userId, e);
            return new ArrayList<>();
        }
    }

    // Add to KeycloakService
    @Cacheable(value = "keycloak_user_admin_group_ids", key = "#userId")
    public List<String> getUserAdminGroupIds(String userId) {
        // First get the site names
        List<String> siteNames = getUserAdminGroups(userId);
        log.debug("Sites: " + siteNames);
        // Then convert to IDs
        return siteNames.stream()
            .map(siteName -> getGroupByName(siteName))
            .filter(Optional::isPresent)
            .map(group -> group.get().getId())
            .collect(Collectors.toList());
    }

    /**
     * Check if a user has the GLOBAL_ADMIN role
     */
    public boolean hasGlobalAdminRole(String userId) {
        try {
            List<String> roles = getUserRoles(userId);
            return roles.contains("global_admin");
        } catch (Exception e) {
            log.error("Error checking if user {} has GLOBAL_ADMIN role", userId, e);
            return false;
        }
    }
    
    /**
     * Assign a role to a user
     */
    private boolean assignRoleToUser(String userId, String roleName) {
        try {
            UserResource userResource = getRealmResource().users().get(userId);
            RoleRepresentation role = getRealmResource().roles().get(roleName).toRepresentation();
            
            if (role == null) { // Should ideally be caught by NotFoundException if role doesn't exist
                log.error("Role {} not found or its representation is null. Cannot assign to user {}.", roleName, userId);
                return false;
            }
            
            userResource.roles().realmLevel().add(Collections.singletonList(role));
            log.info("Assigned role {} to user {}", roleName, userId);
            return true;
        } catch (NotFoundException e) {
            log.error("Role {} not found. Cannot assign to user {}. Ensure role exists.", roleName, userId, e);
            return false;
        } catch (Exception e) {
            log.error("Error assigning role {} to user {}", roleName, userId, e);
            return false;
        }
    }

    /**
     * Remove a role from a user
     */
    private boolean removeRoleFromUser(String userId, String roleName) {
        try {
            UserResource userResource = getRealmResource().users().get(userId);
            RoleRepresentation role = getRealmResource().roles().get(roleName).toRepresentation();
            
            if (role == null) {
                log.warn("Role {} not found or its representation is null. Cannot remove from user {}.", roleName, userId);
                return false;
            }
            
            userResource.roles().realmLevel().remove(Collections.singletonList(role));
            log.info("Removed role {} from user {}", roleName, userId);
            return true;
        } catch (NotFoundException e) {
            log.warn("Role {} not found. Cannot remove from user {}. Assuming already removed.", roleName, userId);
            return true; // Role doesn't exist, so effectively removed
        } catch (Exception e) {
            log.error("Error removing role {} from user {}", roleName, userId, e);
            return false;
        }
    }

    /**
     * Get users who are members of a specific site (group)
     * @param groupId
     */
    @Cacheable(value = USERS_IN_GROUP_CACHE, key = "#groupId", unless = "#result.isEmpty()")
    public List<UserRepresentation> getUsersInGroup(String groupId) {
        try {
            // Get the site (group) resource
            GroupResource groupResource = getRealmResource().groups().group(groupId);
            
            // Fetch all members of the group
            List<UserRepresentation> members = groupResource.members();
            
            log.debug("Found {} users in site {}", members.size(), groupId);
            return members;
        } catch (Exception e) {
            log.error("Error getting users in site {}", groupId, e);
            return Collections.emptyList();
        }
    }

    /**
     * Remove a user from a site (group)
     */
    @Caching(evict = {        
        @CacheEvict(value = USERS_CACHE, allEntries = true),
        @CacheEvict(value = USER_GROUPS_CACHE, key = "#userId"),
        @CacheEvict(value = USER_SITES_CACHE, key = "#userId"),
        @CacheEvict(value = USERS_IN_GROUP_CACHE, allEntries = true),
        @CacheEvict(value = GROUP_MEMBERS_CACHE, allEntries = true),
    })
    public boolean removeUserFromSite(String userId, String siteId) {
        try {
            // Check if user is actually in the site
            if (!isUserInGroup(userId, siteId)) {
                log.info("User {} is not in site {}, nothing to remove", userId, siteId);
                return true; // Not an error since the end state is what was desired
            }

            // Get the user resource
            UserResource userResource = getRealmResource().users().get(userId);
            
            // Remove the user from the group
            userResource.leaveGroup(siteId);
            
            // Verify removal was successful
            boolean stillInSite = isUserInGroup(userId, siteId);
            if (stillInSite) {
                log.warn("Failed to remove user {} from site {} - user is still a member", userId, siteId);
                return false;
            }
            
            log.info("Successfully removed user {} from site {}", userId, siteId);
            return true;
        } catch (Exception e) {
            log.error("Error removing user {} from site {}: {}", userId, siteId, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Get all sites ids (groups) a user belongs to
     */
    public List<String> getUserSites(String userId) {
        try {
            // Get the user resource
            UserResource userResource = getRealmResource().users().get(userId);
            
            // Get all groups the user belongs to
            List<GroupRepresentation> userGroups = userResource.groups();
            
            // Extract the site IDs (group IDs)
            List<String> siteIds = userGroups.stream()
                .map(GroupRepresentation::getId)
                .collect(Collectors.toList());
            
            log.debug("User {} belongs to {} sites", userId, siteIds.size());
            return siteIds;
        } catch (Exception e) {
            log.error("Error retrieving sites for user {}: {}", userId, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Get all sites a user belongs to as GroupRepresentations
     */
    // FIX: added @Cacheable — USER_GROUPS_CACHE was being evicted in multiple methods but never populated through this path
    @Cacheable(value = USER_GROUPS_CACHE, key = "#userId", unless = "#result.isEmpty()")
    public List<GroupRepresentation> getUserGroups(String userId) {
        try {
            // Get the user resource
            UserResource userResource = getRealmResource().users().get(userId);
            
            // Get all groups the user belongs to
            List<GroupRepresentation> userGroups = userResource.groups();
            
            log.debug("User {} belongs to {} site groups", userId, userGroups.size());
            return userGroups;
        } catch (Exception e) {
            log.error("Error retrieving site groups for user {}: {}", userId, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

    /**
     * Make a user a site admin
     */
    @Caching(evict = {        
        @CacheEvict(value = USERS_CACHE, allEntries = true),
        @CacheEvict(value = USER_GROUPS_CACHE, key = "#userId"),
        @CacheEvict(value = USER_SITES_CACHE, key = "#userId"),
        @CacheEvict(value = USERS_IN_GROUP_CACHE, allEntries = true),
        @CacheEvict(value = GROUP_MEMBERS_CACHE, allEntries = true),
        @CacheEvict(value = USER_SITE_ADMIN_STATUS, key = "#userId + '_' + #siteId")
    })
    public boolean makeSiteAdmin(String userId, String siteId, String requesterUserId) throws AccessDeniedException {
        if (!hasGlobalAdminRole(requesterUserId) &&
                !isUserSiteAdmin(requesterUserId, siteId)) {
            throw new AccessDeniedException("User can't add new users to this site");
        }

        try {

            // First ensure the user is a member of the site
            if (!isUserInGroup(userId, siteId)) {
                addUserToKeycloakGroup(userId, siteId);
            }

            // Get the site name
            Optional<GroupRepresentation> site = getGroupById(siteId);
            if (site.isEmpty()) {
                return false;
            }

            // Assign the site admin role
            return assignSiteAdminRole(userId, site.get().getName());
        } catch (Exception e) {
            log.error("Error making user {} admin of site {}: {}", userId, siteId, e.getMessage(), e);
            return false;
        }
    }

    /**
     * Creates a UserRepresentation object from a UserDTO
     *
     * @param userDTO the user data transfer object
     * @return the created UserRepresentation
     */
    private UserRepresentation createUserRepresentation(UserDTO userDTO) {
        UserRepresentation user = new UserRepresentation();

        // Set basic fields
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        user.setEnabled(true);
        user.setEmailVerified(true);

        // Set attributes
        Map<String, List<String>> attributes = createUserAttributes(userDTO);
        user.setAttributes(attributes);

        return user;
    }

    /**
     * Creates a map of user attributes from a UserDTO
     *
     * @param userDTO the user data transfer object
     * @return the map of user attributes
     */
    private Map<String, List<String>> createUserAttributes(UserDTO userDTO) {
        Map<String, List<String>> attributes = new HashMap<>();

        // Add SSH key if provided
        if (userDTO.getSshPublicKey() != null && !userDTO.getSshPublicKey().isEmpty()) {
            attributes.put(ATTR_SSH_KEY, Collections.singletonList(userDTO.getSshPublicKey()));
        }

        // Add avatar if provided
        if (userDTO.getAvatar() != null && !userDTO.getAvatar().isEmpty()) {
            attributes.put(ATTR_AVATAR, Collections.singletonList(userDTO.getAvatar()));
        }

        return attributes;
    }

    /**
     * Creates the user in Keycloak
     *
     * @param user the user representation
     * @return the ID of the created user, or null if creation failed
     */
    private String createUserInKeycloak(UserRepresentation user) {
        UsersResource usersResource = getRealmResource().users();

        // Detailed log of the user representation
        log.debug("User representation: {}", user);

        Response response = usersResource.create(user);
        log.debug("User creation response - Status: {}, Message: {}",
                response.getStatus(), response.getStatusInfo().getReasonPhrase());

        if (response.getStatus() != 201) {
            if (response.hasEntity()) {
                // Try to read the response body to better understand the error
                String responseBody = response.readEntity(String.class);
                log.error("Error details from Keycloak: {}", responseBody);
            }
            log.error("User creation failed in Keycloak: {} ({})",
                    response.getStatusInfo().getReasonPhrase(), response.getStatus());
            return null;
        }

        // Get created user ID
        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        log.info("User created in Keycloak with ID: {}", userId);

        return userId;
    }

    /**
     * Sets the password for a user
     *
     * @param userId the user ID
     * @param password the password to set
     * @return true if password was set successfully, false otherwise
     */
    private boolean setUserPassword(String userId, String password) {
        try {
            CredentialRepresentation credential = new CredentialRepresentation();
            credential.setType(CredentialRepresentation.PASSWORD);
            credential.setValue(password);
            credential.setTemporary(false);

            getRealmResource().users().get(userId).resetPassword(credential);
            log.debug("Password successfully set for user: {}", userId);
            return true;
        } catch (Exception e) {
            log.error("Error setting password for user: {}", userId, e);
            return false;
        }
    }

    /**
     * Assigns groups to a user
     *
     * @param userId the user ID
     * @return true if groups were assigned successfully, false otherwise
     */
    private boolean assignGroupsToUser(String userId) {
        try {
            log.debug("Attempting to assign groups to user: {}", userId);
            
            // Get the user resource
            UserResource userResource = getRealmResource().users().get(userId);
            
            // Get all groups in the realm
            // FIX: explicit pagination to avoid the server-side default limit in KC 26
            List<GroupRepresentation> groups = getRealmResource().groups().groups(0, Integer.MAX_VALUE);
            
            // Join each group individually
            for (GroupRepresentation group : groups) {
                userResource.joinGroup(group.getId());
                log.debug("Added user {} to group {}", userId, group.getName());
            }
            
            log.debug("All groups successfully assigned to user: {}", userId);
            return true;
        } catch (Exception e) {
            log.error("Error assigning groups to user: {}", userId, e);
            return false;
        }
    }

    /**
     * Get site name by site ID, returning a default value if site is not found
     * @param siteId The ID of the site/group
     * @param defaultName The default name to return if site is not found
     * @return The site name, or the default name if site is not found
     */
    public String getSiteNameById(String siteId, String defaultName) {
        Optional<GroupRepresentation> groupRepresentation = getGroupById(siteId);
        if (groupRepresentation.isPresent()) {
            return groupRepresentation.get().getName();
        } else {
            return defaultName;
        }
    }

}