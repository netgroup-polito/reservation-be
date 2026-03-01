package it.polito.cloudresources.be.service;

import it.polito.cloudresources.be.dto.users.UserDTO;
import jakarta.transaction.Transactional;
import jakarta.ws.rs.core.Response;
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

import jakarta.ws.rs.NotFoundException;
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

    // RIMOSSO: public static final String ATTR_SSH_KEY = "ssh_key";
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

    protected Keycloak getKeycloakClient() {
        return KeycloakBuilder.builder()
                .serverUrl(authServerUrl)
                .realm(realm)
                .clientId(clientId)
                .clientSecret(clientSecret)
                .grantType(OAuth2Constants.CLIENT_CREDENTIALS)
                .build();
    }

    protected RealmResource getRealmResource() {
        return getKeycloakClient().realm(realm);
    }

    @Cacheable(value = USERS_CACHE, unless = "#result.isEmpty()")
    public List<UserRepresentation> getUsers() {
        try {
            log.debug("Cache miss: Fetching all users from Keycloak");
            return getRealmResource().users().list();
        } catch (Exception e) {
            log.error("Error fetching users from Keycloak", e);
            return Collections.emptyList();
        }
    }

    @Cacheable(value = USER_BY_USERNAME_CACHE, key = "#username", unless = "#result == null")
    public Optional<UserRepresentation> getUserByUsername(String username) {
        try {
            log.debug("Cache miss: Fetching user by username '{}'", username);
            List<UserRepresentation> users = getRealmResource().users().search(username, null, null, null, 0, 1);
            return users.isEmpty() ? Optional.empty() : Optional.of(users.get(0));
        } catch (Exception e) {
            log.error("Error fetching user from Keycloak by username", e);
            return Optional.empty();
        }
    }

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

    @Transactional
    @Caching(evict = {
            @CacheEvict(value = USERS_CACHE, allEntries = true),
            @CacheEvict(value = USER_BY_ROLE_CACHE, allEntries = true)
    })
    public String createUser(UserDTO userDTO, String password) {
        try {
            log.debug("Attempting to create user: username={}, email={}, firstName={}, lastName={}",
                    userDTO.getUsername(), userDTO.getEmail(), userDTO.getFirstName(), userDTO.getLastName());

            UserRepresentation user = createUserRepresentation(userDTO);

            String userId = createUserInKeycloak(user);
            if (userId == null) {
                return null;
            }

            if (!setUserPassword(userId, password)) {
                log.warn("Password could not be set for user: {}", userId);
            }

            assignGroupsToUser(userId);
            Set<String> roles = userDTO.getRoles();
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

    @Transactional
    @Caching(evict = {
            @CacheEvict(value = USER_BY_ID_CACHE, key = "#userId"),
            @CacheEvict(value = USERS_CACHE, allEntries = true),
            @CacheEvict(value = USER_ATTRIBUTES_CACHE, key = "#userId + '_*'"),
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

            Map<String, List<String>> userAttributes = user.getAttributes();
            if (userAttributes == null) {
                userAttributes = new HashMap<>();
            }

            // RIMOSSO BLOCCO ATTR_SSH_KEY

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
                
                List<String> normalizedNewRoleNames = newRoleNames.stream()
                    .map(roleName -> {
                        if (roleName.endsWith("_site_admin")) {
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
                
                List<String> rolesToAdd = normalizedNewRoleNames.stream()
                    .filter(roleName -> !currentRoleNames.contains(roleName))
                    .collect(Collectors.toList());
                
                List<String> rolesToRemove = currentRoleNames.stream()
                    .filter(roleName -> !normalizedNewRoleNames.contains(roleName))
                    .collect(Collectors.toList());
                
                for (String roleName : rolesToAdd) {
                    assignRoleToUser(userId, roleName);
                }
                for (String roleName : rolesToRemove) {
                    removeRoleFromUser(userId, roleName);
                }
                
                log.info("Updated roles for user {}: added {}, removed {}", userId, rolesToAdd, rolesToRemove);
            }

            user.setAttributes(userAttributes);
            userResource.update(user);
            log.debug("Basic user info updated for user: {}", userId);

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

    @Caching(evict = {
            @CacheEvict(value = USER_BY_ID_CACHE, key = "#userId"),
            @CacheEvict(value = USERS_CACHE, allEntries = true),
            @CacheEvict(value = USER_ATTRIBUTES_CACHE, key = "#userId + '_*'"),
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


    public Optional<String> getUserAvatar(String userId) {
        return getUserAttribute(userId, ATTR_AVATAR);
    }

    public void ensureRealmRoles(String... roleNames) {
        RealmResource realmResource = getRealmResource();
        for (String roleName : roleNames) {
            try {
                realmResource.roles().get(roleName).toRepresentation();
                log.debug("Role {} already exists in Keycloak.", roleName);
            } catch (NotFoundException e) {
                log.info("Role {} not found in Keycloak. Creating...", roleName);
                createRoleInKeycloakInternal(realmResource, roleName);
            } catch (Exception e) {
                log.error("Error ensuring realm role {} in Keycloak: {}", roleName, e.getMessage(), e);
            }
        }
    }

    private void createRoleInKeycloakInternal(RealmResource realmResource, String roleName) {
        try {
            RoleRepresentation role = new RoleRepresentation();
            role.setName(roleName);
            realmResource.roles().create(role);
            log.info("Created role in Keycloak: {}", roleName);
        } catch (Exception e) {
            log.error("Error creating role {} in Keycloak: {}", roleName, e.getMessage(), e);
        }
    }

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
        return getRealmResource().groups().groups();
    }
    
    @Cacheable(value = GROUP_BY_ID_CACHE, key = "#groupId")
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

    @Cacheable(value = GROUP_BY_NAME_CACHE, key = "#groupName")
    public Optional<GroupRepresentation> getGroupByName(String groupName) {
        try {
            log.debug("Cache miss: Fetching group by name '{}'", groupName);
            return getRealmResource().groups().groups().stream()
                    .filter(group -> group.getName().equals(groupName))
                    .findFirst();
        } catch (Exception e) {
            log.error("Error fetching site", e);
            return Optional.empty();
        }
    }
    
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

        Map<String, List<String>> attributes = new HashMap<>();
        if (description != null && !description.isEmpty()) {
            attributes.put("description", Collections.singletonList(description));
            group.setAttributes(attributes);
        }

        String groupId = setupNewKeycloakGroup(group);

        if (groupId != null) {
            createSiteAdminRole(name);
            log.debug("Creating group in private mode: {}", privateSite);
            if(!privateSite) {
                List<UserRepresentation> allUsers = getUsers();
                for (UserRepresentation user : allUsers) {
                    addUserToKeycloakGroup(user.getId(), groupId);
                }
            }
        }
        return groupId;
    }
    
    @Caching(evict = {
            @CacheEvict(value = GROUP_BY_ID_CACHE, key = "#groupId"),
            @CacheEvict(value = GROUPS_CACHE, allEntries = true),
            @CacheEvict(value = GROUP_BY_NAME_CACHE, allEntries = true)
    })
    public boolean updateGroup(String groupId, GroupRepresentation updatedGroup) {
        try {
            GroupResource groupResource = getRealmResource().groups().group(groupId);
            GroupRepresentation currentGroup = groupResource.toRepresentation();
            
            updatedGroup.setId(groupId);
            
            if (updatedGroup.getSubGroups() == null && currentGroup.getSubGroups() != null) {
                updatedGroup.setSubGroups(currentGroup.getSubGroups());
            }
            
            groupResource.update(updatedGroup);
            log.info("Updated site with ID: {}", groupId);
            return true;
        } catch (Exception e) {
            log.error("Error updating site with ID: {}", groupId, e);
            return false;
        }
    }
    
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
            GroupRepresentation group = groupResource.toRepresentation(); 
            
            String roleToRemove = getSiteAdminRoleName(group.getName());

            groupResource.remove();
            log.info("Deleted group with ID: {}", groupId);

            try {
                realmResource.roles().deleteRole(roleToRemove);
                log.info("Deleted role: {}", roleToRemove);
            } catch (NotFoundException e) {
                log.warn("Role {} not found, could not delete it or it was already deleted.", roleToRemove);
            } catch (Exception e) {
                log.error("Error deleting role {}: {}", roleToRemove, e.getMessage(), e);
            }
            return true;
        } catch (NotFoundException e) {
            log.warn("Group with ID {} not found for deletion.", groupId);
            return false;
        } catch (Exception e) {
            log.error("Error deleting group with ID: {}", groupId, e);
            return false;
        }
    }

    @Cacheable(value = GROUP_MEMBERS_CACHE, key = "#groupId + '_' + #userId")
    public boolean isUserInGroup(String userId, String groupId) {
        try {
            log.debug("Cache miss: Checking if user '{}' is in group '{}'", userId, groupId);
            UserResource userResource = getRealmResource().users().get(userId);
            List<GroupRepresentation> userGroups = userResource.groups();
            
            return userGroups.stream()
                .anyMatch(group -> group.getId().equals(groupId));
        } catch (Exception e) {
            log.error("Error checking if user {} is in group {}", userId, groupId, e);
            return false;
        }
    }

    @Caching(evict = {
            @CacheEvict(value = GROUP_MEMBERS_CACHE, key = "#groupId + '_' + #userId"),
            @CacheEvict(value = USERS_IN_GROUP_CACHE, key = "#groupId"),
            @CacheEvict(value = USER_GROUPS_CACHE, key = "#userId"),
            @CacheEvict(value = USER_SITES_CACHE, key = "#userId")
    })
    public boolean addUserToKeycloakGroup(String userId, String groupId) {
        try {
            if (isUserInGroup(userId, groupId)) {
                log.info("User {} is already in site {}", userId, groupId);
                return true;
            }
            
            UserResource userResource = getRealmResource().users().get(userId);
            userResource.joinGroup(groupId);
            
            log.info("Added user {} to site {}", userId, groupId);
            return true;
        } catch (Exception e) {
            log.error("Error adding user {} to site {}", userId, groupId, e);
            return false;
        }
    }

    public String getSiteAdminRoleName(String siteName) {
        return siteName.toLowerCase().replace(' ', '_') + "_site_admin";
    }

    public boolean createSiteAdminRole(String siteName) {
        RealmResource realmResource = getRealmResource();
        String roleName = getSiteAdminRoleName(siteName);
        try {
            realmResource.roles().get(roleName).toRepresentation();
            log.info("Site admin role {} already exists.", roleName);
            return true; 
        } catch (NotFoundException e) {
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
            log.error("Error checking existence of site admin role {}: {}", roleName, ex.getMessage(), ex);
            return false;
        }
    }

    @CacheEvict(value = USER_ROLES_CACHE, key = "#userId")
    public boolean assignSiteAdminRole(String userId, String siteName) {
        try {
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

    @CacheEvict(value = {
            USER_ROLES_CACHE, 
            USER_ADMIN_GROUPS_CACHE
    }, key = "#userId")
    public void removeSiteAdminRole(String userId, String siteId, String requesterUserId) throws AccessDeniedException {
        if (!hasGlobalAdminRole(requesterUserId) &&
                !isUserSiteAdmin(requesterUserId, siteId)) {
            throw new AccessDeniedException("User can't remove site admin role in this site");
        }

        String roleName = getSiteAdminRoleName(getGroupNameById(siteId)); 
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
        } catch (Exception e) {
            log.error("Error removing site admin role {} from user {}: {}", roleName, userId, e.getMessage(), e);
            throw new RuntimeException("Error removing site admin role, please try again", e);
        }
    }

    @Cacheable(value = USER_SITE_ADMIN_STATUS, key = "#userId + '_' + #siteId")
    public boolean isUserSiteAdmin(String userId, String siteId) {
        if (hasGlobalAdminRole(userId)) {
            return true;
        }

        try {
            log.debug("Cache miss: Checking if user '{}' is admin for site '{}'", userId, siteId);
            Optional<GroupRepresentation> site = getGroupById(siteId);
            if (site.isEmpty()) {
                return false;
            }

            String roleName = getSiteAdminRoleName(site.get().getName());
            List<String> userRoles = getUserRoles(userId);
            return userRoles.contains(roleName);
        } catch (Exception e) {
            log.error("Error checking if user is site admin: {}", e.getMessage(), e);
            return false;
        }
    }

    @Cacheable(value = USER_ADMIN_GROUPS_CACHE, key = "#userId")
    public List<String> getUserAdminGroups(String userId) {
        try {
            log.debug("Cache miss: Fetching admin groups for user '{}'", userId);
            getRealmResource().users().get(userId).toRepresentation(); 
            
            List<String> roles = getUserRoles(userId);
            
            return roles.stream()
                .filter(role -> role.endsWith("_site_admin"))
                .map(role -> role.substring(0, role.length() - "_site_admin".length()))
                .collect(Collectors.toList());
                
        } catch (NotFoundException e) {
            log.warn("User with ID {} not found when trying to fetch admin groups.", userId);
            return new ArrayList<>(); 
        } catch (Exception e) {
            log.error("Error getting admin sites for user {}", userId, e);
            return new ArrayList<>();
        }
    }

    @Cacheable(value = "keycloak_user_admin_group_ids", key = "#userId")
    public List<String> getUserAdminGroupIds(String userId) {
        List<String> siteNames = getUserAdminGroups(userId);
        log.debug("Sites: " + siteNames);
        return siteNames.stream()
            .map(siteName -> getGroupByName(siteName))
            .filter(Optional::isPresent)
            .map(group -> group.get().getId())
            .collect(Collectors.toList());
    }

  

    public boolean hasGlobalAdminRole(String userId) {
    try {
        List<String> roles = getUserRoles(userId);
        // Usa stream().anyMatch con ignoreCase per massima sicurezza
        return roles.stream().anyMatch(role -> role.equalsIgnoreCase("global_admin"));
    } catch (Exception e) {
        log.error("Error checking if user {} has GLOBAL_ADMIN role", userId, e);
        return false;
    }
}
    
    @Caching(evict = {
        @CacheEvict(value = USERS_CACHE, allEntries = true),
        @CacheEvict(value = USER_ROLES_CACHE, key = "#userId"),
        @CacheEvict(value = USER_BY_ID_CACHE, key = "#userId"),
        @CacheEvict(value = USER_BY_ROLE_CACHE, allEntries = true)
    })
    public boolean assignRoleToUser(String userId, String roleName) {
        try {
            UserResource userResource = getRealmResource().users().get(userId);
            
            RoleRepresentation role;
            try {
                role = getRealmResource().roles().get(roleName).toRepresentation();
            } catch (NotFoundException e) {
                log.error("Role {} not found in Keycloak.", roleName);
                return false;
            }
            
            if (role == null) {
                log.error("Role {} representation is null. Cannot assign to user {}.", roleName, userId);
                return false;
            }
            
            userResource.roles().realmLevel().add(Collections.singletonList(role));
            log.info("Assigned role {} to user {}", roleName, userId);
            return true;
        } catch (NotFoundException e) {
            log.error("User {} not found when assigning role {}.", userId, roleName, e);
            return false;
        } catch (Exception e) {
            log.error("Error assigning role {} to user {}", roleName, userId, e);
            return false;
        }
    }

    @Caching(evict = {
        @CacheEvict(value = USERS_CACHE, allEntries = true),
        @CacheEvict(value = USER_ROLES_CACHE, key = "#userId"),
        @CacheEvict(value = USER_BY_ID_CACHE, key = "#userId"),
        @CacheEvict(value = USER_BY_ROLE_CACHE, allEntries = true)
    })
    public boolean removeRoleFromUser(String userId, String roleName) {
        try {
            UserResource userResource = getRealmResource().users().get(userId);
            
            RoleRepresentation role;
            try {
                role = getRealmResource().roles().get(roleName).toRepresentation();
            } catch (NotFoundException e) {
                log.warn("Role {} not found. Cannot remove from user {}. Assuming already removed.", roleName, userId);
                return true; 
            }
            
            if (role == null) {
                return false;
            }
            
            userResource.roles().realmLevel().remove(Collections.singletonList(role));
            log.info("Removed role {} from user {}", roleName, userId);
            return true;
        } catch (NotFoundException e) {
            log.warn("User {} not found when removing role.", userId);
            return false; 
        } catch (Exception e) {
            log.error("Error removing role {} from user {}", roleName, userId, e);
            return false;
        }
    }

    @Cacheable(value = USERS_IN_GROUP_CACHE, key = "#groupId", unless = "#result.isEmpty()")
    public List<UserRepresentation> getUsersInGroup(String groupId) {
        try {
            GroupResource groupResource = getRealmResource().groups().group(groupId);
            List<UserRepresentation> members = groupResource.members();
            
            log.debug("Found {} users in site {}", members.size(), groupId);
            return members;
        } catch (Exception e) {
            log.error("Error getting users in site {}", groupId, e);
            return Collections.emptyList();
        }
    }

    @Caching(evict = {        
        @CacheEvict(value = USERS_CACHE, allEntries = true),
        @CacheEvict(value = USER_GROUPS_CACHE, key = "#userId"),
        @CacheEvict(value = USER_SITES_CACHE, key = "#userId"),
        @CacheEvict(value = USERS_IN_GROUP_CACHE, allEntries = true),
        @CacheEvict(value = GROUP_MEMBERS_CACHE, allEntries = true),
    })
    public boolean removeUserFromSite(String userId, String siteId) {
        try {
            if (!isUserInGroup(userId, siteId)) {
                log.info("User {} is not in site {}, nothing to remove", userId, siteId);
                return true; 
            }

            UserResource userResource = getRealmResource().users().get(userId);
            userResource.leaveGroup(siteId);
            
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

    public List<String> getUserSites(String userId) {
        try {
            UserResource userResource = getRealmResource().users().get(userId);
            List<GroupRepresentation> userGroups = userResource.groups();
            
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

    public List<GroupRepresentation> getUserGroups(String userId) {
        try {
            UserResource userResource = getRealmResource().users().get(userId);
            List<GroupRepresentation> userGroups = userResource.groups();
            
            log.debug("User {} belongs to {} site groups", userId, userGroups.size());
            return userGroups;
        } catch (Exception e) {
            log.error("Error retrieving site groups for user {}: {}", userId, e.getMessage(), e);
            return Collections.emptyList();
        }
    }

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
            if (!isUserInGroup(userId, siteId)) {
                addUserToKeycloakGroup(userId, siteId);
            }

            Optional<GroupRepresentation> site = getGroupById(siteId);
            if (site.isEmpty()) {
                return false;
            }

            return assignSiteAdminRole(userId, site.get().getName());
        } catch (Exception e) {
            log.error("Error making user {} admin of site {}: {}", userId, siteId, e.getMessage(), e);
            return false;
        }
    }

    private UserRepresentation createUserRepresentation(UserDTO userDTO) {
        UserRepresentation user = new UserRepresentation();
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        user.setEnabled(true);
        user.setEmailVerified(true);

        Map<String, List<String>> attributes = createUserAttributes(userDTO);
        user.setAttributes(attributes);

        return user;
    }

    private Map<String, List<String>> createUserAttributes(UserDTO userDTO) {
        Map<String, List<String>> attributes = new HashMap<>();

        // RIMOSSO BLOCCO ATTR_SSH_KEY

        if (userDTO.getAvatar() != null && !userDTO.getAvatar().isEmpty()) {
            attributes.put(ATTR_AVATAR, Collections.singletonList(userDTO.getAvatar()));
        }

        return attributes;
    }

    private String createUserInKeycloak(UserRepresentation user) {
        UsersResource usersResource = getRealmResource().users();
        log.debug("User representation: {}", user);

        Response response = usersResource.create(user);
        log.debug("User creation response - Status: {}, Message: {}",
                response.getStatus(), response.getStatusInfo().getReasonPhrase());

        if (response.getStatus() != 201) {
            if (response.hasEntity()) {
                String responseBody = response.readEntity(String.class);
                log.error("Error details from Keycloak: {}", responseBody);
            }
            log.error("User creation failed in Keycloak: {} ({})",
                    response.getStatusInfo().getReasonPhrase(), response.getStatus());
            return null;
        }

        String userId = response.getLocation().getPath().replaceAll(".*/([^/]+)$", "$1");
        log.info("User created in Keycloak with ID: {}", userId);

        return userId;
    }

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

    private boolean assignGroupsToUser(String userId) {
        try {
            log.debug("Attempting to assign groups to user: {}", userId);
            UserResource userResource = getRealmResource().users().get(userId);
            List<GroupRepresentation> groups = getRealmResource().groups().groups();
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

    public boolean hasRole(String userId, String roleName) {
        try {
            List<String> roles = getUserRoles(userId);
            return roles.stream().anyMatch(r -> r.equalsIgnoreCase(roleName));
        } catch (Exception e) {
            log.error("Error checking role {} for user {}", roleName, userId, e);
            return false;
        }
    }

    public String getSiteNameById(String siteId, String defaultName) {
        Optional<GroupRepresentation> groupRepresentation = getGroupById(siteId);
        if (groupRepresentation.isPresent()) {
            return groupRepresentation.get().getName();
        } else {
            return defaultName;
        }
    }

}