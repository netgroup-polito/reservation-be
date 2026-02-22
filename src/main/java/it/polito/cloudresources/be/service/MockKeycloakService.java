package it.polito.cloudresources.be.service;

import it.polito.cloudresources.be.dto.users.UserDTO;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Service;

import java.util.*;
import java.util.stream.Collectors;

/**
 * Mock implementation of the KeycloakService for development without an actual Keycloak server
 */
@Service
@Profile("dev")
@Slf4j
public class MockKeycloakService extends KeycloakService {

    // In-memory storage of mock users
    private final Map<String, UserRepresentation> users = new HashMap<>();
    private final Map<String, List<String>> userRoles = new HashMap<>();
    private final Map<String, Map<String, List<String>>> userAttributes = new HashMap<>();

    // In-memory storage of mock sites (groups)
    private final Map<String, GroupRepresentation> sites = new HashMap<>();
    private final Map<String, Set<String>> siteMembers = new HashMap<>(); // siteId -> Set of userIds
    private final Map<String, Set<String>> userSites = new HashMap<>(); // userId -> Set of siteIds

    /**
     * Constructor initializes with basic structure
     */
   public MockKeycloakService() {
    log.info("Initializing MockKeycloakService");
    
    String adminId = UUID.randomUUID().toString();
    UserRepresentation adminUser = new UserRepresentation();
    UserRepresentation user = new UserRepresentation();

    adminUser.setId(adminId);
    adminUser.setUsername("admin1");
    adminUser.setEmail("admin@example.com");
    adminUser.setFirstName("Global");
    adminUser.setLastName("Admin");
    adminUser.setEnabled(true);
    
    users.put(adminId, adminUser);

    String userId = UUID.randomUUID().toString();

    user.setId(userId);
    user.setUsername("user1");
    user.setEmail("user@example.com");
    user.setFirstName("User");
    user.setLastName("UserLasname");
    user.setEnabled(true);
    
    users.put(userId, user);
    
    // USIAMO RUOLI MINUSCOLI
    userRoles.put(adminId, new ArrayList<>(Arrays.asList("global_admin", "user")));
    userSites.put(adminId, new HashSet<>());
    userRoles.put(userId, new ArrayList<>(Arrays.asList("user")));
    userSites.put(userId, new HashSet<>());
    
    log.info("Created bootstrap admin user with ID: {}", adminId);
    }

    /**
     * Assign a role to a user - public version for initialization
     */
    public boolean assignRoleToUser(String userId, String roleName) {
        try {
            List<String> userRolesList = userRoles.getOrDefault(userId, new ArrayList<>());
            if (!userRolesList.contains(roleName)) {
                userRolesList.add(roleName);
                userRoles.put(userId, userRolesList);
                log.info("Assigned role {} to user {}", roleName, userId);
            }
            return true;
        } catch (Exception e) {
            log.error("Error assigning role {} to user {}", roleName, userId, e);
            return false;
        }
    }

    @Override
    public List<UserRepresentation> getUsers() {
        return new ArrayList<>(users.values());
    }

    @Override
    public Optional<UserRepresentation> getUserByUsername(String username) {
        return users.values().stream()
                .filter(user -> user.getUsername().equals(username))
                .findFirst();
    }

    @Override
    public Optional<UserRepresentation> getUserByEmail(String email) {
        return users.values().stream()
                .filter(user -> user.getEmail().equals(email))
                .findFirst();
    }

    @Override
    public Optional<UserRepresentation> getUserById(String id) {
        return Optional.ofNullable(users.get(id));
    }

    @Override
    public String createUser(UserDTO userDTO, String password) {
        String userId = UUID.randomUUID().toString();

        UserRepresentation user = new UserRepresentation();
        user.setId(userId);
        user.setUsername(userDTO.getUsername());
        user.setEmail(userDTO.getEmail());
        user.setFirstName(userDTO.getFirstName());
        user.setLastName(userDTO.getLastName());
        user.setEnabled(true);
        user.setEmailVerified(true);

        // Set attributes
        Map<String, List<String>> attributes = new HashMap<>();
        
        // RIMOSSO BLOCCO SSH KEY (che usava ATTR_SSH_KEY)
        
        if (userDTO.getAvatar() != null && !userDTO.getAvatar().isEmpty()) {
            attributes.put(ATTR_AVATAR, Collections.singletonList(userDTO.getAvatar()));
        }
        userAttributes.put(userId, attributes);

        Set<String> roles = userDTO.getRoles();
        
        users.put(userId, user);
        userRoles.put(userId, roles != null ? new ArrayList<>(roles) : new ArrayList<>());
        userSites.put(userId, new HashSet<>());

        // Add user to site if specified
        if (userDTO.getSiteId() != null && !userDTO.getSiteId().isEmpty()) {
            addUserToKeycloakGroup(userId, userDTO.getSiteId());
        }

        log.info("Created mock user: {}", userDTO.getUsername());
        return userId;
    }

    @Override
    public boolean updateUser(String userId, Map<String, Object> attributes) {
        UserRepresentation user = users.get(userId);
        if (user == null) {
            return false;
        }

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

        // Handle user attributes
        Map<String, List<String>> userAttrs = userAttributes.getOrDefault(userId, new HashMap<>());

        // RIMOSSO BLOCCO SSH KEY (che usava ATTR_SSH_KEY)

        if (attributes.containsKey(ATTR_AVATAR)) {
            String avatar = (String) attributes.get(ATTR_AVATAR);
            if (avatar != null && !avatar.isEmpty()) {
                userAttrs.put(ATTR_AVATAR, Collections.singletonList(avatar));
            } else {
                userAttrs.remove(ATTR_AVATAR);
            }
        }

        userAttributes.put(userId, userAttrs);

        if (attributes.containsKey("roles")) {
            @SuppressWarnings("unchecked")
            List<String> roles = (List<String>) attributes.get("roles");
            
            // Normalize site_admin role names to ensure consistency
            List<String> normalizedRoles = roles.stream()
                .map(roleName -> {
                    if (roleName.endsWith("_site_admin")) {
                        // Extract site name and normalize it
                        String siteName = roleName.substring(0, roleName.length() - "_site_admin".length());
                        return getSiteAdminRoleName(siteName);
                    }
                    return roleName;
                })
                .collect(Collectors.toList());
            
            userRoles.put(userId, normalizedRoles != null ? new ArrayList<>(normalizedRoles) : new ArrayList<>());
        }

        log.info("Updated mock user: {}", user.getUsername());
        return true;
    }

    @Override
    public boolean deleteUser(String userId) {
        if (users.containsKey(userId)) {
            String username = users.get(userId).getUsername();
            users.remove(userId);
            userRoles.remove(userId);
            userAttributes.remove(userId);

            // Remove from sites
            Set<String> siteIds = userSites.getOrDefault(userId, new HashSet<>());
            for (String siteId : siteIds) {
                Set<String> members = siteMembers.getOrDefault(siteId, new HashSet<>());
                members.remove(userId);
                siteMembers.put(siteId, members);
            }
            userSites.remove(userId);

            log.info("Deleted mock user: {}", username);
            return true;
        }
        return false;
    }

    @Override
    public List<String> getUserRoles(String userId) {
        return userRoles.getOrDefault(userId, new ArrayList<>());
    }

    @Override
    public Optional<String> getUserAttribute(String userId, String attributeName) {
        Map<String, List<String>> attrs = userAttributes.get(userId);
        if (attrs != null && attrs.containsKey(attributeName)) {
            List<String> values = attrs.get(attributeName);
            if (values != null && !values.isEmpty()) {
                return Optional.of(values.get(0));
            }
        }
        return Optional.empty();
    }

    @Override
    public List<UserRepresentation> getUsersByRole(String roleName) {
        List<UserRepresentation> result = new ArrayList<>();
        for (Map.Entry<String, List<String>> entry : userRoles.entrySet()) {
            if (entry.getValue().contains(roleName) ||
                    entry.getValue().contains(roleName.toUpperCase()) ||
                    entry.getValue().contains(roleName.toLowerCase())) {
                result.add(users.get(entry.getKey()));
            }
        }
        return result;
    }

    // Site (Group) related methods

    @Override
    public List<GroupRepresentation> getAllGroups() {
        return new ArrayList<>(sites.values());
    }

    @Override
    public Optional<GroupRepresentation> getGroupById(String id) {
        return Optional.ofNullable(sites.get(id));
    }

    @Override
    public Optional<GroupRepresentation> getGroupByName(String groupName) {
        return sites.values().stream()
                .filter(group -> group.getName().equals(groupName))
                .findFirst();
    }

    @Override
    public String setupNewKeycloakGroup(String name, String description, boolean privateSite) {
        String siteId = UUID.randomUUID().toString();

        GroupRepresentation group = new GroupRepresentation();
        group.setId(siteId);
        group.setName(name);

        // Set attributes for the description
        Map<String, List<String>> attributes = new HashMap<>();
        if (description != null && !description.isEmpty()) {
            attributes.put("description", Collections.singletonList(description));
            group.setAttributes(attributes);
        }

        sites.put(siteId, group);
        siteMembers.put(siteId, new HashSet<>());

        // Create the site admin role for this site
        createSiteAdminRole(name);

        log.info("Created mock site: {} with ID: {}", name, siteId);
        return siteId;
    }

    @Override
    public boolean updateGroup(String siteId, GroupRepresentation updatedGroup) {
        if (!sites.containsKey(siteId)) {
            return false;
        }

        GroupRepresentation existingGroup = sites.get(siteId);

        // Update only what is provided
        if (updatedGroup.getName() != null) {
            existingGroup.setName(updatedGroup.getName());
        }

        if (updatedGroup.getAttributes() != null) {
            existingGroup.setAttributes(updatedGroup.getAttributes());
        }

        sites.put(siteId, existingGroup);
        log.info("Updated mock site: {} with ID: {}", existingGroup.getName(), siteId);
        return true;
    }

    @Override
    public boolean deleteGroup(String siteId) {
        if (!sites.containsKey(siteId)) {
            return false;
        }

        // Remove site
        String siteName = sites.get(siteId).getName();
        sites.remove(siteId);

        // Remove all users from this site
        Set<String> members = siteMembers.getOrDefault(siteId, new HashSet<>());
        for (String userId : members) {
            Set<String> userSiteSet = userSites.getOrDefault(userId, new HashSet<>());
            userSiteSet.remove(siteId);
            userSites.put(userId, userSiteSet);

            // Remove the site admin role if the user had it
            String siteAdminRole = getSiteAdminRoleName(siteName);
            List<String> userRolesList = userRoles.getOrDefault(userId, new ArrayList<>());
            userRolesList.remove(siteAdminRole);
            userRoles.put(userId, userRolesList);
        }

        siteMembers.remove(siteId);

        log.info("Deleted mock site: {} with ID: {}", siteName, siteId);
        return true;
    }

    @Override
    public boolean isUserInGroup(String userId, String siteId) {
        Set<String> members = siteMembers.getOrDefault(siteId, new HashSet<>());
        return members.contains(userId);
    }

    @Override
    public boolean addUserToKeycloakGroup(String userId, String siteId) {
        // Check if site and user exist
        if (!sites.containsKey(siteId) || !users.containsKey(userId)) {
            return false;
        }

        // Add user to site
        Set<String> members = siteMembers.getOrDefault(siteId, new HashSet<>());
        members.add(userId);
        siteMembers.put(siteId, members);

        // Add site to user
        Set<String> userSiteSet = userSites.getOrDefault(userId, new HashSet<>());
        userSiteSet.add(siteId);
        userSites.put(userId, userSiteSet);

        log.info("Added user {} to site {}", userId, siteId);
        return true;
    }

    @Override
    public String getSiteAdminRoleName(String siteName) {
        return siteName.toLowerCase().replace(' ', '_') + "_site_admin";
    }

    @Override
    public boolean createSiteAdminRole(String siteName) {
        // In mock implementation, we just log it
        log.info("Created site admin role: {}", getSiteAdminRoleName(siteName));
        return true;
    }

    @Override
    public boolean assignSiteAdminRole(String userId, String siteName) {
        // Get site ID from name
        Optional<GroupRepresentation> siteOpt = getGroupByName(siteName);
        if (!siteOpt.isPresent()) {
            log.warn("Site not found with name: {}", siteName);
            return false;
        }

        String siteId = siteOpt.get().getId();

        // First ensure the user is a member of the site
        if (!isUserInGroup(userId, siteId)) {
            addUserToKeycloakGroup(userId, siteId);
        }

        // Add the site-specific admin role to the user
        String siteAdminRole = getSiteAdminRoleName(siteName);
        List<String> userRolesList = userRoles.getOrDefault(userId, new ArrayList<>());
        if (!userRolesList.contains(siteAdminRole)) {
            userRolesList.add(siteAdminRole);
            userRoles.put(userId, userRolesList);
        }

        log.info("Assigned site admin role {} to user {}", siteAdminRole, userId);
        return true;
    }

    @Override
    public void removeSiteAdminRole(String userId, String siteId, String requesterUserId) {
        // Check permissions - requesterUserId should be a global admin or site admin
        if (!hasGlobalAdminRole(requesterUserId) && !isUserSiteAdmin(requesterUserId, siteId)) {
            log.warn("User {} doesn't have permission to remove site admin role", requesterUserId);
            throw new org.springframework.security.access.AccessDeniedException("Cannot remove site admin role");
        }

        // Get the site name
        String siteName = sites.get(siteId).getName();
        String siteAdminRole = getSiteAdminRoleName(siteName);

        // Remove the site admin role from the user
        List<String> userRolesList = userRoles.getOrDefault(userId, new ArrayList<>());
        userRolesList.remove(siteAdminRole);
        userRoles.put(userId, userRolesList);

        log.info("Removed site admin role {} from user {}", siteAdminRole, userId);
    }

    @Override
    public boolean isUserSiteAdmin(String userId, String siteId) {
        // Global admins are implicitly site admins
        if (hasGlobalAdminRole(userId)) {
            return true;
        }

        // Get the site name
        GroupRepresentation site = sites.get(siteId);
        if (site == null) {
            return false;
        }

        // Check if user has the site-specific admin role
        String siteAdminRole = getSiteAdminRoleName(site.getName());
        List<String> userRolesList = userRoles.getOrDefault(userId, new ArrayList<>());
        return userRolesList.contains(siteAdminRole);
    }

    @Override
    public List<String> getUserAdminGroups(String userId) {
        // For each site, check if user has the site admin role
        List<String> adminSites = new ArrayList<>();

        for (GroupRepresentation site : sites.values()) {
            String siteAdminRole = getSiteAdminRoleName(site.getName());
            List<String> userRolesList = userRoles.getOrDefault(userId, new ArrayList<>());

            if (userRolesList.contains(siteAdminRole)) {
                adminSites.add(site.getId());
            }
        }

        // Global admins can administer all sites
        if (hasGlobalAdminRole(userId)) {
            return new ArrayList<>(sites.keySet());
        }

        return adminSites;
    }

    @Override
    public List<String> getUserSites(String userId) {
        return new ArrayList<>(userSites.getOrDefault(userId, new HashSet<>()));
    }

    @Override
    public List<GroupRepresentation> getUserGroups(String userId) {
        Set<String> siteIds = userSites.getOrDefault(userId, new HashSet<>());
        return siteIds.stream()
                .map(sites::get)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public boolean hasGlobalAdminRole(String userId) {
        List<String> roles = getUserRoles(userId);
        return roles.contains("GLOBAL_ADMIN");
    }

    /**
     * In dev mode, assume that we're logged in as admin1 for consistent access
     */
    public String getCurrentUserKeycloakId() {
        // In development, return the ID of admin1
        Optional<UserRepresentation> adminUser = getUserByUsername("admin1");
        if (adminUser.isPresent()) {
            return adminUser.get().getId();
        }
        
        // If admin1 doesn't exist (shouldn't happen), return first user ID
        return users.values().stream()
            .findFirst()
            .map(UserRepresentation::getId)
            .orElse("mock-user-id");
    }

    @Override
    public List<UserRepresentation> getUsersInGroup(String siteId) {
        Set<String> members = siteMembers.getOrDefault(siteId, new HashSet<>());
        return members.stream()
                .map(users::get)
                .filter(Objects::nonNull)
                .collect(Collectors.toList());
    }

    @Override
    public boolean makeSiteAdmin(String userId, String siteId, String requesterUserId) {
        // Check permissions
        if (!hasGlobalAdminRole(requesterUserId) && !isUserSiteAdmin(requesterUserId, siteId)) {
            log.warn("User {} doesn't have permission to make site admin", requesterUserId);
            return false;
        }

        // Get the site name
        GroupRepresentation site = sites.get(siteId);
        if (site == null) {
            log.warn("Site not found with ID: {}", siteId);
            return false;
        }

        // Ensure user is in site
        if (!isUserInGroup(userId, siteId)) {
            addUserToKeycloakGroup(userId, siteId);
        }

        // Add the site-specific admin role to the user
        String siteAdminRole = getSiteAdminRoleName(site.getName());
        List<String> userRolesList = userRoles.getOrDefault(userId, new ArrayList<>());
        if (!userRolesList.contains(siteAdminRole)) {
            userRolesList.add(siteAdminRole);
            userRoles.put(userId, userRolesList);
        }

        log.info("User {} made admin of site {} with role {}", userId, siteId, siteAdminRole);
        return true;
    }

    @Override
    public void ensureRealmRoles(String... roleNames) {
        log.info("Ensuring mock realm roles: {}", Arrays.toString(roleNames));
        // No-op in mock implementation
    }
}