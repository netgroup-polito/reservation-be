package it.polito.cloudresources.be.service;

import it.polito.cloudresources.be.dto.EventDTO;
import it.polito.cloudresources.be.dto.users.CreateUserDTO;
import it.polito.cloudresources.be.dto.users.UpdateProfileDTO;
import it.polito.cloudresources.be.dto.users.UpdateUserDTO;
import it.polito.cloudresources.be.dto.users.UserDTO;
import it.polito.cloudresources.be.mapper.UserMapper;
import it.polito.cloudresources.be.model.AuditLog;
import jakarta.persistence.EntityExistsException;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.keycloak.representations.idm.GroupRepresentation;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.*;

/**
 * Service for user operations, using Keycloak as the source of truth
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class UserService {

    private final KeycloakService keycloakService;
    private final AuditLogService auditLogService;
    private final EventService eventService;
    private final UserMapper userMapper;

    // RIMOSSI: SshKeyService e SshKeyValidator non servono più qui.
    // La gestione delle chiavi è delegata interamente al Wallet.

    /**
     * Get all users
     * @return A list of all users
     */
    public List<UserDTO> getAllUsers(String userId) {

        if (keycloakService.hasGlobalAdminRole(userId)) {
            return userMapper.toDto(keycloakService.getUsers());
        }

        List<String> groupsName = keycloakService.getUserAdminGroups(userId);
        if (groupsName.isEmpty()) {
            throw new AccessDeniedException("The user is not an administrator of any site");
        }

        List<UserDTO> usersToReturn = new ArrayList<>(List.of());
        for(String groupName : groupsName) {
            Optional<GroupRepresentation> group = keycloakService.getGroupByName(groupName);
            if(group.isPresent()) {
                List<UserRepresentation> users = keycloakService.getUsersInGroup(group.get().getId());
                usersToReturn.addAll(userMapper.toDto(users));
            }
        }

        return usersToReturn;
    }

    /**
     * Get user by ID (Keycloak ID)
     * @param id The Keycloak user ID
     * @return Optional containing the user if found
     */
    public UserDTO getUserById(String id, String requesterUserId) {
        if(!keycloakService.hasGlobalAdminRole(requesterUserId) &&
           !keycloakService.getUserAdminGroups(requesterUserId).isEmpty() &&
           !(Objects.equals(id, requesterUserId))) {
            throw new AccessDeniedException("The user is neither a global admin nor a site admin and the requested user isn't the user itself");
        }

        Optional<UserRepresentation> userRepresentation = keycloakService.getUserById(id);

        if(!userRepresentation.isPresent()) {
            throw new EntityNotFoundException("User not found");
        }

        // RIMOSSO: userDto.setSshPublicKey(...) -> Le chiavi non sono più nel DTO utente
        return userMapper.toDto(userRepresentation.get());
    }

    /**
     * Get user by email
     * @param email The email to search for
     * @return Optional containing the user if found
     */
    public Optional<UserDTO> getUserByEmail(String email) {
        return keycloakService.getUserByEmail(email)
                .map(userMapper::toDto);
    }

    /**
     * Get user by username
     * @param username The username to search for
     * @return Optional containing the user if found
     */
    public Optional<UserDTO> getUserByUsername(String username) {
        return keycloakService.getUserByUsername(username)
                .map(userMapper::toDto);
    }

    /**
     * Create new user
     * @param createUserDTO The user data transfer object containing the information for the new user
     * @param password The password for the new user
     * @return The created user
     */
    public UserDTO createUser(CreateUserDTO createUserDTO, String password, String requesterUserId) {

        if(keycloakService.getUserAdminGroups(requesterUserId).isEmpty() &&
                !keycloakService.hasGlobalAdminRole(requesterUserId)) {
            throw new AccessDeniedException("User can't create new users");
        }
        // Check if username already exists
        if (getUserByUsername(createUserDTO.getUsername()).isPresent()) {
            throw new EntityExistsException("Username already exists");
        }

        // Check if email already exists
        if (getUserByEmail(createUserDTO.getEmail()).isPresent()) {
            throw new EntityExistsException("Email already exists");
        }

        // Build the user DTO using UserDTO's built-in builder
        UserDTO userDTO = UserDTO.builder()
                .username(createUserDTO.getUsername())
                .email(createUserDTO.getEmail())
                .firstName(createUserDTO.getFirstName())
                .lastName(createUserDTO.getLastName())
                .avatar(createUserDTO.getAvatar())
                // RIMOSSO: .sshPublicKey(...) -> Non si salva più in creazione
                .roles(createUserDTO.getRoles())
                .withGeneratedAvatarIfEmpty()
                .withNormalizedEmail()
                .withUppercaseRoles()
                .build();

        // Create user in Keycloak
        String userId = keycloakService.createUser(userDTO, password);

        if (userId == null) {
            throw new RuntimeException("Failed to create user in Keycloak");
        }

        auditLogService.logCrudAction(AuditLog.LogType.ADMIN,
                AuditLog.LogAction.CREATE,
                new AuditLog.LogEntity("USER", userId),
                ""); //FIXME: Log Admin user in details parameter

        // Retrieve and return the newly created user
        return keycloakService.getUserById(userId)
                .map(userMapper::toDto)
                .orElseThrow(() -> new RuntimeException("User created but could not be retrieved"));
    }

    /**
     * Update existing user with optional password update
     * @param id The Keycloak user ID
     * @param updateUserDTO The user data to update
     * @param requesterUserId The Keycloak user ID of the requester
     * @return The updated user
     */
    public UserDTO updateUser(String id, UpdateUserDTO updateUserDTO, String requesterUserId) {

        if (!Objects.equals(id, requesterUserId) && 
            !keycloakService.hasGlobalAdminRole(requesterUserId) && 
            keycloakService.getUserAdminGroups(requesterUserId).isEmpty()) {
            throw new AccessDeniedException("User does not have enough privileges");
        }   
        
        Map<String, Object> attributes = new HashMap<>();

        // Only update fields that are present in the DTO
        if (updateUserDTO.getUsername() != null) {
            attributes.put("username", updateUserDTO.getUsername());
        }

        if (updateUserDTO.getEmail() != null) {
            attributes.put("email", updateUserDTO.getEmail());
        }

        if (updateUserDTO.getFirstName() != null) {
            attributes.put("firstName", updateUserDTO.getFirstName());
        }

        if (updateUserDTO.getLastName() != null) {
            attributes.put("lastName", updateUserDTO.getLastName());
        }

        if (updateUserDTO.getAvatar() != null) {
            attributes.put(KeycloakService.ATTR_AVATAR, updateUserDTO.getAvatar());
        }

        // RIMOSSO: Blocco if (updateUserDTO.getSshPublicKey() != null)

        if (updateUserDTO.getRoles() != null) {
            attributes.put("roles", new ArrayList<>(updateUserDTO.getRoles()));
        }

        // Add password to attributes if provided
        if (updateUserDTO.getPassword() != null && !updateUserDTO.getPassword().isEmpty()) {
            attributes.put("password", updateUserDTO.getPassword());
        }

        boolean updated = keycloakService.updateUser(id, attributes);
        if (!updated) {
            throw new RuntimeException("Failed to update user in Keycloak");
        }

        auditLogService.logCrudAction(AuditLog.LogType.ADMIN,
                AuditLog.LogAction.UPDATE,
                new AuditLog.LogEntity("USER", id),
                ""); //FIXME: Log Admin user

        // Retrieve and return the updated user
        return keycloakService.getUserById(id)
                .map(userMapper::toDto)
                .orElseThrow(() -> new RuntimeException("User updated but could not be retrieved"));
    }

    public UserDTO updateProfile(String id, UpdateProfileDTO profileDTO) {
        Map<String, Object> attributes = new HashMap<>();

        if (profileDTO.getEmail() != null) {
            attributes.put("email", profileDTO.getEmail());
        }

        if (profileDTO.getFirstName() != null) {
            attributes.put("firstName", profileDTO.getFirstName());
        }

        if (profileDTO.getLastName() != null) {
            attributes.put("lastName", profileDTO.getLastName());
        }

        if (profileDTO.getAvatar() != null) {
            attributes.put(KeycloakService.ATTR_AVATAR, profileDTO.getAvatar());
        }

        // RIMOSSO: Blocco if (profileDTO.getSshPublicKey() != null)

        if (profileDTO.getPassword() != null && !profileDTO.getPassword().isEmpty()) {
            attributes.put("password", profileDTO.getPassword());
        }

        boolean updated = keycloakService.updateUser(id, attributes);
        if (!updated) {
            throw new RuntimeException("Failed to update user in Keycloak");
        }

        auditLogService.logCrudAction(AuditLog.LogType.USER,
                AuditLog.LogAction.UPDATE,
                new AuditLog.LogEntity("USER", id),
                "User profile updated"); 

        // Retrieve and return the updated user
        return keycloakService.getUserById(id)
                .map(userMapper::toDto)
                .orElseThrow(() -> new RuntimeException("User updated but could not be retrieved"));
    }

    /**
     * Delete user
     * @param deleteKeycloakId The Keycloak user ID to delete
     * @param currentKeycloakId The Keycloak user ID that requested the deletion
     * @return true if deleted successfully, false otherwise
     */
    @Transactional
    public boolean deleteUser(String deleteKeycloakId, String currentKeycloakId) {
        // Get username for logging before deletion
        if (!keycloakService.hasGlobalAdminRole(currentKeycloakId) &&
                !keycloakService.getUserAdminGroups(currentKeycloakId).isEmpty()) {
            throw new AccessDeniedException("User does not have enough privileges");
        }
        Optional<UserRepresentation> user = keycloakService.getUserById(deleteKeycloakId);

        if(!user.isPresent()) {
            throw new EntityNotFoundException("User not found");
        }
        List<EventDTO> userEventsToDelete = eventService.getEventsByUserKeycloakId(deleteKeycloakId, currentKeycloakId);
        
        for(EventDTO event : userEventsToDelete) {
            eventService.deleteEvent(event.getId(), currentKeycloakId);
        }

        boolean deleted = keycloakService.deleteUser(deleteKeycloakId);

        if (deleted) {
            // Log the action
            auditLogService.logCrudAction(AuditLog.LogType.ADMIN,
                    AuditLog.LogAction.DELETE,
                    new AuditLog.LogEntity("USER", deleteKeycloakId),
                    "Admin " + currentKeycloakId + " deleted user: " + user.get());
        }

        return deleted;
    }

    /**
     * Get users by role
     * @param role The role to search for
     * @return List of users with the specified role
     */
    public List<UserDTO> getUsersByRole(String role, String requesterId) {
        if (!keycloakService.hasGlobalAdminRole(requesterId) &&
                !keycloakService.getUserAdminGroups(requesterId).isEmpty()) {
            throw new AccessDeniedException("User does not have enough privileges");
        }

        return userMapper.toDto(keycloakService.getUsersByRole(role));
    }

    // RIMOSSI METODI LEGACY SSH (getUserSshKey, deleteUserSshKey)
}