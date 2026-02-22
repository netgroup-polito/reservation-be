package it.polito.cloudresources.be.controller;

import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.security.SecurityRequirement;
import io.swagger.v3.oas.annotations.tags.Tag;

import it.polito.cloudresources.be.dto.users.CreateUserDTO;
import it.polito.cloudresources.be.dto.users.SshKeyDTO;
import it.polito.cloudresources.be.dto.users.UpdateProfileDTO;
import it.polito.cloudresources.be.dto.users.UpdateUserDTO;
import it.polito.cloudresources.be.dto.users.UserDTO;
import it.polito.cloudresources.be.service.KeycloakService;
import it.polito.cloudresources.be.service.SiteService;
import it.polito.cloudresources.be.service.SshKeyService;
import it.polito.cloudresources.be.service.UserService;
import it.polito.cloudresources.be.util.ControllerUtils;

import jakarta.persistence.EntityExistsException;
import jakarta.persistence.EntityNotFoundException;
import jakarta.validation.Valid;

import lombok.RequiredArgsConstructor;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

/**
 * REST API controller for managing users (fully integrated with Keycloak)
 */
@RestController
@RequestMapping("/users")
@RequiredArgsConstructor
@Tag(name = "Users", description = "API for managing users")
@SecurityRequirement(name = "bearer-auth")
public class UserController {

    private final UserService userService;
    private final SiteService siteService;
    private final KeycloakService keycloakService;
    private final SshKeyService sshKeyService;
    private final ControllerUtils utils;

    // ==========================================
    // BASIC USER MANAGEMENT
    // ==========================================

    @GetMapping
    @Operation(summary = "Get all users", description = "Retrieves all users with optional site filtering")
    public ResponseEntity<List<UserDTO>> getAllUsers(
            @RequestParam(required = false) String siteId,
            Authentication authentication) {

        try {
            String currentUserKeycloakId = utils.getCurrentUserKeycloakId(authentication);
            if (siteId != null) {
                return ResponseEntity.ok(siteService.getUsersInSite(siteId, currentUserKeycloakId));
            }
            return ResponseEntity.ok(userService.getAllUsers(currentUserKeycloakId));
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/{id}")
    @Operation(summary = "Get user by ID", description = "Retrieves a specific user by their ID (Admin only)")
    public ResponseEntity<UserDTO> getUserById(@PathVariable String id, Authentication authentication) {
        try {
            String currentKeycloakUserId = utils.getCurrentUserKeycloakId(authentication);
            return ResponseEntity.ok(userService.getUserById(id, currentKeycloakUserId));
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @GetMapping("/me")
    @Operation(summary = "Get current user", description = "Retrieves the profile of the currently authenticated user")
    public ResponseEntity<UserDTO> getCurrentUser(Authentication authentication) {
        try {
            String keycloakId = utils.getCurrentUserKeycloakId(authentication);
            return ResponseEntity.ok(userService.getUserById(keycloakId, keycloakId));
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (EntityNotFoundException e) {
            return ResponseEntity.status(HttpStatus.NOT_FOUND).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping
    @Operation(summary = "Create user", description = "Creates a new user (Admin only)")
    public ResponseEntity<Object> createUser(@Valid @RequestBody CreateUserDTO createUserDTO, Authentication authentication) {
        try {
            String currentKeycloakUserId = utils.getCurrentUserKeycloakId(authentication);
            UserDTO createdUser = userService.createUser(createUserDTO, createUserDTO.getPassword(), currentKeycloakUserId);
            return ResponseEntity.status(HttpStatus.CREATED).body(createdUser);
        } catch (AccessDeniedException e) {
            return utils.createErrorResponse(HttpStatus.FORBIDDEN, "User does not have privileges");
        } catch (IllegalArgumentException e) {
            return utils.createErrorResponse(HttpStatus.BAD_REQUEST, "Invalid input: " + e.getMessage());
        } catch (EntityExistsException e) {
            return utils.createErrorResponse(HttpStatus.CONFLICT, "Username or Email already used");
        } catch (Exception e) {
            return utils.createErrorResponse(HttpStatus.BAD_REQUEST, "Failed to create user: " + e.getMessage());
        }
    }

    @PutMapping("/{id}")
    @Operation(summary = "Update user", description = "Updates an existing user (Admin only)")
    public ResponseEntity<Object> updateUser(
            @PathVariable String id,
            @Valid @RequestBody UpdateUserDTO updateUserDTO,
            Authentication authentication) {
        try {
            String currentKeycloakUserId = utils.getCurrentUserKeycloakId(authentication);
            UserDTO updatedUser = userService.updateUser(id, updateUserDTO, currentKeycloakUserId);
            return ResponseEntity.ok(updatedUser);
        } catch (AccessDeniedException e) {
            return utils.createErrorResponse(HttpStatus.FORBIDDEN, e.getMessage());
        } catch (Exception e) {
            return utils.createErrorResponse(HttpStatus.BAD_REQUEST, "Failed to update user: " + e.getMessage());
        }
    }

    @PutMapping("/me")
    @Operation(summary = "Update profile", description = "Updates the current user's profile")
    public ResponseEntity<Object> updateProfile(
            @Valid @RequestBody UpdateProfileDTO updateProfileDTO,
            Authentication authentication) {
        try {
            String keycloakId = utils.getCurrentUserKeycloakId(authentication);
            UserDTO updatedUser = userService.updateProfile(keycloakId, updateProfileDTO);
            return ResponseEntity.ok(updatedUser);
        } catch (IllegalArgumentException e) {
            return utils.createErrorResponse(HttpStatus.BAD_REQUEST, e.getMessage());
        } catch (EntityNotFoundException e) {
            return utils.createErrorResponse(HttpStatus.NOT_FOUND, "User not found");
        } catch (Exception e) {
            return utils.createErrorResponse(HttpStatus.BAD_REQUEST, "Failed to update profile: " + e.getMessage());
        }
    }

    @DeleteMapping("/{id}")
    @Operation(summary = "Delete user", description = "Deletes an existing user (Admin only)")
    public ResponseEntity<Object> deleteUser(@PathVariable String id, Authentication authentication) {
        try {
            String currentKeycloakUserId = utils.getCurrentUserKeycloakId(authentication);
            userService.deleteUser(id, currentKeycloakUserId);
            return utils.createSuccessResponse("User deleted successfully");
        } catch (AccessDeniedException e) {
            return utils.createErrorResponse(HttpStatus.FORBIDDEN, e.getMessage());
        } catch (EntityNotFoundException e) {
            return utils.createErrorResponse(HttpStatus.NOT_FOUND, e.getMessage());
        } catch (Exception e) {
            return utils.createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to delete user: " + e.getMessage());
        }
    }

    @GetMapping("/by-role/{role}")
    @Operation(summary = "Get users by role", description = "Retrieves users with a specific role (Admin only)")
    public ResponseEntity<List<UserDTO>> getUsersByRole(@PathVariable String role, Authentication authentication) {
        try {
            String currentKeycloakUserId = utils.getCurrentUserKeycloakId(authentication);
            List<UserDTO> users = userService.getUsersByRole(role.toLowerCase(), currentKeycloakUserId);
            return ResponseEntity.ok(users);
        } catch (AccessDeniedException e) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    // ==========================================
    // SSH WALLET ENDPOINTS (Multi-Key)
    // ==========================================

    @GetMapping("/me/ssh-keys")
    @Operation(summary = "Get Key Wallet", description = "Retrieves all SSH keys in the user's wallet")
    public ResponseEntity<List<SshKeyDTO>> getWalletKeys(Authentication authentication) {
        try {
            String keycloakId = utils.getCurrentUserKeycloakId(authentication);
            return ResponseEntity.ok(sshKeyService.getAllUserKeys(keycloakId));
        } catch (Exception e) {
            return ResponseEntity.status(HttpStatus.INTERNAL_SERVER_ERROR).build();
        }
    }

    @PostMapping("/me/ssh-keys")
    @Operation(summary = "Add Key to Wallet", description = "Adds a new SSH key to the wallet")
    public ResponseEntity<SshKeyDTO> addWalletKey(
            @Valid @RequestBody SshKeyDTO keyDTO,
            Authentication authentication) {

        String keycloakId = utils.getCurrentUserKeycloakId(authentication);
        SshKeyDTO created = sshKeyService.addWalletKey(keycloakId, keyDTO, keycloakId);
        return ResponseEntity.status(HttpStatus.CREATED).body(created);
    }

    @DeleteMapping("/me/ssh-keys/{id}")
    @Operation(summary = "Delete Key from Wallet", description = "Removes a specific key from the wallet by ID")
    public ResponseEntity<Object> deleteWalletKey(
            @PathVariable Long id,
            Authentication authentication) {

        try {
            String keycloakId = utils.getCurrentUserKeycloakId(authentication);
            boolean deleted = sshKeyService.deleteWalletKey(id, keycloakId);
            if (!deleted) {
                return utils.createErrorResponse(HttpStatus.NOT_FOUND, "Key not found or access denied");
            }
            return utils.createSuccessResponse("Key deleted successfully");
        } catch (Exception e) {
            return utils.createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Failed to delete key: " + e.getMessage());
        }
    }

    @PutMapping("/me/ssh-keys/{id}")
    @Operation(summary = "Update Key in Wallet", description = "Updates a specific SSH key in the wallet by ID")
    public ResponseEntity<SshKeyDTO> updateWalletKey(
            @PathVariable Long id,
            @Valid @RequestBody SshKeyDTO keyDTO,
            Authentication authentication) {

        String keycloakId = utils.getCurrentUserKeycloakId(authentication);
        SshKeyDTO updated = sshKeyService.updateSshKey(id, keycloakId, keyDTO);
        return ResponseEntity.ok(updated);
    }

    // ==========================================
    // ROLE MANAGEMENT (Custom ISO)
    // ==========================================

    @PutMapping("/{id}/roles/custom-iso-uploader")
    @Operation(summary = "Assign Custom ISO Role", description = "Grants the user permission to use custom ISO URLs (Admin only)")
    public ResponseEntity<Object> assignCustomIsoRole(@PathVariable String id, Authentication authentication) {
        try {
            String adminId = utils.getCurrentUserKeycloakId(authentication);
            if (!keycloakService.hasGlobalAdminRole(adminId)) {
                return utils.createErrorResponse(HttpStatus.FORBIDDEN, "Only global admins can manage user roles");
            }
            boolean success = keycloakService.assignRoleToUser(id, "custom-iso-uploader");
            if (success) {
                return utils.createSuccessResponse("Role 'custom-iso-uploader' assigned successfully");
            } else {
                return utils.createErrorResponse(HttpStatus.BAD_REQUEST, "Failed to assign role");
            }
        } catch (Exception e) {
            return utils.createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Error: " + e.getMessage());
        }
    }

    @DeleteMapping("/{id}/roles/custom-iso-uploader")
    @Operation(summary = "Remove Custom ISO Role", description = "Revokes the user permission to use custom ISO URLs (Admin only)")
    public ResponseEntity<Object> removeCustomIsoRole(@PathVariable String id, Authentication authentication) {
        try {
            String adminId = utils.getCurrentUserKeycloakId(authentication);
            if (!keycloakService.hasGlobalAdminRole(adminId)) {
                return utils.createErrorResponse(HttpStatus.FORBIDDEN, "Only global admins can manage user roles");
            }
            boolean success = keycloakService.removeRoleFromUser(id, "custom-iso-uploader");
            if (success) {
                return utils.createSuccessResponse("Role 'custom-iso-uploader' removed successfully");
            } else {
                return utils.createErrorResponse(HttpStatus.BAD_REQUEST, "Failed to remove role");
            }
        } catch (Exception e) {
            return utils.createErrorResponse(HttpStatus.INTERNAL_SERVER_ERROR, "Error: " + e.getMessage());
        }
    }
}