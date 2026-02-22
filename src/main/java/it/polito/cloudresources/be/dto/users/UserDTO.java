package it.polito.cloudresources.be.dto.users;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.util.HashSet;
import java.util.Set;

/**
 * DTO for User data transfer, based entirely on Keycloak
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(builderMethodName = "builder")
public class UserDTO {
    private String id;

    @NotBlank(message = "Username is required")
    @Size(max = 50, message = "Username cannot exceed 50 characters")
    private String username;

    @NotBlank(message = "First name is required")
    @Size(max = 50, message = "First name cannot exceed 50 characters")
    private String firstName;

    @NotBlank(message = "Last name is required")
    @Size(max = 50, message = "Last name cannot exceed 50 characters")
    private String lastName;

    @NotBlank(message = "Email is required")
    @Email(message = "Invalid email format")
    private String email;

    private String avatar;

    

    private Set<String> roles;

    @NotBlank(message = "A site must be provided")
    private String siteId;

    /**
     * Returns the user's full name by concatenating first and last name
     */
    public String getFullName() {
        return firstName + " " + lastName;
    }

    /**
     * Custom builder with additional utility methods
     */
    public static class UserDTOBuilder {
        /**
         * Generates an avatar from name initials if not already set
         * @return the current builder for method chaining
         */
        public UserDTOBuilder withGeneratedAvatarIfEmpty() {
            if (this.avatar == null || this.avatar.isEmpty()) {
                StringBuilder generatedAvatar = new StringBuilder();

                if (this.firstName != null && !this.firstName.isEmpty()) {
                    generatedAvatar.append(this.firstName.substring(0, 1).toUpperCase());
                }

                if (this.lastName != null && !this.lastName.isEmpty()) {
                    generatedAvatar.append(this.lastName.substring(0, 1).toUpperCase());
                }

                if (generatedAvatar.length() > 0) {
                    this.avatar = generatedAvatar.toString();
                }
            }
            return this;
        }

        /**
         * Adds a single role to the roles set
         * @param role the role to add
         * @return the current builder for method chaining
         */
        public UserDTOBuilder withRole(String role) {
            if (role != null && !role.trim().isEmpty()) {
                if (this.roles == null) {
                    this.roles = new HashSet<>();
                }
                this.roles.add(role);
            }
            return this;
        }

        /**
         * Converts all roles to uppercase for consistency
         * @return the current builder for method chaining
         */
        public UserDTOBuilder withUppercaseRoles() {
            if (this.roles != null && !this.roles.isEmpty()) {
                Set<String> uppercaseRoles = new HashSet<>();
                for (String role : this.roles) {
                    uppercaseRoles.add(role.toUpperCase());
                }
                this.roles = uppercaseRoles;
            }
            return this;
        }

        /**
         * Normalizes the email address (converts to lowercase and trims)
         * @return the current builder for method chaining
         */
        public UserDTOBuilder withNormalizedEmail() {
            if (this.email != null) {
                this.email = this.email.toLowerCase().trim();
            }
            return this;
        }
    }

    /**
     * Creates a builder pre-populated with an existing user's data
     * @param user the user to copy data from
     * @return a builder initialized with the existing user's data
     */
    public static UserDTOBuilder from(UserDTO user) {
        return builder()
                .id(user.getId())
                .username(user.getUsername())
                .firstName(user.getFirstName())
                .lastName(user.getLastName())
                .email(user.getEmail())
                .avatar(user.getAvatar())
                // RIMOSSO: .sshPublicKey(user.getSshPublicKey())
                .roles(user.getRoles() != null ? new HashSet<>(user.getRoles()) : null)
                .siteId(user.getSiteId());
    }
}