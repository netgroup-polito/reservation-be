package it.polito.cloudresources.be.dto.users;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.Set;

/**
 * DTO for user creation
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(builderMethodName = "builder")
public class CreateUserDTO {
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

    @NotBlank(message = "Password is required")
    @ToString.Exclude
    private String password;

    private String avatar;

    // RIMOSSO: private String sshPublicKey; -> Le chiavi si aggiungono dopo tramite Wallet

    @NotNull(message = "Roles are required")
    private Set<String> roles;

    /**
     * Fluent builder for CreateUserDTO
     */
    public static class CreateUserDTOBuilder {
        // Lombok will generate the builder methods
    }
}