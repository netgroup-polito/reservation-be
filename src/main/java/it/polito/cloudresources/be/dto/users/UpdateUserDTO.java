package it.polito.cloudresources.be.dto.users;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

import java.util.Set;

/**
 * DTO for updating user information (admin use)
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(builderMethodName = "builder")
public class UpdateUserDTO {
    @Size(max = 50, message = "Username cannot exceed 50 characters")
    private String username;

    @Size(max = 50, message = "First name cannot exceed 50 characters")
    private String firstName;

    @Size(max = 50, message = "Last name cannot exceed 50 characters")
    private String lastName;

    @Email(message = "Invalid email format")
    private String email;

    @ToString.Exclude
    private String password;

    private String avatar;

    // RIMOSSO: private String sshPublicKey; -> Gestione tramite Wallet

    private Set<String> roles;

    /**
     * Fluent builder for UpdateUserDTO
     */
    public static class UpdateUserDTOBuilder {
        // Lombok will generate the builder methods
    }
}