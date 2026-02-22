package it.polito.cloudresources.be.dto.users;

import jakarta.validation.constraints.Email;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;
import lombok.ToString;

/**
 * DTO for users to update their own profile information
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(builderMethodName = "builder")
public class UpdateProfileDTO {
    @Size(max = 50, message = "First name cannot exceed 50 characters")
    private String firstName;

    @Size(max = 50, message = "Last name cannot exceed 50 characters")
    private String lastName;

    @Email(message = "Invalid email format")
    private String email;

    private String avatar;

    @ToString.Exclude
    private String password;

    // RIMOSSO: private String sshPublicKey; -> Gestito ora tramite Wallet (SshKeyService)

    /**
     * Fluent builder for UpdateProfileDTO
     */
    public static class UpdateProfileDTOBuilder {
        // Lombok will generate the builder methods
    }
}