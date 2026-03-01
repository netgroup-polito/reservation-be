package it.polito.cloudresources.be.dto.users;

import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for SSH public key operations
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder(builderMethodName = "builder")
public class SshKeyDTO {
    
    // The database ID of the key (useful for deletion)
    private Long id;

    // The friendly name of the key (e.g., "Work Laptop", "Default")
    private String label;

    @NotNull(message = "SSH public key is required")
    private String sshPublicKey;

    /**
     * Fluent builder for SshKeyDTO
     */
    public static class SshKeyDTOBuilder {
        // Lombok will generate the builder methods
    }
}