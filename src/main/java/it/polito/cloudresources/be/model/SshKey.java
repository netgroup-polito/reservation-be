package it.polito.cloudresources.be.model;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.Id;
import jakarta.persistence.Table;
import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * Entity for storing SSH keys in the database
 */
@Entity
@Table(name = "ssh_keys")
@Data
@NoArgsConstructor
@AllArgsConstructor
@Builder
public class SshKey {
    
    @Id
    @GeneratedValue
    private Long id;
    
    // REMOVED "unique = true" to allow 1:N relationship (multiple keys per user)
    @Column(name = "user_id", nullable = false)
    private String userId;
    
    // NEW FIELD: Label to identify the key (e.g., "Laptop", "Default")
    @Column(name = "label")
    private String label;

    @Column(name = "ssh_key", nullable = false, length = 4000)
    private String sshKey;
    
    @Column(name = "created_at", nullable = false)
    private java.time.LocalDateTime createdAt;
    
    @Column(name = "updated_at", nullable = false)
    private java.time.LocalDateTime updatedAt;
    
    @Column(name = "created_by", nullable = false)
    private String createdBy;
    
    @Column(name = "updated_by", nullable = false)
    private String updatedBy;

    // Helper to ensure backward compatibility (if label is null -> "Default")
    @jakarta.persistence.PrePersist
    @jakarta.persistence.PreUpdate
    public void ensureLabel() {
        if (this.label == null || this.label.trim().isEmpty()) {
            this.label = "Default";
        }
    }
}