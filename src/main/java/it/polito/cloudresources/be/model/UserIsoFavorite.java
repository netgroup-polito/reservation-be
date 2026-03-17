package it.polito.cloudresources.be.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "user_iso_favorites")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class UserIsoFavorite {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @Column(name = "user_id", nullable = false)
    private String userId; 

    @NotBlank
    private String alias; 

    @NotBlank
    @Column(name = "image_url", columnDefinition = "TEXT", nullable = false)
    private String imageUrl;

    @NotBlank
    @Column(name = "checksum_url", columnDefinition = "TEXT", nullable = false)
    private String checksumUrl;

    @Column(name = "created_at")
    private java.time.LocalDateTime createdAt;

    @PrePersist
    protected void onCreate() {
        createdAt = java.time.LocalDateTime.now();
    }
}

