package it.polito.cloudresources.be.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;

import it.polito.cloudresources.be.config.datetime.DateTimeConfig;

/**
 * Event entity. Copied from reservation-be.
 * Added 'startNotifiedAt' and 'endNotifiedAt' fields to track processing status for start/end events.
 */
@Entity
@Table(name = "events")
@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class Event extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Size(max = 100)
    private String title;

    @Size(max = 500)
    private String description;

    @NotNull
    @Column(name = "start_time")
    private ZonedDateTime start;

    @NotNull
    @Column(name = "end_time")
    private ZonedDateTime end;

    @ManyToOne
    @JoinColumn(name = "resource_id", nullable = false)
    private Resource resource;

    @NotBlank
    @Column(name = "keycloak_id")
    private String keycloakId; // Keycloak user ID

    @Column(name = "custom_parameters", columnDefinition = "TEXT")
    private String customParameters; // JSON string storing custom parameter values

    // Field to mark when the start notification was sent
    @Column(name = "start_notified_at")
    private ZonedDateTime startNotifiedAt;

    // Field to mark when the end notification was sent
    @Column(name = "end_notified_at")
    private ZonedDateTime endNotifiedAt;

    @Column(name = "operating_system")
    private String operatingSystem;

    // --- NUOVI CAMPI AGGIUNTI PER METAL3 ---
    @Column(name = "image_url", columnDefinition = "TEXT")
    private String imageUrl;

    @Column(name = "checksum_url", columnDefinition = "TEXT")
    private String checksumUrl;

    @Column(name = "checksum_type", length = 20)
    private String checksumType;

    @Column(name = "deleted", nullable = false)
    private boolean deleted = false;
    // -----------------------------------------
    // ----------------------------------------

    /**
     * Pre-persist hook to ensure start and end dates have correct timezone.
     */
    @PrePersist
    @Override
    public void prePersist() {
        // Call the parent class method first
        super.prePersist();
        ensureCorrectTimezone();
    }

    /**
     * Pre-update hook to ensure start and end dates have correct timezone.
     */
    @PreUpdate
    @Override
    public void preUpdate() {
        // Call the parent class method first
        super.preUpdate();
        ensureCorrectTimezone();
    }

    private void ensureCorrectTimezone() {
        if (start != null) {
            start = start.withZoneSameInstant(DateTimeConfig.DEFAULT_ZONE_ID);
        }
        if (end != null) {
            end = end.withZoneSameInstant(DateTimeConfig.DEFAULT_ZONE_ID);
        }
    }

    // Avoid issues with Lombok and circular dependencies
    @Override
    public String toString() {
        return "Event{" +
                "id=" + id +
                ", title='" + title + '\'' +
                ", start=" + start +
                ", end=" + end +
                ", resourceId=" + (resource != null ? resource.getId() : null) +
                ", keycloakId='" + keycloakId + '\'' +
                ", deleted=" + deleted +  // <--- AGGIUNTO: Fondamentale per il debug ora
                ", startNotifiedAt=" + startNotifiedAt +
                ", endNotifiedAt=" + endNotifiedAt +
                ", operatingSystem='" + operatingSystem + '\'' +
                ", imageUrl='" + imageUrl + '\'' +
                ", checksumUrl='" + checksumUrl + '\'' +
                ", checksumType='" + checksumType + '\'' + // <--- AGGIUNTO: Utile per Metal3
                '}';
    }
}