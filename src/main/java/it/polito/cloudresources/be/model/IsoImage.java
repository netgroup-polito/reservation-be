package it.polito.cloudresources.be.model;

import jakarta.persistence.*;
import jakarta.validation.constraints.NotBlank;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

@Entity
@Table(name = "iso_images")
@Data
@NoArgsConstructor
@AllArgsConstructor
public class IsoImage {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @NotBlank
    @Column(unique = true)
    private String name;        // ID interno (es: "ubuntu")
    
    private String displayName; // Label per UI (es: "Ubuntu 22.04 LTS")

    // --- NUOVI CAMPI (Definizione Struttura Dati Reale) ---
    
    @Column(name = "image_url", columnDefinition = "TEXT")
    private String imageUrl;    // L'URL della ISO (qcow2)

    @Column(name = "checksum_url", columnDefinition = "TEXT")
    private String checksumUrl; // L'URL o la stringa dello SHA

    @Column(name = "checksum_type", length = 20)
    private String checksumType = "sha256"; // Default a SHA256
    
    @Column(name = "is_active")
    private Boolean isActive = true;
}