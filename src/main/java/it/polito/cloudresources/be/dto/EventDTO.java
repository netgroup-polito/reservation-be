package it.polito.cloudresources.be.dto;

import com.fasterxml.jackson.annotation.JsonFormat;

import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import jakarta.validation.constraints.Size;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;

/**
 * DTO for Event data transfer.
 * Updated to support Metal3 provisioning logic (Standard ISO, Favorites, Custom URLs).
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class EventDTO {
    private Long id;

    @NotBlank(message = "Title is required")
    @Size(max = 100, message = "Title cannot exceed 100 characters")
    private String title;

    @Size(max = 500, message = "Description cannot exceed 500 characters")
    private String description;

    @NotNull(message = "Start date is required")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX")
    private ZonedDateTime start;

    @NotNull(message = "End date is required")
    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX")
    private ZonedDateTime end;

    @NotNull(message = "Resource is required")
    private Long resourceId;

    private String userId;

    // Campo Legacy/Visualizzazione: usato come etichetta (es. "Ubuntu 22.04")
    private String operatingSystem;

    @Size(max = 1000, message = "Custom parameters cannot exceed 1000 characters")
    private String customParameters; // JSON string storing custom parameter values

    // Additional fields for the frontend
    private String userName;
    private String resourceName;

    // --- NUOVI CAMPI PER LA LOGICA DI PROVISIONING (Metal3) ---

    // Discriminatore: "STANDARD", "FAVORITE", "CUSTOM" (o null)
    private String osSelectionType;

    // SCENARIO 1: ISO GESTITA (STANDARD) -> ID tabella iso_images
    private Long selectedIsoId;

    // SCENARIO 2: ISO PREFERITA (FAVORITE) -> ID tabella user_iso_favorites
    private Long selectedFavoriteId;

    // SCENARIO 3: URL CUSTOM (CUSTOM) -> Stringhe crude
    private String customImageUrl;
    private String customChecksumUrl;
    private String customChecksumType; // es. "sha256"

    // FLAGS PER SALVATAGGIO PREFERITI (Solo se osSelectionType == CUSTOM)
    private Boolean saveAsFavorite; 
    private String favoriteAlias;   
}