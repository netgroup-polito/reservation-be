package it.polito.cloudresources.be.service;

import it.polito.cloudresources.be.dto.IsoImageDTO;
import it.polito.cloudresources.be.model.IsoImage;
import it.polito.cloudresources.be.repository.IsoImageRepository;
import it.polito.cloudresources.be.util.UrlValidator; // Import necessario
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.util.List;
import java.util.stream.Collectors;

@Service
@RequiredArgsConstructor
public class IsoImageService {

    private final IsoImageRepository isoImageRepository;

    public List<IsoImageDTO> getAllIsoImages() {
        return isoImageRepository.findAll().stream()
                .map(this::toDTO)
                .collect(Collectors.toList());
    }

    /**
     * Ritorna solo le immagini ATTIVE e CONFIGURATE (con URL valida).
     * Questo impedisce agli utenti di selezionare immagini "vuote" che l'admin non ha ancora finito di configurare.
     */
    public List<IsoImageDTO> getActiveIsoImages() {
        return isoImageRepository.findAllByIsActiveTrueOrderByDisplayNameAsc().stream()
                .filter(img -> img.getImageUrl() != null && !img.getImageUrl().isBlank()) // FILTRO DI SICUREZZA
                .map(this::toDTO)
                .collect(Collectors.toList());
    }

    @Transactional
    public IsoImageDTO saveIsoImage(IsoImageDTO dto) {
        // --- VALIDAZIONE SICUREZZA URL (NUOVO) ---
        // Se l'admin ha inserito una URL, verifichiamo che esista davvero
        if (dto.getImageUrl() != null && !dto.getImageUrl().isBlank()) {
            try {
                UrlValidator.checkUrlReachable(dto.getImageUrl());
            } catch (Exception e) {
                // Rilanciamo come IllegalArgumentException che Spring trasforma in 400 Bad Request
                throw new IllegalArgumentException("Image URL non valida o irraggiungibile: " + e.getMessage());
            }
        }

        if (dto.getChecksumUrl() != null && !dto.getChecksumUrl().isBlank()) {
            try {
                UrlValidator.checkUrlReachable(dto.getChecksumUrl());
            } catch (Exception e) {
                throw new IllegalArgumentException("Checksum URL non valida o irraggiungibile: " + e.getMessage());
            }
        }
        // -----------------------------------------

        IsoImage iso;
        
        // Se c'è un ID, è un aggiornamento
        if (dto.getId() != null) {
            iso = isoImageRepository.findById(dto.getId())
                    .orElse(new IsoImage());
        } else {
            // Check duplicati sul nome interno (es. "ubuntu") solo in creazione
            // Questo evita crash brutti del DB se l'admin riusa lo stesso ID
            if (isoImageRepository.findByName(dto.getName()).isPresent()) {
                throw new IllegalArgumentException("Esiste già una ISO con questo ID interno: " + dto.getName());
            }
            iso = new IsoImage();
        }

        // Mapping manuale
        iso.setName(dto.getName());
        iso.setDisplayName(dto.getDisplayName());
        iso.setImageUrl(dto.getImageUrl());
        iso.setChecksumUrl(dto.getChecksumUrl());
        iso.setChecksumType(dto.getChecksumType() != null ? dto.getChecksumType() : "sha256");
        iso.setIsActive(dto.isActive());

        return toDTO(isoImageRepository.save(iso));
    }

    @Transactional
    public void deleteIsoImage(Long id) {
        isoImageRepository.deleteById(id);
    }

    private IsoImageDTO toDTO(IsoImage entity) {
        return IsoImageDTO.builder()
                .id(entity.getId())
                .name(entity.getName())
                .displayName(entity.getDisplayName())
                .imageUrl(entity.getImageUrl())
                .checksumUrl(entity.getChecksumUrl())
                .checksumType(entity.getChecksumType())
                .active(entity.getIsActive())
                .build();
    }
}