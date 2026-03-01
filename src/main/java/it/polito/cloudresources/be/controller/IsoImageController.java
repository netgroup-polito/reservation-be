package it.polito.cloudresources.be.controller;

import it.polito.cloudresources.be.dto.IsoImageDTO;
import it.polito.cloudresources.be.model.UserIsoFavorite; // Import nuovo
import it.polito.cloudresources.be.repository.UserIsoFavoriteRepository; // Import nuovo
import it.polito.cloudresources.be.service.IsoImageService;
import it.polito.cloudresources.be.service.KeycloakService;
import it.polito.cloudresources.be.util.ControllerUtils;
import jakarta.validation.Valid;
import lombok.RequiredArgsConstructor;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.Authentication;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/iso-images")
@RequiredArgsConstructor
public class IsoImageController {

    private final IsoImageService isoImageService;
    private final KeycloakService keycloakService;
    private final UserIsoFavoriteRepository userIsoFavoriteRepository; // <--- NUOVO REPOSITORY
    private final ControllerUtils utils;

    @GetMapping
    public ResponseEntity<List<IsoImageDTO>> getActiveIso() {
        return ResponseEntity.ok(isoImageService.getActiveIsoImages());
    }

    // --- NUOVO ENDPOINT PER I PREFERITI ---
    @GetMapping("/favorites")
    public ResponseEntity<List<UserIsoFavorite>> getUserFavorites(@RequestParam String userId, Authentication auth) {
        String currentUserId = utils.getCurrentUserKeycloakId(auth);
        
        // Security Check: Un utente può leggere solo i suoi preferiti, a meno che non sia admin
        if (!currentUserId.equals(userId) && !keycloakService.hasGlobalAdminRole(currentUserId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        
        return ResponseEntity.ok(userIsoFavoriteRepository.findAllByUserId(userId));
    }

    // --- NUOVO ENDPOINT DELETE PER I PREFERITI ---
    @DeleteMapping("/favorites/{id}")
    public ResponseEntity<Void> deleteUserFavorite(@PathVariable Long id, Authentication auth) {
        String currentUserId = utils.getCurrentUserKeycloakId(auth);

        // 1. Cerchiamo il preferito nel DB
        return userIsoFavoriteRepository.findById(id)
            .map(favorite -> {
                // 2. Controllo di Sicurezza: Il preferito appartiene a chi sta chiamando?
                // (O se è un admin globale, può cancellare tutto)
                if (!favorite.getUserId().equals(currentUserId) && !keycloakService.hasGlobalAdminRole(currentUserId)) {
                    return ResponseEntity.status(HttpStatus.FORBIDDEN).<Void>build();
                }
                
                // 3. Se è mio, lo cancello
                userIsoFavoriteRepository.delete(favorite);
                return ResponseEntity.noContent().<Void>build();
            })
            .orElse(ResponseEntity.notFound().build());
    }
    // ---------------------------------------------
    // --------------------------------------

    @GetMapping("/admin")
    public ResponseEntity<List<IsoImageDTO>> getAllIsoForAdmin(Authentication auth) {
        String userId = utils.getCurrentUserKeycloakId(auth);
        if (!keycloakService.hasGlobalAdminRole(userId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.ok(isoImageService.getAllIsoImages());
    }

    @PostMapping
    public ResponseEntity<IsoImageDTO> saveIso(@Valid @RequestBody IsoImageDTO dto, Authentication auth) {
        String userId = utils.getCurrentUserKeycloakId(auth);
        if (!keycloakService.hasGlobalAdminRole(userId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        return ResponseEntity.status(HttpStatus.CREATED).body(isoImageService.saveIsoImage(dto));
    }

    @DeleteMapping("/{id}")
    public ResponseEntity<Void> deleteIso(@PathVariable Long id, Authentication auth) {
        String userId = utils.getCurrentUserKeycloakId(auth);
        if (!keycloakService.hasGlobalAdminRole(userId)) {
            return ResponseEntity.status(HttpStatus.FORBIDDEN).build();
        }
        isoImageService.deleteIsoImage(id);
        return ResponseEntity.noContent().build();
    }
}