package it.polito.cloudresources.be.service;

import it.polito.cloudresources.be.dto.users.SshKeyDTO;
import it.polito.cloudresources.be.model.SshKey;
import it.polito.cloudresources.be.repository.SshKeyRepository;
import it.polito.cloudresources.be.util.SshKeyValidator;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import java.time.LocalDateTime;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service for managing SSH keys in the database
 * Updated to support Multiple Keys (Wallet)
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class SshKeyService {
    
    private final SshKeyRepository sshKeyRepository;
    private final SshKeyValidator sshKeyValidator;
    
    // ==========================================
    // NEW WALLET METHODS (Multi-Key Support)
    // ==========================================

    /**
     * Get ALL keys for a user
     */
    public List<SshKeyDTO> getAllUserKeys(String userId) {
        return sshKeyRepository.findAllByUserId(userId).stream()
                .map(this::toDto)
                .collect(Collectors.toList());
    }

    /**
     * Add a new key to the wallet
     */
    @Transactional
    public SshKeyDTO addWalletKey(String userId, SshKeyDTO keyDto, String actionBy) {
        String label = (keyDto.getLabel() == null || keyDto.getLabel().trim().isEmpty()) 
                        ? "Key " + System.currentTimeMillis() 
                        : keyDto.getLabel();
                        
        SshKey saved = saveKeyInternal(userId, label, keyDto.getSshPublicKey(), actionBy);
        return toDto(saved);
    }

    /**
     * Delete a specific key from the wallet
     */
    @Transactional
    public boolean deleteWalletKey(Long keyId, String userId) {
        Optional<SshKey> key = sshKeyRepository.findByIdAndUserId(keyId, userId);
        if (key.isPresent()) {
            sshKeyRepository.delete(key.get());
            return true;
        }
        return false;
    }

    /**
     * Update an existing key in the wallet
     */
    @Transactional
    public SshKeyDTO updateSshKey(Long keyId, String userId, SshKeyDTO keyDto) {
        // Cerca la chiave per ID e verifica che appartenga all'utente (sicurezza)
        SshKey key = sshKeyRepository.findById(keyId)
                .orElseThrow(() -> new IllegalArgumentException("Ssh Key not found"));

        // Controllo di sicurezza: l'utente loggato è il proprietario?
        if (!key.getUserId().equals(userId)) {
             throw new SecurityException("Access denied: You do not own this key");
        }

        // Aggiorna solo se i campi non sono nulli
        if (keyDto.getLabel() != null && !keyDto.getLabel().isEmpty()) {
            key.setLabel(keyDto.getLabel());
        }
        
        if (keyDto.getSshPublicKey() != null && !keyDto.getSshPublicKey().isEmpty()) {
            // Valida e formatta la nuova chiave
            String formattedKey = sshKeyValidator.formatSshKey(keyDto.getSshPublicKey());
            sshKeyValidator.isValidSshPublicKey(formattedKey);
            key.setSshKey(formattedKey);
        }

        // Aggiorna timestamp
        key.setUpdatedAt(LocalDateTime.now());
        
        // Salva e restituisci DTO
        return toDto(sshKeyRepository.save(key));
    }

    // ==========================================
    // INTERNAL HELPERS
    // ==========================================

    private SshKey saveKeyInternal(String userId, String label, String rawKey, String actionBy) {
        // Validate and format
        String formattedKey = sshKeyValidator.formatSshKey(rawKey);
        sshKeyValidator.isValidSshPublicKey(formattedKey);
        
        LocalDateTime now = LocalDateTime.now();

        // Check if a key with this specific label already exists for this user
        Optional<SshKey> existing = sshKeyRepository.findByUserIdAndLabel(userId, label);

        SshKey entity;
        if (existing.isPresent()) {
            entity = existing.get();
            entity.setSshKey(formattedKey);
            entity.setUpdatedAt(now);
            entity.setUpdatedBy(actionBy);
        } else {
            entity = SshKey.builder()
                    .userId(userId)
                    .label(label)
                    .sshKey(formattedKey)
                    .createdAt(now)
                    .updatedAt(now)
                    .createdBy(actionBy)
                    .updatedBy(actionBy)
                    .build();
        }
        return sshKeyRepository.save(entity);
    }
    
    /**
     * Convert SshKey entity to SshKeyDTO
     */
    public SshKeyDTO toDto(SshKey sshKey) {
        if (sshKey == null) {
            return new SshKeyDTO(null, null, null);
        }
        return SshKeyDTO.builder()
                .id(sshKey.getId())
                .label(sshKey.getLabel())
                .sshPublicKey(sshKey.getSshKey())
                .build();
    }
}