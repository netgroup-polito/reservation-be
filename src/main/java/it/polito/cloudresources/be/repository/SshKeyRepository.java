package it.polito.cloudresources.be.repository;

import it.polito.cloudresources.be.model.SshKey;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

/**
 * Repository for SSH keys
 */
@Repository
public interface SshKeyRepository extends JpaRepository<SshKey, Long> {
    
    /**
     * Find all SSH keys by user ID
     * * @param userId The Keycloak user ID
     * @return List of SSH keys found
     */
    List<SshKey> findAllByUserId(String userId);

    /**
     * Find a specific SSH key by user ID and Label
     * Useful for retrieving the "Default" key for legacy support
     * * @param userId The Keycloak user ID
     * @param label The label of the key
     * @return Optional containing the SSH key if found
     */
    Optional<SshKey> findByUserIdAndLabel(String userId, String label);

    /**
     * Find a specific SSH key by ID and User ID
     * Ensure users can only access their own keys
     * * @param id The Key ID
     * @param userId The Keycloak user ID
     * @return Optional containing the SSH key if found
     */
    Optional<SshKey> findByIdAndUserId(Long id, String userId);
    
    /**
     * Delete all SSH keys by user ID
     * * @param userId The Keycloak user ID
     * @return Number of records deleted
     */
    int deleteAllByUserId(String userId);
}