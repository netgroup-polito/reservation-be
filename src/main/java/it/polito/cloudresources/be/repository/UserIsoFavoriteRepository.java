package it.polito.cloudresources.be.repository;

import it.polito.cloudresources.be.model.UserIsoFavorite;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;

@Repository
public interface UserIsoFavoriteRepository extends JpaRepository<UserIsoFavorite, Long> {
    
    // Trova tutti i preferiti di un utente specifico
    List<UserIsoFavorite> findAllByUserId(String userId);

    // Conta quanti preferiti ha un utente con quel nome (per evitare duplicati di alias)
    boolean existsByUserIdAndAlias(String userId, String alias);
}