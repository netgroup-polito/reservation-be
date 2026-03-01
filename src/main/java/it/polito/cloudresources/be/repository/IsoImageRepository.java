package it.polito.cloudresources.be.repository;

import it.polito.cloudresources.be.model.IsoImage;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.stereotype.Repository;

import java.util.List;
import java.util.Optional;

@Repository
public interface IsoImageRepository extends JpaRepository<IsoImage, Long> { // Nota <IsoImage, Long>
    
    // Trova le immagini attive ordinate per nome visualizzato
    List<IsoImage> findAllByIsActiveTrueOrderByDisplayNameAsc();
    
    // Serve per l'inizializzazione o check duplicati
    Optional<IsoImage> findByName(String name);
}