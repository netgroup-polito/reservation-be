package it.polito.cloudresources.be.mapper;

import it.polito.cloudresources.be.dto.users.UserDTO;
import it.polito.cloudresources.be.service.KeycloakService;
import lombok.RequiredArgsConstructor;
import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.stereotype.Component;

import java.util.HashSet;
import java.util.List;
import java.util.stream.Collectors;

/**
 * Mapper for converting between Keycloak UserRepresentation and UserDTO objects
 */
@Component
@RequiredArgsConstructor
public class UserMapper {
    
    private final KeycloakService keycloakService;
    
    
    /**
     * Convert from UserRepresentation to UserDTO
     */
    public UserDTO toDto(UserRepresentation userRepresentation) {
        if (userRepresentation == null) {
            return null;
        }
        
        UserDTO dto = new UserDTO();
        dto.setId(userRepresentation.getId());
        dto.setUsername(userRepresentation.getUsername());
        dto.setFirstName(userRepresentation.getFirstName());
        dto.setLastName(userRepresentation.getLastName());
        dto.setEmail(userRepresentation.getEmail());
        
        // Get roles
        List<String> roles = keycloakService.getUserRoles(userRepresentation.getId());
        dto.setRoles(new HashSet<>(roles));

        // Get avatar
        keycloakService.getUserAvatar(userRepresentation.getId())
            .ifPresent(dto::setAvatar);

        // RIMOSSO: Blocco che recuperava e settava la sshPublicKey
        
        return dto;
    }
    
    /**
     * Convert a list of UserRepresentations to a list of UserDTOs
     */
    public List<UserDTO> toDto(List<UserRepresentation> userRepresentations) {
        if (userRepresentations == null) {
            return null;
        }
        
        return userRepresentations.stream()
                .map(this::toDto)
                .collect(Collectors.toList());
    }
}