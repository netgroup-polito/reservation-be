package it.polito.cloudresources.be.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;
import lombok.NoArgsConstructor;

@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class IsoImageDTO {
    private Long id;            
    private String name;        
    private String displayName; 
    private String imageUrl;    
    private String checksumUrl; 
    private String checksumType;
    private boolean active;
}