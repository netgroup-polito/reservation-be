package it.polito.cloudresources.be.dto;

import it.polito.cloudresources.be.model.WebhookEventType;
import jakarta.validation.constraints.NotBlank;
import jakarta.validation.constraints.NotNull;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

/**
 * DTO for webhook log creation requests
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class WebhookLogRequestDTO {
    
    @NotBlank(message = "Webhook ID is required")
    private String webhookId;
    
    @NotNull(message = "Event type is required")
    private WebhookEventType eventType;
    
    @NotBlank(message = "Payload is required")
    private String payload;
    
    private Integer statusCode;
    
    
    private String response;
    
    @NotNull(message = "Success status is required")
    private Boolean success;
    
    private Integer retryCount = 0;
    
    private Long resourceId;
    
    private Object metadata;
}