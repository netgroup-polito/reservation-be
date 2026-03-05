package it.polito.cloudresources.be.model;

import jakarta.persistence.*;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.EqualsAndHashCode;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;

/**
 * Entity for storing webhook execution logs
 */
@Entity
@Table(name = "webhook_logs")
@Data
@NoArgsConstructor
@AllArgsConstructor
@EqualsAndHashCode(callSuper = true)
public class WebhookLog extends AuditableEntity {
    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;
    
    @ManyToOne
    @JoinColumn(name = "webhook_id")
    private WebhookConfig webhook;
    
    @Enumerated(EnumType.STRING)
    private WebhookEventType eventType;
    
    @Column(columnDefinition = "TEXT")
    private String payload;
    
    private Integer statusCode;
    
    @Column(columnDefinition = "TEXT")
    private String response;
    
    private boolean success;
    
    private int retryCount = 0;
    
    private ZonedDateTime nextRetryAt;
    
    // Resource that triggered this webhook
    @ManyToOne
    @JoinColumn(name = "resource_id")
    private Resource resource;
}