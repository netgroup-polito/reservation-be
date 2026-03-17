package it.polito.cloudresources.be.service;

import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.core.type.TypeReference;

import it.polito.cloudresources.be.config.datetime.DateTimeConfig;
import it.polito.cloudresources.be.dto.WebhookLogRequestDTO;
import it.polito.cloudresources.be.dto.webhooks.WebhookConfigDTO;
import it.polito.cloudresources.be.dto.webhooks.WebhookConfigResponseDTO;
import it.polito.cloudresources.be.dto.webhooks.WebhookPayload;
import it.polito.cloudresources.be.mapper.WebhookMapper;
import it.polito.cloudresources.be.model.*;
import it.polito.cloudresources.be.repository.ResourceRepository;
import it.polito.cloudresources.be.repository.ResourceTypeRepository;
import it.polito.cloudresources.be.repository.WebhookConfigRepository;
import it.polito.cloudresources.be.repository.WebhookLogRepository;
import it.polito.cloudresources.be.repository.SshKeyRepository;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.springframework.data.domain.Page;
import org.springframework.data.domain.PageRequest;
import org.springframework.data.domain.Sort;
import org.springframework.http.*;
import org.springframework.scheduling.annotation.Async;
import org.springframework.scheduling.annotation.Scheduled;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.client.RestTemplate;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Optional;
import java.util.Map;
import java.util.stream.Collectors;

/**
 * Service for webhook operations
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class WebhookService {

    private final WebhookConfigRepository webhookConfigRepository;
    private final WebhookLogRepository webhookLogRepository;
    private final ResourceRepository resourceRepository;
    private final ResourceTypeRepository resourceTypeRepository;
    private final SshKeyRepository sshKeyRepository;
    private final WebhookMapper webhookMapper;
    private final ObjectMapper objectMapper;
    private final AuditLogService auditLogService;
    private final KeycloakService keycloakService;
    private final RestTemplate restTemplate;
    
    /**
     * Create a new webhook configuration
     * 
     * @param dto The webhook configuration data
     * @param userId The current user's ID
     * @return The created webhook with client secret
     */
    @Transactional
    public WebhookConfigResponseDTO createWebhook(WebhookConfigDTO dto, String userId) {
        // Check authorization if resource specified
        if (dto.getResourceId() != null) {
            Resource resource = resourceRepository.findById(dto.getResourceId())
                    .orElseThrow(() -> new EntityNotFoundException("Resource not found with ID: " + dto.getResourceId()));
            
            // Verify resource belongs to the selected site
            if (!resource.getSiteId().equals(dto.getSiteId())) {
                throw new IllegalArgumentException("The selected resource does not belong to the specified site");
            }
            
            if (!canManageWebhooksForResource(userId, resource)) {
                throw new AccessDeniedException("You don't have permission to create webhooks for this resource");
            }
        }
        
        // Check if resourceTypeId is specified and validate it belongs to the selected site
        if (dto.getResourceTypeId() != null) {
            resourceTypeRepository.findById(dto.getResourceTypeId())
                    .filter(resourceType -> resourceType.getSiteId().equals(dto.getSiteId()))
                    .orElseThrow(() -> new IllegalArgumentException("The selected resource type does not belong to the specified site"));
        }
        
        // Create webhook entity from DTO
        WebhookConfig webhookConfig = webhookMapper.toEntity(dto);
        
        // Generate a single shared secret key
        String sharedSecret = generateRandomKey();
        
        webhookConfig.setSecret(sharedSecret);
        
        // Save the webhook configuration
        WebhookConfig savedWebhook = webhookConfigRepository.save(webhookConfig);

        String siteName = keycloakService.getSiteNameById(savedWebhook.getSiteId(), "Unknown site");
        
        // Log the creation
        auditLogService.logCrudAction(
                AuditLog.LogType.ADMIN,
                AuditLog.LogAction.CREATE,
                new AuditLog.LogEntity("WEBHOOK", savedWebhook.getId().toString()),
                "User " + userId + " created webhook " + savedWebhook.getName(),
                siteName
        );
        
        // Return DTO with the shared secret
        WebhookConfigDTO responseDto = webhookMapper.toDto(savedWebhook);
        return new WebhookConfigResponseDTO(responseDto, sharedSecret);
    }
    
    /**
     * Update an existing webhook configuration
     * 
     * @param id The webhook ID
     * @param dto The updated webhook data
     * @param userId The current user's ID
     * @return The updated webhook
     */
    @Transactional
    public WebhookConfigDTO updateWebhook(Long id, WebhookConfigDTO dto, String userId) {
        WebhookConfig existingWebhook = webhookConfigRepository.findById(id)
                .orElseThrow(() -> new EntityNotFoundException("Webhook not found with ID: " + id));

        // Check authorization based on the webhook's current resource/resource type
        if (!canManageWebhook(userId, existingWebhook)) {
            throw new AccessDeniedException("You don't have permission to update this webhook");
        }

        // Prevent modification of siteId, resourceId, and resourceTypeId
        if (dto.getSiteId() != null && !dto.getSiteId().equals(existingWebhook.getSiteId())) {
            throw new IllegalArgumentException("Cannot update siteId. Please create a new webhook instead.");
        }
        // Check if the resourceId in the DTO is different from the existing one
        Long existingResourceId = existingWebhook.getResource() != null ? existingWebhook.getResource().getId() : null;
        if (dto.getResourceId() != null && !dto.getResourceId().equals(existingResourceId)) {
            throw new IllegalArgumentException("Cannot update resourceId. Please create a new webhook instead.");
        }
        // Check if the resourceTypeId in the DTO is different from the existing one
        Long existingResourceTypeId = existingWebhook.getResourceType() != null ? existingWebhook.getResourceType().getId() : null;
        if (dto.getResourceTypeId() != null && !dto.getResourceTypeId().equals(existingResourceTypeId)) {
            throw new IllegalArgumentException("Cannot update resourceTypeId. Please create a new webhook instead.");
        }

        // Update allowed fields
        existingWebhook.setName(dto.getName());
        existingWebhook.setUrl(dto.getUrl());
        existingWebhook.setEventType(dto.getEventType());
        existingWebhook.setEnabled(dto.isEnabled());
        existingWebhook.setMaxRetries(dto.getMaxRetries());
        existingWebhook.setRetryDelaySeconds(dto.getRetryDelaySeconds());
        // Secret and ID are not updated from DTO

        // Save the updated webhook
        WebhookConfig savedWebhook = webhookConfigRepository.save(existingWebhook);
        String siteName = keycloakService.getSiteNameById(savedWebhook.getSiteId(), "Unknown site");
        // Log the update
        auditLogService.logCrudAction(
                AuditLog.LogType.ADMIN,
                AuditLog.LogAction.UPDATE,
                new AuditLog.LogEntity("WEBHOOK", savedWebhook.getId().toString()),
                "User " + userId + " updated webhook " + savedWebhook.getName(),
                siteName
        );
        
        return webhookMapper.toDto(savedWebhook);
    }
    
    /**
     * Delete a webhook configuration
     * 
     * @param id The webhook ID
     * @param userId The current user's ID
     * @return true if deleted successfully
     */
    @Transactional
    public boolean deleteWebhook(Long id, String userId) {
        return webhookConfigRepository.findById(id)
                .map(webhook -> {
                    // Check authorization
                    if (!canManageWebhook(userId, webhook)) {
                        throw new AccessDeniedException("You don't have permission to delete this webhook");
                    }
                    
                    webhookLogRepository.findByWebhookId(id).forEach(webhookLogRepository::delete);
                    webhookConfigRepository.deleteById(id);
                    
                    String siteName = keycloakService.getSiteNameById(webhook.getSiteId(), "Unknown site");

                    
                    // Log the deletion
                    auditLogService.logCrudAction(
                            AuditLog.LogType.ADMIN,
                            AuditLog.LogAction.DELETE,
                            new AuditLog.LogEntity("WEBHOOK", id.toString()),
                            "User " + userId + " deleted webhook " + webhook.getName(),
                            siteName
                    );
                    
                    return true;
                })
                .orElse(false);
    }
    
    /**
     * Get all webhooks accessible to the current user
     * 
     * @param userId The current user's ID
     * @return List of accessible webhooks
     */
    public List<WebhookConfigDTO> getAllWebhooks(String userId) {
        List<WebhookConfig> webhooks;
        
        // Global admins can see all webhooks
        if (keycloakService.hasGlobalAdminRole(userId)) {
            webhooks = webhookConfigRepository.findAll();
        } else {
            // Get sites where the user is an admin
            List<String> adminSites = keycloakService.getUserAdminGroupIds(userId);
            log.debug("userId: {}, adminSites: {}", userId, adminSites);
            // Get webhooks for resources in these sites

            webhooks = adminSites.stream()
                    .flatMap(siteId -> webhookConfigRepository.findBySiteId(siteId).stream())
                    .toList();
            log.debug(userId + " webhooks: " + webhooks);
                
        }
        log.debug("Returned webhooks for user {}: {}", userId, webhooks);
        return webhooks.stream()
                .map(webhookMapper::toDto)
                .toList();
    }
    
    /**
     * Get webhook by ID if accessible to the current user
     * 
     * @param id The webhook ID
     * @param userId The current user's ID
     * @return The webhook if found and accessible
     */
    public Optional<WebhookConfigDTO> getWebhookById(Long id, String userId) {
        return webhookConfigRepository.findById(id)
                .filter(webhook -> canManageWebhook(userId, webhook))
                .map(webhookMapper::toDto);
    }

    /**
     * Get all webhook logs accessible to the current user
     * 
     * @param userId The current user's ID
     * @param success Optional filter for success status
     * @param query Optional text search query
     * @param page Page number
     * @param size Page size
     * @return Page of accessible webhook logs
     */
    public Page<WebhookLog> getAllAccessibleWebhookLogs(
            String userId, Boolean success, String query, int page, int size) {
        
        PageRequest pageRequest = PageRequest.of(
                page, size, Sort.by(Sort.Direction.DESC, "createdAt"));
        
        // Global admins can see all logs
        if (keycloakService.hasGlobalAdminRole(userId)) {
            if (success != null && query != null && !query.isEmpty()) {
                // Filter by both success and query
                return webhookLogRepository.findBySuccessAndResponseContainingIgnoreCase(
                        success, query, pageRequest);
            } else if (success != null) {
                // Filter by success only
                return webhookLogRepository.findBySuccess(success, pageRequest);
            } else if (query != null && !query.isEmpty()) {
                // Filter by query only
                return webhookLogRepository.findByPayloadContainingIgnoreCase(query, pageRequest);
            } else {
                // No filters
                return webhookLogRepository.findAll(pageRequest);
            }
        }
        
        // Site admins can only see logs for webhooks in their sites
        List<String> adminSites = keycloakService.getUserAdminGroups(userId);
        
        if (adminSites.isEmpty()) {
            // User is not admin of any site, return empty page
            return Page.empty(pageRequest);
        }
        
        // Get all webhooks in the sites where the user is an admin
        List<WebhookConfig> accessibleWebhooks = new ArrayList<>();
        
        for (String siteId : adminSites) {
            // Get webhooks for resources in this site
            accessibleWebhooks.addAll(
                    webhookConfigRepository.findByResourceSiteIdAndEnabled(siteId, true));
            
            // Get webhooks for resource types in this site
            accessibleWebhooks.addAll(
                    webhookConfigRepository.findByResourceTypeSiteIdAndEnabled(siteId, true));
        }
        
        // If no accessible webhooks, return empty page
        if (accessibleWebhooks.isEmpty()) {
            return Page.empty(pageRequest);
        }
        
        // Extract webhook IDs
        List<Long> webhookIds = accessibleWebhooks.stream()
                .map(WebhookConfig::getId)
                .toList();
        
        // Get logs for these webhooks with the specified filters
        if (success != null && query != null && !query.isEmpty()) {
            // Filter by both success and query
            return webhookLogRepository.findByWebhookIdInAndSuccessAndPayloadContainingIgnoreCase(
                    webhookIds, success, query, pageRequest);
        } else if (success != null) {
            // Filter by success only
            return webhookLogRepository.findByWebhookIdInAndSuccess(webhookIds, success, pageRequest);
        } else if (query != null && !query.isEmpty()) {
            // Filter by query only
            return webhookLogRepository.findByWebhookIdInAndPayloadContainingIgnoreCase(
                    webhookIds, query, pageRequest);
        } else {
            // No filters, just filter by webhook IDs
            return webhookLogRepository.findByWebhookIdIn(webhookIds, pageRequest);
        }
    }
    
    /**
     * Process a resource event by sending webhooks (Updated for SSH Keys List)
     */
    @Async
    @Transactional
    public void processResourceEvent(WebhookEventType eventType, Resource resource, Object data) {
        try {
            log.debug("Processing resource event {} for resource {}", eventType, resource.getId());
            
            // Variabile per i dati che invieremo
            Object payloadData = data;

            // Logica specifica per START e CREATED: Arricchimento Chiavi SSH
            if ((eventType == WebhookEventType.EVENT_START || eventType == WebhookEventType.EVENT_CREATED) 
                && data instanceof Event) {
                
                Event event = (Event) data;
                
                if (event.getKeycloakId() != null) {
                    try {
                        // FIX 1: Conversione sicura della Mappa usando TypeReference
                        Map<String, Object> eventMap = objectMapper.convertValue(event, new TypeReference<Map<String, Object>>() {});

                        // FIX 2: Usa il nome corretto del metodo nel Repository (findAllByUserId)
                        List<SshKey> userKeys = sshKeyRepository.findAllByUserId(event.getKeycloakId());
                        
                        // FIX 3: Estrazione stringhe
                        // NOTA: Se 'getSshPublicKey' è rosso, apri SshKey.java e controlla il nome del getter (es. getPublicKey o getKey)
                        List<String> sshKeyList = userKeys.stream().map(SshKey::getSshKey).collect(Collectors.toList());

                        // 4. Inserimento nel JSON
                        eventMap.put("sshKeys", sshKeyList);
                        
                        // Pulizia campi legacy
                        eventMap.remove("sshPublicKey"); 
                        eventMap.remove("sshKeyId");
                        eventMap.remove("ssh_key"); 

                        // Info extra
                        eventMap.put("resourceName", resource.getName());
                        eventMap.put("resourceId", resource.getId());

                        payloadData = eventMap;
                        
                        log.debug("Enriched webhook payload with {} SSH keys for user {}", sshKeyList.size(), event.getKeycloakId());
                    } catch (Exception e) {
                        log.error("Failed to fetch SSH keys for webhook enrichment: {}", e.getMessage());
                    }
                }
            }

            // Recupera i webhook configurati
            List<WebhookConfig> webhooks = webhookConfigRepository.findRelevantWebhooksForResourceEvent(
                    resource.getId(), eventType);
            
            log.debug("Found {} webhooks to process", webhooks.size());
            
            for (WebhookConfig webhook : webhooks) {
                try {
                    executeWebhook(webhook, eventType, payloadData, resource);
                } catch (Exception e) {
                    log.error("Error executing webhook {}: {}", webhook.getName(), e.getMessage());
                    scheduleRetry(webhook, eventType, payloadData, resource);
                }
            }
        } catch (Exception e) {
            log.error("Error processing resource event: {}", e.getMessage(), e);
        }
    }

    /**
     * Execute a test webhook
     * 
     * @param webhookId The webhook ID
     * @param userId The current user's ID
     * @return true if executed successfully
     */
    public boolean testWebhook(Long webhookId, String userId) {
        WebhookConfig webhook = webhookConfigRepository.findById(webhookId)
                .orElseThrow(() -> new EntityNotFoundException("Webhook not found with ID: " + webhookId));
        
        // Check authorization
        if (!canManageWebhook(userId, webhook)) {
            throw new AccessDeniedException("You don't have permission to test this webhook");
        }
        
        try {
            // Create test data
            TestWebhookData testData = new TestWebhookData(
                    "This is a test event",
                    ZonedDateTime.now(DateTimeConfig.DEFAULT_ZONE_ID),
                    webhook.getId()
            );
            
            // Execute the webhook
            Resource resource = webhook.getResource();
            if (resource == null && webhook.getResourceType() != null) {
                // Get a sample resource of this type
                List<Resource> resources = resourceRepository.findByTypeId(webhook.getResourceType().getId());
                if (!resources.isEmpty()) {
                    resource = resources.get(0);
                }
            }
            
            executeWebhook(webhook, WebhookEventType.ALL, testData, resource);
            return true;
        } catch (Exception e) {
            log.error("Error testing webhook: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Execute a webhook
     * 
     * @param webhook The webhook configuration
     * @param eventType The event type
     * @param data The event data
     * @param resource The resource that triggered the event
     * @throws JsonProcessingException If there's an error serializing the payload
     */
    private void executeWebhook(WebhookConfig webhook, WebhookEventType eventType, Object data, Resource resource) 
            throws JsonProcessingException {
        // Create payload
        WebhookPayload payload = new WebhookPayload(
                eventType,
                ZonedDateTime.now(DateTimeConfig.DEFAULT_ZONE_ID),
                webhook.getId().toString(),
                data
        );
        
        String payloadJson = safeSerializePayload(payload);
        
        // Set up headers with signature
        HttpHeaders headers = createHeaders(webhook, payloadJson);
        
        log.debug("Sending webhook to URL: {}", webhook.getUrl());
        
        // Execute HTTP call
        ResponseEntity<String> response;
        try {
            response = restTemplate.exchange(
                    webhook.getUrl(),
                    HttpMethod.POST,
                    new HttpEntity<>(payloadJson, headers),
                    String.class
            );
        } catch (Exception e) {
            log.error("Webhook request failed: {}", e.getMessage());
            
            // Create a failure log
            WebhookLog log = new WebhookLog();
            log.setWebhook(webhook);
            log.setEventType(eventType);
            log.setPayload(payloadJson);
            log.setStatusCode(null);
            log.setResponse("Request failed: " + e.getMessage());
            log.setSuccess(false);
            log.setResource(resource);
            
            // Schedule retry
            scheduleRetry(log);
            
            throw e;
        }
        
        // Log the result
        WebhookLog webhookLog = new WebhookLog();
        webhookLog.setWebhook(webhook);
        webhookLog.setEventType(eventType);
        webhookLog.setPayload(payloadJson);
        webhookLog.setStatusCode(response.getStatusCode().value());
        webhookLog.setResponse(response.getBody());
        webhookLog.setSuccess(response.getStatusCode().is2xxSuccessful());
        webhookLog.setResource(resource);
        
        webhookLogRepository.save(webhookLog);
        
        if (!webhookLog.isSuccess()) {
            log.error("Webhook failed with status code: {}", webhookLog.getStatusCode());
            logSystemEvent(
                    "Webhook failure", 
                    "Webhook " + webhook.getName() + " failed with status " + webhookLog.getStatusCode(),
                    AuditLog.LogSeverity.WARNING
            );
            
            // Schedule retry if necessary
            scheduleRetry(webhookLog);
        } else {
            log.debug("Webhook successful with status code: {}", webhookLog.getStatusCode());
        }
    }
    
    /**
     * Schedule a retry for a webhook
     * 
     * @param webhook The webhook configuration
     * @param eventType The event type
     * @param data The event data
     * @param resource The resource that triggered the event
     */
    private void scheduleRetry(WebhookConfig webhook, WebhookEventType eventType, Object data, Resource resource) {
        try {
            // Create payload
            WebhookPayload payload = new WebhookPayload(
                    eventType,
                    ZonedDateTime.now(DateTimeConfig.DEFAULT_ZONE_ID),
                    webhook.getId().toString(),
                    data
            );
            
            String payloadJson = safeSerializePayload(payload);
            
            // Create log with retry information
            WebhookLog webhookLog = new WebhookLog();
            webhookLog.setWebhook(webhook);
            webhookLog.setEventType(eventType);
            webhookLog.setPayload(payloadJson);
            webhookLog.setSuccess(false);
            webhookLog.setResource(resource);
            webhookLog.setRetryCount(0);
            webhookLog.setNextRetryAt(ZonedDateTime.now(DateTimeConfig.DEFAULT_ZONE_ID)
                    .plusSeconds(webhook.getRetryDelaySeconds()));
            
            webhookLogRepository.save(webhookLog);
            
            log.debug("Scheduled webhook retry for {}", webhook.getName());
        } catch (Exception e) {
            log.error("Error scheduling webhook retry: {}", e.getMessage(), e);
        }
    }
    
    /**
     * Schedule a retry for a failed webhook log
     * 
     * @param webhookLog The webhook log
     */
    private void scheduleRetry(WebhookLog webhookLog) {
        if (webhookLog.getRetryCount() >= webhookLog.getWebhook().getMaxRetries()) {
            log.debug("Max retries reached for webhook {}", webhookLog.getWebhook().getName());
            return;
        }
        
        // Calculate next retry time with exponential backoff
        int retryCount = webhookLog.getRetryCount();
        int delaySeconds = webhookLog.getWebhook().getRetryDelaySeconds() * (int) Math.pow(2, retryCount);
        webhookLog.setNextRetryAt(ZonedDateTime.now(DateTimeConfig.DEFAULT_ZONE_ID).plusSeconds(delaySeconds));
        webhookLog.setRetryCount(retryCount + 1);
        
        webhookLogRepository.save(webhookLog);
        
        log.debug("Scheduled retry {} for webhook {}, next attempt in {} seconds",
        webhookLog.getRetryCount(), webhookLog.getWebhook().getName(), delaySeconds);
    }
    
    /**
     * Process scheduled webhook retries
     */
    @Scheduled(fixedRate = 60000) // Run every minute
    public void processRetries() {
        ZonedDateTime now = ZonedDateTime.now(DateTimeConfig.DEFAULT_ZONE_ID);
        
        List<WebhookLog> pendingRetries = webhookLogRepository.findPendingRetries(now);
        
        if (!pendingRetries.isEmpty()) {
            log.debug("Processing {} pending webhook retries", pendingRetries.size());
        }
        
        for (WebhookLog webhookLog : pendingRetries) {
            try {
                // Parse the stored payload
                WebhookPayload payload = objectMapper.readValue(webhookLog.getPayload(), WebhookPayload.class);
                
                // Execute the webhook
                executeWebhook(webhookLog.getWebhook(), webhookLog.getEventType(), payload.getData(), webhookLog.getResource());
            } catch (Exception e) {
                log.error("Retry failed for webhook log ID {}: {}", webhookLog.getId(), e.getMessage());
                scheduleRetry(webhookLog);
            }
        }
    }
    
    /**
     * Create HTTP headers for webhook request
     */
    private HttpHeaders createHeaders(WebhookConfig webhook, String payload) {
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        
        // Add signature if secret is present
        if (webhook.getSecret() != null && !webhook.getSecret().isEmpty()) {
            String signature = generateHmacSignature(payload, webhook.getSecret());
            headers.add("X-Webhook-Signature", signature);
        }
        
        return headers;
    }
    
    /**
     * Generate HMAC signature for payload
     */
    public String generateHmacSignature(String payload, String secretKey) {
        try {
            Mac sha256Hmac = Mac.getInstance("HmacSHA256");
            SecretKeySpec secretKeySpec = new SecretKeySpec(secretKey.getBytes(), "HmacSHA256");
            sha256Hmac.init(secretKeySpec);
            byte[] hash = sha256Hmac.doFinal(payload.getBytes());
            return Base64.getEncoder().encodeToString(hash);
        } catch (Exception e) {
            log.error("Error generating HMAC signature: {}", e.getMessage(), e);
            return "";
        }
    }
    
    /**
     * Validate webhook signature
     * 
     * @param webhookId The webhook ID from the request
     * @param signature The signature from X-Webhook-Signature header
     * @param payload The request payload
     * @return true if signature is valid
     */
    public boolean validateWebhookSignature(String webhookId, String signature, String payload) {
        if (webhookId == null || signature == null || payload == null) {
            log.warn("Invalid signature validation request: webhookId={}, signature={}, payload length={}", 
                    webhookId, signature != null ? "present" : "null", payload != null ? payload.length() : 0);
            return false;
        }
        
        try {
            Long id = Long.parseLong(webhookId);
            Optional<WebhookConfig> webhookOpt = webhookConfigRepository.findById(id);
            
            if (webhookOpt.isEmpty()) {
                log.warn("Webhook not found with ID: {}", webhookId);
                return false;
            }
            
            WebhookConfig webhook = webhookOpt.get();
            if (!webhook.isEnabled()) {
                log.warn("Webhook {} is disabled", webhookId);
                return false;
            }
            
            String secret = webhook.getSecret();
            if (secret == null || secret.isEmpty()) {
                log.warn("No secret configured for webhook {}", webhookId);
                return false;
            }
            
            // Use existing signature generation logic
            String expectedSignature = generateHmacSignature(payload, secret);
            boolean isValid = expectedSignature.equals(signature);
            
            if (!isValid) {
                log.warn("Invalid signature for webhook {}", webhookId);
            } else {
                log.debug("Valid signature for webhook {}", webhookId);
            }
            
            return isValid;
            
        } catch (NumberFormatException e) {
            log.warn("Invalid webhook ID format: {}", webhookId);
            return false;
        } catch (Exception e) {
            log.error("Error validating webhook signature: {}", e.getMessage(), e);
            return false;
        }
    }
    
    /**
     * Generate a random key for webhook authentication
     */
    private String generateRandomKey() {
        byte[] key = new byte[32]; // 256 bits
        SecureRandom secureRandom = new SecureRandom();
        secureRandom.nextBytes(key);
        return new String(Base64.getEncoder().encode(key), StandardCharsets.UTF_8);   
    }
    
    /**
     * Check if a user can manage webhooks for a resource
     */
    private boolean canManageWebhooksForResource(String userId, Resource resource) {
        // Global admins can manage all webhooks
        if (keycloakService.hasGlobalAdminRole(userId)) {
            return true;
        }
        
        // Site admins can manage webhooks for resources in their sites
        return keycloakService.isUserSiteAdmin(userId, resource.getSiteId());
    }
    
    /**
     * Check if a user can manage a webhook
     */
    private boolean canManageWebhook(String userId, WebhookConfig webhook) {
        // Global admins can manage all webhooks
        if (keycloakService.hasGlobalAdminRole(userId)) {
            return true;
        }
        
        // Get the site ID from the webhook
        String siteId = webhook.getSiteId();
        if (siteId == null) {
            return false;
        }
        
        // Check if user is admin of the site
        return keycloakService.isUserSiteAdmin(userId, siteId);
    }
    
    /**
     * Data class for test webhook
     */
    @lombok.Data
    private static class TestWebhookData {
        private final String message;
        private final ZonedDateTime timestamp;
        private final Long webhookId;
    }
    
    /**
     * Log a system event
     */
    private void logSystemEvent(String message, String details, AuditLog.LogSeverity severity) {
        auditLogService.logCrudAction(
                AuditLog.LogType.ADMIN,
                AuditLog.LogAction.UPDATE,
                new AuditLog.LogEntity("SYSTEM", null),
                details
        );
    }
    
    /**
     * Process webhook log creation request with validation
     * 
     * @param rawPayload The raw payload as received from the webhook
     * @param signature The webhook signature from headers
     * @return ProcessWebhookLogResult containing the log or error information
     */
    @Transactional
    public ProcessWebhookLogResult processWebhookLogCreation(String rawPayload, String signature) {
        try {
            // Parse the request body manually
            WebhookLogRequestDTO request;
            try {
                ObjectMapper objectMapper = new ObjectMapper();
                request = objectMapper.readValue(rawPayload, WebhookLogRequestDTO.class);
            } catch (Exception e) {
                log.warn("Invalid JSON payload in webhook log request", e);
                return ProcessWebhookLogResult.error(HttpStatus.BAD_REQUEST, "Invalid JSON payload");
            }
            
            // Validate required fields manually since we can't use @Valid
            if (request.getWebhookId() == null || request.getWebhookId().isBlank()) {
                return ProcessWebhookLogResult.error(HttpStatus.BAD_REQUEST, "Webhook ID is required");
            }
            if (request.getEventType() == null) {
                return ProcessWebhookLogResult.error(HttpStatus.BAD_REQUEST, "Event type is required");
            }
            if (request.getPayload() == null || request.getPayload().isBlank()) {
                return ProcessWebhookLogResult.error(HttpStatus.BAD_REQUEST, "Payload is required");
            }
            if (request.getSuccess() == null) {
                return ProcessWebhookLogResult.error(HttpStatus.BAD_REQUEST, "Success status is required");
            }
            
            // Validate signature using the raw payload
            if (!validateWebhookSignature(request.getWebhookId(), signature, rawPayload)) {
                log.warn("Invalid webhook signature for webhook ID: {}", request.getWebhookId());
                return ProcessWebhookLogResult.error(HttpStatus.UNAUTHORIZED, "Invalid signature");
            }
            
            // Get the webhook configuration
            Long webhookId;
            try {
                webhookId = Long.parseLong(request.getWebhookId());
            } catch (NumberFormatException e) {
                return ProcessWebhookLogResult.error(HttpStatus.BAD_REQUEST, "Invalid webhook ID format");
            }
            
            Optional<WebhookConfig> webhookOpt = webhookConfigRepository.findById(webhookId);
            if (webhookOpt.isEmpty()) {
                return ProcessWebhookLogResult.error(HttpStatus.NOT_FOUND, "Webhook not found");
            }
            
            WebhookConfig webhook = webhookOpt.get();
            
            // Get resource if specified
            Resource resource = null;
            if (request.getResourceId() != null) {
                Optional<Resource> resourceOpt = resourceRepository.findById(request.getResourceId());
                if (resourceOpt.isEmpty()) {
                    return ProcessWebhookLogResult.error(HttpStatus.NOT_FOUND, "Resource not found");
                }
                resource = resourceOpt.get();
            }
            
            // Create webhook log
            WebhookLog webhookLog = new WebhookLog();
            webhookLog.setWebhook(webhook);
            webhookLog.setEventType(request.getEventType());
            webhookLog.setPayload(request.getPayload());
            webhookLog.setStatusCode(request.getStatusCode());
            webhookLog.setResponse(request.getResponse());
            webhookLog.setSuccess(request.getSuccess());
            webhookLog.setRetryCount(request.getRetryCount() != null ? request.getRetryCount() : 0);
            webhookLog.setResource(resource);
            
            WebhookLog savedLog = webhookLogRepository.save(webhookLog);
            
            log.info("Webhook log created successfully for webhook {} with status {}", 
                    request.getWebhookId(), request.getSuccess() ? "success" : "failure");
            
            return ProcessWebhookLogResult.success(savedLog);
            
        } catch (Exception e) {
            log.error("Error processing webhook log creation: {}", e.getMessage(), e);
            return ProcessWebhookLogResult.error(HttpStatus.INTERNAL_SERVER_ERROR, 
                    "An error occurred while processing the webhook log creation");
        }
    }

    /**
     * Result class for webhook log processing
     */
    public static class ProcessWebhookLogResult {
        private final boolean success;
        private final WebhookLog webhookLog;
        private final HttpStatus status;
        private final String errorMessage;

        private ProcessWebhookLogResult(boolean success, WebhookLog webhookLog, HttpStatus status, String errorMessage) {
            this.success = success;
            this.webhookLog = webhookLog;
            this.status = status;
            this.errorMessage = errorMessage;
        }

        public static ProcessWebhookLogResult success(WebhookLog webhookLog) {
            return new ProcessWebhookLogResult(true, webhookLog, HttpStatus.CREATED, null);
        }

        public static ProcessWebhookLogResult error(HttpStatus status, String errorMessage) {
            return new ProcessWebhookLogResult(false, null, status, errorMessage);
        }

        public boolean isSuccess() {
            return success;
        }

        public WebhookLog getWebhookLog() {
            return webhookLog;
        }

        public HttpStatus getStatus() {
            return status;
        }

        public String getErrorMessage() {
            return errorMessage;
        }
    }
    
    /**
     * Safely serialize webhook payload to JSON, handling potential Hibernate session issues
     * 
     * @param payload The webhook payload to serialize
     * @return JSON string representation of the payload
     * @throws JsonProcessingException If serialization fails
     */
    private String safeSerializePayload(WebhookPayload payload) throws JsonProcessingException {
        try {
            return objectMapper.writeValueAsString(payload);
        } catch (Exception e) {
            // If serialization fails due to lazy loading issues, log the error and create a simplified payload
            log.warn("Failed to serialize webhook payload due to lazy loading issues: {}", e.getMessage());
            
            // Create a simplified payload without potentially problematic data
            WebhookPayload simplifiedPayload = new WebhookPayload(
                    payload.getEventType(),
                    payload.getTimestamp(),
                    payload.getWebhookId(),
                    "Payload serialization failed due to detached entity. Event type: " + payload.getEventType()
            );
            
            return objectMapper.writeValueAsString(simplifiedPayload);
        }
    }
}