package it.polito.cloudresources.be.service;

import it.polito.cloudresources.be.model.IsoImage;
import it.polito.cloudresources.be.model.UserIsoFavorite;
import it.polito.cloudresources.be.repository.IsoImageRepository;
import it.polito.cloudresources.be.repository.UserIsoFavoriteRepository;
import it.polito.cloudresources.be.util.UrlValidator;


import it.polito.cloudresources.be.dto.EventDTO;
import it.polito.cloudresources.be.mapper.EventMapper;
import it.polito.cloudresources.be.model.AuditLog;
import it.polito.cloudresources.be.model.Event;
import it.polito.cloudresources.be.model.Resource;
import it.polito.cloudresources.be.model.ResourceStatus;
import it.polito.cloudresources.be.model.ResourceType;
import it.polito.cloudresources.be.model.WebhookEventType;
import it.polito.cloudresources.be.repository.EventRepository;
import it.polito.cloudresources.be.repository.ResourceRepository;
import it.polito.cloudresources.be.util.DateTimeUtils;
import jakarta.persistence.EntityNotFoundException;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;

import org.keycloak.representations.idm.UserRepresentation;
import org.springframework.security.access.AccessDeniedException;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;

import org.springframework.transaction.support.TransactionSynchronization;
import org.springframework.transaction.support.TransactionSynchronizationManager;

import java.time.ZonedDateTime;
import java.util.ArrayList;
import java.util.List;
import java.util.Optional;
import java.util.stream.Collectors;

/**
 * Service for event operations with consistent time zone handling
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class EventService {

    private final IsoImageRepository isoImageRepository;
    private final UserIsoFavoriteRepository userIsoFavoriteRepository;
    private final EventRepository eventRepository;
    private final ResourceRepository resourceRepository;
    private final NotificationService notificationService;
    private final ResourceService resourceService;
    private final KeycloakService keycloakService;
    private final AuditLogService auditLogService;
    private final WebhookService webhookService;
    private final EventMapper eventMapper;
    private final DateTimeUtils dateTimeUtils;
    
    // Role required to use custom ISO URLs
    private static final String ROLE_CUSTOM_ISO_UPLOADER = "custom-iso-uploader";

    /**
     * Get all events based on user site access
     */
    public List<EventDTO> getAllEvents(String userId) {
        if (keycloakService.hasGlobalAdminRole(userId)) {
            // Global admins see all events
            return eventMapper.toDto(eventRepository.findAll());
        } else {
            // Site admins and regular users see only events for resources in their sites
            List<String> userSites = keycloakService.getUserSites(userId);

            if (userSites.isEmpty()) {
                return new ArrayList<>();
            }

            List<Event> events = eventRepository.findBySiteIds(userSites);
            return eventMapper.toDto(events);
        }
    }

    /**
     * Get events by site
     */
    public List<EventDTO> getEventsBySite(String siteId, String userId) {
        // Validate user has access
        if (!keycloakService.isUserInGroup(userId, siteId) &&
                !keycloakService.hasGlobalAdminRole(userId)) {
            throw new AccessDeniedException("User does not have access to this site");
        }

        List<Event> events = eventRepository.findBySiteId(siteId);

        return eventMapper.toDto(events);
    }

    /**
     * Get event by ID
     */
    public EventDTO getEventById(Long id, String userId) {
        Optional<Event> eventOpt = eventRepository.findById(id);
        
        if (!eventOpt.isPresent()) {
            throw new EntityNotFoundException("Event " + id + " not found");
        }
        
        Event event = eventOpt.get();
        
        // Check if the user can access this event
        if (!canAccessEvent(userId, event)) {
            throw new AccessDeniedException("User " + userId + " can't access event " + id);
        }
        
        return eventMapper.toDto(event);
    }

    /**
     * Get events by resource
     */
    public List<EventDTO> getEventsByResource(Long resourceId, String userId) {
        // Check if the user has access to this resource
        Resource resource = resourceRepository.findById(resourceId)
                .orElseThrow(() -> new EntityNotFoundException("Resource not found with ID: " + resourceId));
        
        if (!resourceService.canAccessResource(userId, resource)) {
            throw new AccessDeniedException("You don't have access to events for this resource");
        }
        
        return eventMapper.toDto(eventRepository.findByResourceId(resourceId));
    }

    /**
     * Get events by user's Keycloak ID
     */
    public List<EventDTO> getEventsByUserKeycloakId(String keycloakId, String requestUserId) {
        // Users can always see their own events, administrators see events from their site
        if (keycloakId.equals(requestUserId) || keycloakService.hasGlobalAdminRole(requestUserId)) {
            return eventMapper.toDto(eventRepository.findByKeycloakId(keycloakId));
        }
        
        // Site admins can see events from users in their sites
        List<String> adminSites = keycloakService.getUserAdminGroups(requestUserId);
        List<String> userSites = keycloakService.getUserSites(keycloakId);
        
        // Check if the request user is admin of any site the target user belongs to
        boolean hasAdminAccess = adminSites.stream()
                .anyMatch(userSites::contains);
        
        if (!hasAdminAccess) {
            throw new AccessDeniedException("You don't have access to this user's events");
        }
        
        // Get the user's events but filter to only sites the admin has access to
        List<String> commonSites = adminSites.stream()
                .filter(userSites::contains)
                .collect(Collectors.toList());
        
        List<Event> userEvents = eventRepository.findBySiteIds(commonSites);
        if (userEvents.isEmpty()) {
            return new ArrayList<>();
        }
                
        return eventMapper.toDto(userEvents);
    }

    /**
     * Get events by date range
     */
    public List<EventDTO> getEventsByDateRange(ZonedDateTime startDate, ZonedDateTime endDate, String userId) {
        // Make sure both dates have time zone info
        ZonedDateTime normalizedStartDate = dateTimeUtils.ensureTimeZone(startDate);
        ZonedDateTime normalizedEndDate = dateTimeUtils.ensureTimeZone(endDate);

        log.debug("getEventsByDateRange called for userId: {}", userId);

        List<Event> events = eventRepository.findByDateRange(normalizedStartDate, normalizedEndDate);

        // Filter events based on site access
        List<Event> accessibleEvents;

        if (keycloakService.hasGlobalAdminRole(userId)) {
            // Global admins see all events
            accessibleEvents = events;
        } else {
            // Site users see only events for resources in their sites
            log.debug("Attempting to fetch sites for user ID: {}", userId);
            List<String> userSites = keycloakService.getUserSites(userId);

            accessibleEvents = events.stream()
                    .filter(event -> userSites.contains(event.getResource().getSiteId()))
                    .collect(Collectors.toList());
        }

        return eventMapper.toDto(accessibleEvents);
    }

    
    /**
     * Create new event (UPDATED)
     */
    @Transactional
    public EventDTO createEvent(EventDTO eventDTO, String userId) {
        log.debug("Creating event with DTO: {}", eventDTO);

        // Ensure time zone info for start
        if (eventDTO.getStart() == null || eventDTO.getEnd() == null) {
            throw new IllegalStateException("Event must have a start end an end time");
        } else {
            eventDTO.setStart(dateTimeUtils.ensureTimeZone(eventDTO.getStart()));
            eventDTO.setEnd(dateTimeUtils.ensureTimeZone(eventDTO.getEnd()));
        }
        
        // Validate time period
        if (eventDTO.getEnd().isBefore(eventDTO.getStart())) {
            throw new IllegalStateException("End time must be after start time");
        }

        // NOTA: Ho rimosso qui la vecchia validateCustomIsoPermission perché la facciamo dopo in modo più intelligente

        // Get the resource and check if user has access
        Resource resource = resourceRepository.findById(eventDTO.getResourceId())
                .orElseThrow(() -> new EntityNotFoundException("Resource not found with ID: " + eventDTO.getResourceId()));
        
        // Check if user has access to this resource's site
        if (!resourceService.canAccessResource(userId, resource)) {
            throw new AccessDeniedException("You don't have access to book this resource");
        }
        
        // Check for time conflicts
        if (hasTimeConflict(eventDTO.getResourceId(), eventDTO.getStart(), eventDTO.getEnd(), null)) {
            throw new IllegalStateException("The selected time period conflicts with existing bookings");
        }
        
        // Check if the resource is in ACTIVE state
        if (resource.getStatus() != ResourceStatus.ACTIVE) {
            throw new IllegalStateException("Cannot book a resource that is not in ACTIVE state. Current state: " + resource.getStatus());
        }
        
        // If userId is different from event's userId, check if requester is admin
        String eventUserId = eventDTO.getUserId() != null ? eventDTO.getUserId() : userId;
        
        if (!eventUserId.equals(userId)) {
            // Check if the requester is admin for the resource's site
            if (!keycloakService.hasGlobalAdminRole(userId) && 
                !keycloakService.isUserSiteAdmin(userId, resource.getSiteId())) {
                throw new AccessDeniedException("Only administrators can create bookings for other users");
            }
            
            // Check if the target user is in the site
            if (!keycloakService.isUserInGroup(eventUserId, resource.getSiteId())) {
                throw new IllegalStateException("The user must be a member of the resource's site to book it");
            }
        }
        
        // Set the user ID to the actual user if not specified
        if (eventDTO.getUserId() == null) {
            eventDTO.setUserId(userId);
        }
        
        // Verify user exists in Keycloak
        keycloakService.getUserById(eventDTO.getUserId())
            .orElseThrow(() -> new EntityNotFoundException("User not found with Keycloak ID: " + eventDTO.getUserId()));
        
        Event event = eventMapper.toEntity(eventDTO);
        
        // --- NUOVA LOGICA: Risoluzione URL Immagine ---
        resolveProvisioningData(event, eventDTO, userId);
        // ----------------------------------------------
        
        Event savedEvent = eventRepository.save(event);
        
        log.debug("Saved event: {}", savedEvent);
        
        // Get user display name for notification
        String userDisplayName = "Unknown user";
        try {
            Optional<UserRepresentation> user = keycloakService.getUserById(event.getKeycloakId());
            if (user.isPresent()) {
                userDisplayName = user.get().getFirstName() + " " + user.get().getLastName();
            }
        } catch (Exception e) {
            log.warn("Could not fetch user details for notification", e);
        }
        
        // Send notification to resource admin
        notificationService.createSystemNotification(
                "New booking created for " + resource.getName() + " by " + userDisplayName,
                "New booking from " + dateTimeUtils.formatDateTime(eventDTO.getStart()) + 
                " to " + dateTimeUtils.formatDateTime(eventDTO.getEnd())
        );
        
        String siteName = keycloakService.getSiteNameById(savedEvent.getResource().getSiteId(), "Unknown site");

        auditLogService.logCrudAction(AuditLog.LogType.USER,
                AuditLog.LogAction.CREATE,
                new AuditLog.LogEntity("EVENT", savedEvent.getId().toString()),
                "User: " + userId + " created event",
                siteName);
                
        webhookService.processResourceEvent(WebhookEventType.EVENT_CREATED, resource, savedEvent);
        
        return eventMapper.toDto(savedEvent);
    }
    

    /**
     * Update existing event (UPDATED)
     */
    @Transactional
    public Optional<EventDTO> updateEvent(Long id, EventDTO eventDTO, String userId) {
        log.debug("Updating event with ID {} using DTO: {}", id, eventDTO);
        
        // Ensure time zone info for start and end times if provided
        if (eventDTO.getStart() != null) {
            eventDTO.setStart(dateTimeUtils.ensureTimeZone(eventDTO.getStart()));
        }
        
        if (eventDTO.getEnd() != null) {
            eventDTO.setEnd(dateTimeUtils.ensureTimeZone(eventDTO.getEnd()));
        }
        
        return eventRepository.findById(id)
                .map(existingEvent -> {
                    // Check if user has permission to update this event
                    if (!canModifyEvent(userId, existingEvent)) {
                        throw new AccessDeniedException("You don't have permission to update this event");
                    }
                    
                    // If changing resource, check if user has access to the new resource
                    if (eventDTO.getResourceId() != null && 
                        !existingEvent.getResource().getId().equals(eventDTO.getResourceId())) {
                        
                        Resource newResource = resourceRepository.findById(eventDTO.getResourceId())
                                .orElseThrow(() -> new EntityNotFoundException("Resource not found"));
                        
                        if (!resourceService.canAccessResource(userId, newResource)) {
                            throw new AccessDeniedException("You don't have access to the new resource");
                        }
                        
                         // Check if the new resource is in ACTIVE state
                        if (newResource.getStatus() != ResourceStatus.ACTIVE) {
                            throw new IllegalStateException("Cannot book a resource that is not in ACTIVE state.");
                        }

                        existingEvent.setResource(newResource);
                    } else {
                         // Also check if the existing resource is still ACTIVE
                        if (existingEvent.getResource().getStatus() != ResourceStatus.ACTIVE) {
                            throw new IllegalStateException("Cannot update booking for a resource that is not in ACTIVE state.");
                        }
                    }
                    
                    // Update fields
                    if (eventDTO.getTitle() != null) {
                        existingEvent.setTitle(eventDTO.getTitle());
                    }
                    
                    if (eventDTO.getDescription() != null) {
                        existingEvent.setDescription(eventDTO.getDescription());
                    }

                    // --- NUOVA LOGICA UPDATE ---
                    // Se c'è una nuova selezione OS, ricalcoliamo tutto
                    if (eventDTO.getOsSelectionType() != null || eventDTO.getOperatingSystem() != null) {
                         resolveProvisioningData(existingEvent, eventDTO, userId);
                    }
                    // ---------------------------
                    
                    // Only update start and end if provided
                    if (eventDTO.getStart() != null) {
                        existingEvent.setStart(eventDTO.getStart());
                    }
                    
                    if (eventDTO.getEnd() != null) {
                        existingEvent.setEnd(eventDTO.getEnd());
                    }
                    
                    // Validate time period after updates
                    if (existingEvent.getEnd().isBefore(existingEvent.getStart())) {
                        throw new IllegalStateException("End time must be after start time");
                    }
                    
                    // Check for time conflicts (excluding this event)
                    Long resourceId = eventDTO.getResourceId() != null ? eventDTO.getResourceId() : existingEvent.getResource().getId();
                    if (hasTimeConflict(resourceId, existingEvent.getStart(), existingEvent.getEnd(), id)) {
                        throw new IllegalStateException("The selected time period conflicts with existing bookings");
                    }
                    
                    // Update user (Keycloak ID) if provided and requester is admin
                    if (eventDTO.getUserId() != null && !eventDTO.getUserId().equals(existingEvent.getKeycloakId())) {
                        // Only admins can change the user
                        boolean isGlobalAdmin = keycloakService.hasGlobalAdminRole(userId);
                        boolean isSiteAdmin = keycloakService.isUserSiteAdmin(userId, existingEvent.getResource().getSiteId());
                        
                        if (!isGlobalAdmin && !isSiteAdmin) {
                            throw new AccessDeniedException("Only administrators can change the booking owner");
                        }
                        
                        // Verify the new user exists in Keycloak
                        keycloakService.getUserById(eventDTO.getUserId())
                            .orElseThrow(() -> new EntityNotFoundException("User not found with Keycloak ID: " + eventDTO.getUserId()));
                        
                        // Check if the new user is in the site
                        if (!keycloakService.isUserInGroup(eventDTO.getUserId(), existingEvent.getResource().getSiteId())) {
                            throw new IllegalStateException("The new user must be a member of the resource's site");
                        }
                            
                        existingEvent.setKeycloakId(eventDTO.getUserId());
                    }
                    
                    Event updatedEvent = eventRepository.save(existingEvent);
                    String siteName = keycloakService.getSiteNameById(updatedEvent.getResource().getSiteId(), "Unknown site");

                    auditLogService.logCrudAction(AuditLog.LogType.USER,
                            AuditLog.LogAction.UPDATE,
                            new AuditLog.LogEntity("EVENT", updatedEvent.getId().toString()),
                            "User: " + userId + " updated event to: " + updatedEvent,
                            siteName);

                    webhookService.processResourceEvent(WebhookEventType.EVENT_UPDATED, updatedEvent.getResource(), updatedEvent);

                    log.debug("Updated event: {}", updatedEvent);
                    return eventMapper.toDto(updatedEvent);
                });
    }

    /**
     * Delete event if the user has permission to do so
     *
    @Transactional
    public boolean deleteEvent(Long id, String userId) {
        Optional<Event> eventOpt = eventRepository.findById(id);
        
        if (!eventOpt.isPresent()) {
            return false;
        }
        
        Event event = eventOpt.get();
        
        // Check if user has permission to delete this event
        if (!canModifyEvent(userId, event)) {
            throw new AccessDeniedException("You don't have permission to delete this event");
        }

        // Store necessary data before deletion to avoid accessing deleted entity
        String siteName = keycloakService.getSiteNameById(event.getResource().getSiteId(), "Unknown site");
        
        // Create a deep clone of the event for the webhook service to avoid accessing deleted entity
        Event eventClone = createEventClone(event);

        // Delete the entity first to avoid transaction conflicts
        eventRepository.deleteById(id);

        // Log the audit action after successful deletion
        auditLogService.logCrudAction(AuditLog.LogType.USER,
                AuditLog.LogAction.DELETE,
                new AuditLog.LogEntity("EVENT", id.toString()),
                "User: " + userId + " deleted event: " + eventClone.toString(),
                siteName);

        // Process webhook asynchronously after deletion is committed
        webhookService.processResourceEvent(WebhookEventType.EVENT_DELETED, eventClone.getResource(), eventClone);

        return true;
    }
        */

    @Transactional
    public boolean deleteEvent(Long id, String userId) {
        Optional<Event> eventOpt = eventRepository.findById(id);
        
        if (!eventOpt.isPresent()) {
            return false;
        }
        
        Event event = eventOpt.get();
        
        // Check if user has permission to delete this event
        if (!canModifyEvent(userId, event)) {
            throw new AccessDeniedException("You don't have permission to delete this event");
        }

        // Store necessary data before deletion to avoid accessing deleted entity
        String siteName = keycloakService.getSiteNameById(event.getResource().getSiteId(), "Unknown site");
        
        // Create a deep clone of the event for the webhook service to avoid accessing deleted entity
        final Event eventClone = createEventClone(event);

        // Delete the entity
        eventRepository.deleteById(id);

        // Log the audit action
        auditLogService.logCrudAction(AuditLog.LogType.USER,
                AuditLog.LogAction.DELETE,
                new AuditLog.LogEntity("EVENT", id.toString()),
                "User: " + userId + " deleted event: " + eventClone.toString(),
                siteName);

        // CRITICAL FIX: Ensure webhook is fired ONLY AFTER the transaction is fully committed to the DB
        TransactionSynchronizationManager.registerSynchronization(new TransactionSynchronization() {
            @Override
            public void afterCommit() {
                log.info("Transaction committed for deleted event {}. Firing webhook...", eventClone.getId());
                webhookService.processResourceEvent(WebhookEventType.EVENT_DELETED, eventClone.getResource(), eventClone);
            }
        });

        return true;
    }
    /**
     * Check if there's a time conflict for a resource booking
     */
    public boolean hasTimeConflict(Long resourceId, ZonedDateTime start, ZonedDateTime end, Long eventId) {
        // Normalize dates with time zone info
        ZonedDateTime normalizedStart = dateTimeUtils.ensureTimeZone(start);
        ZonedDateTime normalizedEnd = dateTimeUtils.ensureTimeZone(end);
        
        // Get the resource
        Resource resource = resourceRepository.findById(resourceId)
            .orElseThrow(() -> new EntityNotFoundException("Resource not found"));
        
        // Check conflicts for this specific resource
        List<Event> directConflicts = eventRepository.findConflictingEvents(
            resourceId, normalizedStart, normalizedEnd, eventId);
            
        if (!directConflicts.isEmpty()) {
            return true;
        }
        
        // Check if any parent resource is booked during this time
        Resource parent = resource.getParent();
        while (parent != null) {
            List<Event> parentConflicts = eventRepository.findConflictingEvents(
                parent.getId(), normalizedStart, normalizedEnd, eventId);
                
            if (!parentConflicts.isEmpty()) {
                return true;
            }
            
            parent = parent.getParent();
        }
        
        // Check if any child resource is booked during this time
        List<Resource> allSubResources = new ArrayList<>();
        resourceService.collectAllSubResources(resource, allSubResources);
        
        for (Resource subResource : allSubResources) {
            List<Event> childConflicts = eventRepository.findConflictingEvents(
                subResource.getId(), normalizedStart, normalizedEnd, eventId);
                
            if (!childConflicts.isEmpty()) {
                return true;
            }
        }
        
        return false;
    }

    /**
     * Check if a resource is available for booking (is in ACTIVE state) and user has access
     */
    public boolean isResourceAvailableForBooking(Long resourceId, String userId) {
        return resourceRepository.findById(resourceId)
                .map(resource -> 
                    resource.getStatus() == ResourceStatus.ACTIVE && resourceService.canAccessResource(userId, resource)
                )
                .orElse(false);
    }

    /**
     * Check if user can modify an event (owns it or is admin of the resource's site)
     */
    private boolean canModifyEvent(String userId, Event event) {
        // User is the owner of the event
        if (event.getKeycloakId().equals(userId)) {
            return true;
        }
        
        // Global admins can modify all events
        if (keycloakService.hasGlobalAdminRole(userId)) {
            return true;
        }
        
        // Site admins can modify events in their sites
        String siteId = event.getResource().getSiteId();
        return keycloakService.isUserSiteAdmin(userId, siteId);
    }

    /**
     * Check if user can access an event (owns it or is in the resource's site)
     */
    private boolean canAccessEvent(String userId, Event event) {
        // User is the owner of the event
        if (event.getKeycloakId().equals(userId)) {
            return true;
        }
        
        // Global admins can access all events
        if (keycloakService.hasGlobalAdminRole(userId)) {
            return true;
        }
        
        // Check if user is in the event resource's site
        String siteId = event.getResource().getSiteId();
        return keycloakService.isUserInGroup(userId, siteId);
    }


    /**
     * Create a deep clone (UPDATED)
     */
    private Event createEventClone(Event original) {
        Event clone = new Event();
        
        // Copy all primitive fields
        clone.setId(original.getId()); 
        clone.setTitle(original.getTitle());
        clone.setDescription(original.getDescription());
        clone.setStart(original.getStart());
        clone.setEnd(original.getEnd());
        clone.setKeycloakId(original.getKeycloakId());
        clone.setStartNotifiedAt(original.getStartNotifiedAt());
        clone.setEndNotifiedAt(original.getEndNotifiedAt());
        
        // Copy audit fields from parent class
        clone.setCreatedAt(original.getCreatedAt());
        clone.setUpdatedAt(original.getUpdatedAt());
        
        // Create a safe copy of the resource that avoids lazy loading issues
        if (original.getResource() != null) {
            Resource originalResource = original.getResource();
            Resource resourceClone = new Resource();
            
            // Copy basic resource fields without lazy collections
            resourceClone.setId(originalResource.getId());
            resourceClone.setName(originalResource.getName());
            resourceClone.setSpecs(originalResource.getSpecs());
            resourceClone.setLocation(originalResource.getLocation());
            resourceClone.setStatus(originalResource.getStatus());
            resourceClone.setSiteId(originalResource.getSiteId());
            
            // Create a safe copy of the resource type without lazy collections
            if (originalResource.getType() != null) {
                ResourceType originalType = originalResource.getType();
                ResourceType typeClone = new ResourceType();
                typeClone.setId(originalType.getId());
                typeClone.setName(originalType.getName());
                typeClone.setColor(originalType.getColor());
                typeClone.setSiteId(originalType.getSiteId());
                // Don't copy the resources collection to avoid lazy loading issues
                resourceClone.setType(typeClone);
            }
            
            // Don't copy collections (subResources, events) to avoid lazy loading issues
            clone.setResource(resourceClone);
        }
        
        return clone;
    }

    // --- NUOVA LOGICA CORE: RISOLUZIONE URL E CHECKSUM ---
    
    private void resolveProvisioningData(Event event, EventDTO dto, String userId) {
        // Se non c'è il discriminatore, fallback alla vecchia logica (solo label testuale)
        if (dto.getOsSelectionType() == null) {
            if (dto.getOperatingSystem() != null) {
                event.setOperatingSystem(dto.getOperatingSystem());
            }
            return;
        }

        switch (dto.getOsSelectionType()) {
            case "STANDARD":
                // Caso 1: Immagine gestita dall'Admin
                if (dto.getSelectedIsoId() == null) {
                     throw new IllegalArgumentException("Selected ISO ID is mandatory for STANDARD type");
                }
                IsoImage iso = isoImageRepository.findById(dto.getSelectedIsoId())
                        .orElseThrow(() -> new EntityNotFoundException("Selected ISO Image not found"));
                
                if (!iso.getIsActive()) throw new IllegalStateException("Selected ISO is not active");
                if (iso.getImageUrl() == null || iso.getImageUrl().isBlank()) throw new IllegalStateException("Selected ISO has no URL configured");

                event.setImageUrl(iso.getImageUrl());
                event.setChecksumUrl(iso.getChecksumUrl());
                event.setChecksumType(iso.getChecksumType());
                event.setOperatingSystem(iso.getDisplayName()); // Label UI
                break;

            case "FAVORITE":
                // Caso 2: Preferito dell'Utente
                if (dto.getSelectedFavoriteId() == null) {
                    throw new IllegalArgumentException("Selected Favorite ID is mandatory for FAVORITE type");
                }
                UserIsoFavorite fav = userIsoFavoriteRepository.findById(dto.getSelectedFavoriteId())
                        .orElseThrow(() -> new EntityNotFoundException("Favorite not found"));

                // Security check: il preferito deve essere mio
                if (!fav.getUserId().equals(userId)) {
                    throw new AccessDeniedException("You cannot use a favorite that belongs to another user");
                }

                event.setImageUrl(fav.getImageUrl());
                event.setChecksumUrl(fav.getChecksumUrl());
                event.setChecksumType("sha256");
                event.setOperatingSystem(fav.getAlias()); // Label UI
                break;

            case "CUSTOM":
                // Caso 3: URL Custom (Power User)
                // 1. Validazione Formato (CORRETTO QUI: isValidSyntax invece di isValidUrl)
                if (!UrlValidator.isValidSyntax(dto.getCustomImageUrl())) {
                    throw new IllegalArgumentException("Invalid Custom Image URL format");
                }
                if (dto.getCustomChecksumUrl() != null && !dto.getCustomChecksumUrl().isBlank() && !UrlValidator.isValidSyntax(dto.getCustomChecksumUrl())) {
                     throw new IllegalArgumentException("Invalid Custom Checksum URL format");
                }

                // 2. Controllo Permessi
                boolean isGlobalAdmin = keycloakService.hasGlobalAdminRole(userId);
                boolean hasCustomRole = keycloakService.hasRole(userId, ROLE_CUSTOM_ISO_UPLOADER);
                
                if (!isGlobalAdmin && !hasCustomRole) {
                     throw new AccessDeniedException("You do not have permission to use Custom Image URLs. Required role: " + ROLE_CUSTOM_ISO_UPLOADER);
                }

                // 3. Set Dati Evento
                event.setImageUrl(dto.getCustomImageUrl());
                event.setChecksumUrl(dto.getCustomChecksumUrl());
                event.setChecksumType(dto.getCustomChecksumType() != null ? dto.getCustomChecksumType() : "sha256");
                event.setOperatingSystem("Custom: " + (dto.getFavoriteAlias() != null ? dto.getFavoriteAlias() : "User defined"));

                // 4. Salvataggio nei preferiti (Opzionale)
                if (Boolean.TRUE.equals(dto.getSaveAsFavorite()) && dto.getFavoriteAlias() != null && !dto.getFavoriteAlias().isBlank()) {
                    saveNewFavorite(userId, dto.getFavoriteAlias(), dto.getCustomImageUrl(), dto.getCustomChecksumUrl());
                }
                break;

            default:
                throw new IllegalArgumentException("Unknown OS Selection Type: " + dto.getOsSelectionType());
        }
    }
    
    private void saveNewFavorite(String userId, String alias, String url, String checksum) {
        // Evita duplicati di nome per lo stesso user
        if (!userIsoFavoriteRepository.existsByUserIdAndAlias(userId, alias)) {
            UserIsoFavorite fav = new UserIsoFavorite();
            fav.setUserId(userId);
            fav.setAlias(alias);
            fav.setImageUrl(url);
            fav.setChecksumUrl(checksum);
            userIsoFavoriteRepository.save(fav);
        }
    }

}