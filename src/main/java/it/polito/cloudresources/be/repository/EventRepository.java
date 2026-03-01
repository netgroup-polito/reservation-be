package it.polito.cloudresources.be.repository;

import it.polito.cloudresources.be.model.Event;
import it.polito.cloudresources.be.model.Resource;
import org.springframework.data.jpa.repository.JpaRepository;
import org.springframework.data.jpa.repository.Query;
import org.springframework.data.repository.query.Param;
import org.springframework.stereotype.Repository;

import java.time.ZonedDateTime;
import java.util.List;

/**
 * Repository for Event entity operations
 * Now using Keycloak IDs instead of User entities
 * UPDATED: Added filtering for logically deleted events (e.deleted = false)
 */
@Repository
public interface EventRepository extends JpaRepository<Event, Long> {

    /**
     * Override standard findAll to exclude deleted events
     */
    @Query("SELECT e FROM Event e WHERE e.deleted = false")
    List<Event> findAllActive();

    /**
     * Find events by user's Keycloak ID
     */
    @Query("SELECT e FROM Event e WHERE e.keycloakId = :keycloakId AND e.deleted = false")
    List<Event> findByKeycloakId(@Param("keycloakId") String keycloakId);

    /**
     * Find events by resource
     */
    @Query("SELECT e FROM Event e WHERE e.resource = :resource AND e.deleted = false")
    List<Event> findByResource(@Param("resource") Resource resource);

    /**
     * Find events by multiple resource IDs (for site-based filtering)
     */
    @Query("SELECT e FROM Event e WHERE e.resource.id IN :resourceIds AND e.deleted = false")
    List<Event> findByResourceIdIn(@Param("resourceIds") List<Long> resourceIds);

    /**
     * Find events by resource ID
     */
    @Query("SELECT e FROM Event e WHERE e.resource.id = :resourceId AND e.deleted = false")
    List<Event> findByResourceId(@Param("resourceId") Long resourceId);

    /**
     * Find events within a date range
     * Only checks if the event start date is within the range to include long-running events
     */
    @Query("SELECT e FROM Event e WHERE e.start >= :startDate AND e.start <= :endDate AND e.deleted = false")
    List<Event> findByDateRange(
            @Param("startDate") ZonedDateTime startDate,
            @Param("endDate") ZonedDateTime endDate);

    /**
     * Find conflicting events for a resource in a time period
     */
    @Query("SELECT e FROM Event e WHERE e.resource.id = :resourceId " +
            "AND e.deleted = false " +
            "AND ((e.start <= :end AND e.end >= :start) OR " +
            "(e.start >= :start AND e.start <= :end) OR " +
            "(e.end >= :start AND e.end <= :end)) " +
            "AND (e.id != :eventId OR :eventId IS NULL)")
    List<Event> findConflictingEvents(
            @Param("resourceId") Long resourceId,
            @Param("start") ZonedDateTime start,
            @Param("end") ZonedDateTime end,
            @Param("eventId") Long eventId);

    /**
     * @param siteIds
     * @return All events related to the input sites
     */
    @Query("SELECT e FROM Event e JOIN e.resource r WHERE r.siteId IN :siteIds AND e.deleted = false")
    List<Event> findBySiteIds(@Param("siteIds") List<String> siteIds);

    /**
     * @param siteId
     * @return All events related to the input site
     */
    @Query("SELECT e FROM Event e JOIN e.resource r WHERE r.siteId = :siteId AND e.deleted = false")
    List<Event> findBySiteId(@Param("siteId") String siteId);
}