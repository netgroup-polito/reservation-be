package it.polito.cloudresources.be.dto;

import com.fasterxml.jackson.annotation.JsonFormat;
import it.polito.cloudresources.be.model.AuditLog;
import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

import java.time.ZonedDateTime;

/**
 * DTO for AuditLog data transfer
 */
@Data
@NoArgsConstructor
@AllArgsConstructor
public class AuditLogDTO {
    private Long id;

    @JsonFormat(shape = JsonFormat.Shape.STRING, pattern = "yyyy-MM-dd'T'HH:mm:ss.SSSX")
    private ZonedDateTime timestamp;
    private String username;
    private String siteName;
    private AuditLog.LogType logType;
    private String entityType;
    private AuditLog.LogAction action;
    private String entityId;
    private String details;
    private AuditLog.LogSeverity severity;

    // Calculated field for display in UI
    //private String shortDetails;

    public String getShortDetails() {
        if (details == null || details.length() <= 50) {
            return details;
        }
        return details.substring(0, 47) + "...";
    }
}