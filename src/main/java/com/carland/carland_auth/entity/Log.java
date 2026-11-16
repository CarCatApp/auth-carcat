package com.carland.carland_auth.entity;

import jakarta.persistence.*;
import lombok.*;
import lombok.experimental.FieldDefaults;

import java.time.LocalDateTime;

/**
 * Session / auth-flow diagnostic log (login–logout teşhisi).
 * Request/response bodies are stored sanitized (PIN/JWT redacted).
 */
@Entity
@Data
@Builder
@NoArgsConstructor
@AllArgsConstructor
@FieldDefaults(level = AccessLevel.PRIVATE)
@Table(name = "logs", indexes = {
        @Index(name = "idx_logs_created_at", columnList = "created_at"),
        @Index(name = "idx_logs_phone", columnList = "phone_number"),
        @Index(name = "idx_logs_user_id", columnList = "user_id"),
        @Index(name = "idx_logs_trace", columnList = "trace_id"),
        @Index(name = "idx_logs_action", columnList = "action")
})
public class Log {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    @Column(name = "log_id")
    Long logId;

    @Column(name = "created_at", nullable = false)
    LocalDateTime createdAt;

    /** Correlates HTTP filter row + in-service step rows for one call. */
    @Column(name = "trace_id", length = 64)
    String traceId;

    /** HTTP (filter) or STEP (service). */
    @Column(name = "source", length = 16)
    String source;

    /** AUTH, OTP_SEND, OTP_VERIFY, SET_PIN, LOGIN, REFRESH, REVOKE, … */
    @Column(name = "action", length = 64)
    String action;

    @Column(name = "user_id", length = 64)
    String userId;

    @Column(name = "phone_number", length = 32)
    String phoneNumber;

    @Column(name = "device_id", length = 256)
    String deviceId;

    @Column(name = "purpose", length = 64)
    String purpose;

    @Column(name = "http_method", length = 16)
    String httpMethod;

    @Column(name = "path", length = 256)
    String path;

    @Column(name = "http_status")
    Integer httpStatus;

    @Column(name = "error_code", length = 128)
    String errorCode;

    @Column(name = "error_message", length = 1024)
    String errorMessage;

    @Column(name = "request_body", columnDefinition = "TEXT")
    String requestBody;

    @Column(name = "response_body", columnDefinition = "TEXT")
    String responseBody;

    /** Free-form: revoke count, next=PIN_CHECK, refresh rejected reason, … */
    @Column(name = "detail", columnDefinition = "TEXT")
    String detail;

    @Column(name = "client_ip", length = 64)
    String clientIp;
}
