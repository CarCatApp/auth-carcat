package com.carland.carland_auth.messaging;

import com.fasterxml.jackson.annotation.JsonIgnoreProperties;

/** Same JSON shape as carland_service EnsureCustomerMessage. */
@JsonIgnoreProperties(ignoreUnknown = true)
public record EnsureCustomerMessage(
        Long userId,
        String phoneNumber,
        String acceptLanguage,
        int attempt
) {
}
