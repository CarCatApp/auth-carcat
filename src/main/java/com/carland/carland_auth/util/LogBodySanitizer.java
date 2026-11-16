package com.carland.carland_auth.util;

import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.node.ObjectNode;
import lombok.RequiredArgsConstructor;
import org.springframework.stereotype.Component;

import java.util.Iterator;
import java.util.Locale;
import java.util.Map;
import java.util.Set;

/**
 * Redacts secrets before persisting auth flow logs.
 */
@Component
@RequiredArgsConstructor
public class LogBodySanitizer {

    private static final Set<String> SECRET_KEYS = Set.of(
            "password", "pin", "pincode", "pin_code",
            "pinsetuptoken", "authtoken", "authenticationtoken", "registertoken",
            "accesstoken", "refreshtoken", "authorization", "token"
    );

    private final ObjectMapper objectMapper;

    public String sanitizeJsonOrText(String raw) {
        if (raw == null || raw.isBlank()) {
            return raw;
        }
        String trimmed = raw.trim();
        if (!(trimmed.startsWith("{") || trimmed.startsWith("["))) {
            return redactJwtLike(trimmed);
        }
        try {
            JsonNode node = objectMapper.readTree(trimmed);
            sanitizeNode(node);
            return objectMapper.writeValueAsString(node);
        } catch (Exception e) {
            return redactJwtLike(trimmed);
        }
    }

    public String shortDeviceId(String deviceId) {
        if (deviceId == null || deviceId.isBlank()) {
            return null;
        }
        if (deviceId.length() <= 48) {
            return deviceId;
        }
        return deviceId.substring(0, 40) + "…(len=" + deviceId.length() + ")";
    }

    private void sanitizeNode(JsonNode node) {
        if (node == null) {
            return;
        }
        if (node.isObject()) {
            ObjectNode obj = (ObjectNode) node;
            Iterator<Map.Entry<String, JsonNode>> fields = obj.fields();
            while (fields.hasNext()) {
                Map.Entry<String, JsonNode> e = fields.next();
                String key = e.getKey();
                JsonNode value = e.getValue();
                if (isSecretKey(key)) {
                    obj.put(key, redactValue(value == null ? null : value.asText()));
                } else if (value != null && (value.isObject() || value.isArray())) {
                    sanitizeNode(value);
                } else if (value != null && value.isTextual() && looksLikeJwt(value.asText())) {
                    obj.put(key, redactValue(value.asText()));
                }
            }
        } else if (node.isArray()) {
            for (JsonNode child : node) {
                sanitizeNode(child);
            }
        }
    }

    private static boolean isSecretKey(String key) {
        if (key == null) {
            return false;
        }
        String k = key.toLowerCase(Locale.ROOT).replace("-", "").replace("_", "");
        return SECRET_KEYS.contains(k);
    }

    private static boolean looksLikeJwt(String s) {
        if (s == null || s.length() < 40) {
            return false;
        }
        String t = s.startsWith("Bearer ") ? s.substring(7) : s;
        int dots = 0;
        for (int i = 0; i < t.length(); i++) {
            if (t.charAt(i) == '.') {
                dots++;
            }
        }
        return dots == 2 && t.length() > 40;
    }

    private static String redactValue(String s) {
        if (s == null || s.isBlank()) {
            return "***";
        }
        String t = s.startsWith("Bearer ") ? s.substring(7) : s;
        if (t.length() <= 12) {
            return "***";
        }
        return t.substring(0, 8) + "…***";
    }

    private static String redactJwtLike(String s) {
        if (looksLikeJwt(s) || (s != null && s.startsWith("Bearer "))) {
            return redactValue(s);
        }
        return s;
    }
}
