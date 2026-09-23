package com.carland.carland_auth.staff;

import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.http.HttpEntity;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.client.RestTemplate;

import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * tr: Staff OTP / şifre maili. Gövdeyi loglama.
 * en: Staff OTP / password mail. Do not log the body.
 */
@Service
@Slf4j
public class StaffMailSender {

    private static final String BREVO_URL = "https://api.brevo.com/v3/smtp/email";

    private final RestTemplate restTemplate = new RestTemplate();

    @Value("${brevo.api-key:}")
    private String brevoApiKey;

    public void sendHtml(String toEmail, String subject, String htmlContent) {
        if (toEmail == null || toEmail.isBlank()) {
            throw new IllegalStateException("email missing");
        }
        if (brevoApiKey == null || brevoApiKey.isBlank()) {
            throw new IllegalStateException("BREVO_API_KEY missing");
        }
        Map<String, Object> body = new HashMap<>();
        body.put("sender", Map.of("name", "CarCat", "email", "noreply@digital-innovation.agency"));
        body.put("to", List.of(Map.of("email", toEmail)));
        body.put("subject", subject);
        body.put("htmlContent", htmlContent);
        HttpHeaders headers = new HttpHeaders();
        headers.setContentType(MediaType.APPLICATION_JSON);
        headers.setAccept(List.of(MediaType.APPLICATION_JSON));
        headers.add("api-key", brevoApiKey);
        restTemplate.postForEntity(BREVO_URL, new HttpEntity<>(body, headers), String.class);
        log.info("STAFF_MAIL_SENT");
    }
}
