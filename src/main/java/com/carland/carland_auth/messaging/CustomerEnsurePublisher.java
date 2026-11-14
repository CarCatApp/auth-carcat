package com.carland.carland_auth.messaging;

import com.carland.carland_auth.config.CustomerEnsureRabbitProperties;
import com.carland.carland_auth.enums.UserRoles;
import com.fasterxml.jackson.databind.ObjectMapper;
import lombok.RequiredArgsConstructor;
import lombok.extern.slf4j.Slf4j;
import org.springframework.amqp.core.Message;
import org.springframework.amqp.core.MessageBuilder;
import org.springframework.amqp.core.MessageProperties;
import org.springframework.amqp.rabbit.core.RabbitTemplate;
import org.springframework.stereotype.Service;

/**
 * After USER becomes ACTIVE (PIN set / login), ask carland to ensure a customers row.
 * Never throws — PIN/login must succeed even if Rabbit is briefly down.
 */
@Service
@RequiredArgsConstructor
@Slf4j
public class CustomerEnsurePublisher {

    private final RabbitTemplate rabbitTemplate;
    private final CustomerEnsureRabbitProperties props;
    private final ObjectMapper objectMapper;

    public void publishForAppUser(Long userId, String phoneNumber, String role, String acceptLanguage) {
        if (userId == null || phoneNumber == null || phoneNumber.isBlank()) {
            return;
        }
        if (role == null || !UserRoles.USER.name().equalsIgnoreCase(role.trim())) {
            return;
        }
        try {
            EnsureCustomerMessage payload = new EnsureCustomerMessage(
                    userId,
                    phoneNumber.trim(),
                    acceptLanguage == null || acceptLanguage.isBlank() ? "az" : acceptLanguage,
                    0);
            byte[] body = objectMapper.writeValueAsBytes(payload);
            Message message = MessageBuilder.withBody(body)
                    .setContentType(MessageProperties.CONTENT_TYPE_JSON)
                    .build();
            rabbitTemplate.send(props.getExchange(), props.getRoutingKey(), message);
            log.info("[customer-ensure] published userId={} phone={}", userId, phoneNumber);
        } catch (Exception e) {
            log.warn("[customer-ensure] publish failed userId={}: {}", userId, e.toString());
        }
    }
}
