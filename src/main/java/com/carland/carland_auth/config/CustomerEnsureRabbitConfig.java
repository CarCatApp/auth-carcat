package com.carland.carland_auth.config;

import org.springframework.amqp.core.DirectExchange;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Auth only publishes. Queue / retry / DLQ topology lives on carland-service.
 */
@Configuration
@EnableConfigurationProperties(CustomerEnsureRabbitProperties.class)
public class CustomerEnsureRabbitConfig {

    @Bean
    DirectExchange customerEnsureExchange(CustomerEnsureRabbitProperties props) {
        return new DirectExchange(props.getExchange(), true, false);
    }
}
