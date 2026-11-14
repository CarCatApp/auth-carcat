package com.carland.carland_auth.config;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties(prefix = "carland.customer-ensure")
public class CustomerEnsureRabbitProperties {
    private String exchange = "customer.ensure";
    private String routingKey = "ensure";
}
