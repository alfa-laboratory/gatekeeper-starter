package ru.ratauth.gatekeeper.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;

@Configuration
@EnableConfigurationProperties(GatekeeperProperties.class)
@ComponentScan(basePackages = "ru.ratauth.gatekeeper")
public class GatekeeperAutoConfiguration {
    @Bean
    @ConditionalOnMissingBean(WebClient.class)
    public WebClient defaultWebClient() {
        return WebClient.create();
    }
}
