package ru.ratauth.gatekeeper.autoconfigure;

import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.ComponentScan;
import org.springframework.context.annotation.Configuration;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Hooks;
import reactor.core.publisher.Operators;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;

@Configuration
@EnableConfigurationProperties(GatekeeperProperties.class)
@ComponentScan(basePackages = "ru.ratauth.gatekeeper")
public class GatekeeperAutoConfiguration {
    private String MDC_CONTEXT_REACTOR_KEY = GatekeeperAutoConfiguration.class.getName();

    @Bean
    @ConditionalOnMissingBean(WebClient.class)
    public WebClient defaultWebClient() {
        return WebClient.create();
    }

    @PostConstruct
    private void contextOperatorHook() {
        Hooks.onEachOperator(MDC_CONTEXT_REACTOR_KEY,
                Operators.lift((scannable, coreSubscriber) -> new MdcContextLifter<>(coreSubscriber))
        );
    }

    @PreDestroy
    private void cleanupHook() {
        Hooks.resetOnEachOperator(MDC_CONTEXT_REACTOR_KEY);
    }
}
