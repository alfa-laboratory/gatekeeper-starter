package ru.ratauth.gatekeeper.filter;

import lombok.extern.slf4j.Slf4j;
import org.slf4j.MDC;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.core.Ordered;
import org.springframework.stereotype.Component;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.security.AuthorizationContext;

import java.text.ParseException;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

import static ru.ratauth.gatekeeper.security.AuthorizationContext.GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR;

@Slf4j
@Component
public class LogFilter implements GlobalFilter, Ordered {
    private static final String LOG_CONTEXT_MAP = "log-context-map";

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        Map<String, String> logContextMap = new ConcurrentHashMap<>();
        return exchange.getSession()
                .flatMap(session -> {
                    try {
                        AuthorizationContext authContext = session.getAttribute(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR);
                        if (authContext != null) {
                            authContext.getClientAuthorizations()
                                    .values().stream()
                                    .findAny()
                                    .ifPresent(authorization -> {
                                        try {
                                            String subject = authorization.getTokens().getIdToken().getJWTClaimsSet().getSubject();
                                            logContextMap.put("user_id", subject);
                                            MDC.put("user_id", subject);
                                        } catch (ParseException e) {
                                            log.error("", e);
                                        }
                                    });
                        }
                    } catch (Exception e) {
                        log.error("", e);
                    }

                    return chain.filter(exchange).subscriberContext(context -> context.put(LOG_CONTEXT_MAP, logContextMap));
                });
    }

    @Override
    public int getOrder() {
        return -2;
    }
}
