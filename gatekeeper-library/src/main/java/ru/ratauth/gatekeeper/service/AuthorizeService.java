package ru.ratauth.gatekeeper.service;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.security.AuthorizationContext;

public interface AuthorizeService {
    Mono<AuthorizationContext> getAuthorizedUserContextByCode(String clientId, String code, ServerWebExchange exchange);
}
