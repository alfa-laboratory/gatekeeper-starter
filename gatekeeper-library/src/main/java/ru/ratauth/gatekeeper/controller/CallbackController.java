package ru.ratauth.gatekeeper.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;
import ru.ratauth.gatekeeper.service.AuthorizeService;

import java.net.URI;

public class CallbackController {
    private final AuthorizeService authorizeService;
    private final URI errorPageUri;

    public CallbackController(AuthorizeService authorizeService, GatekeeperProperties properties) {
        this.authorizeService = authorizeService;
        this.errorPageUri = URI.create(properties.getErrorPageUri());
    }

    public Mono<ResponseEntity<String>> callback(String clientId, String code, ServerWebExchange exchange) {
        return authorizeService.getAuthorizedUserContextByCode(clientId, code, exchange)
                .map(AuthorizationContext::getInitialRequestUri)
                .onErrorReturn(errorPageUri)
                .map(location -> ResponseEntity.status(HttpStatus.FOUND)
                        .location(location)
                        .build());
    }
}
