package ru.ratauth.gatekeeper.controller;

import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;
import ru.ratauth.gatekeeper.service.AuthorizeService;

import java.net.URI;

@RestController
public class CallbackController {
    private final AuthorizeService authorizeService;
    private final URI errorPageUri;

    public CallbackController(AuthorizeService authorizeService, GatekeeperProperties properties) {
        this.authorizeService = authorizeService;
        this.errorPageUri = URI.create(properties.getErrorPageUri());
    }

    @GetMapping("/openid/authorize/{client_id}")
    public Mono<ResponseEntity<String>> callback(@PathVariable("client_id") String clientId, @RequestParam String code, ServerWebExchange exchange) {
        return authorizeService.getAuthorizedUserContextByCode(clientId, code, exchange)
                .map(AuthorizationContext::getInitialRequestUri)
                .onErrorReturn(errorPageUri)
                .map(location -> ResponseEntity.status(HttpStatus.FOUND)
                        .location(location)
                        .build());
    }
}
