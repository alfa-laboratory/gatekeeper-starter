package ru.ratauth.gatekeeper.service;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;

public interface RedirectService {
    Mono<Void> sendRedirect(ServerWebExchange exchange, Client client);

    Mono<Void> sendRedirectToAuthorizationPage(ServerWebExchange exchange, Client client);
}
