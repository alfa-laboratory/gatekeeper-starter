package ru.ratauth.gatekeeper.service;

import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;

public interface LogoutService {
    Mono<Void> performLogout(Client client, ServerWebExchange exchange);

    Mono<Void> performLogoutAndRedirect(String clientId, ServerWebExchange exchange);
}
