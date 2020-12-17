package ru.ratauth.gatekeeper.service;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.filter.AuthorizationFilter;
import ru.ratauth.gatekeeper.properties.Client;

public interface LogoutService {
    Mono<AuthorizationFilter.AuthorizeResult> performLogout(Client client, WebSession session);

    Mono<Void> performLogoutAndRedirect(String clientId, ServerWebExchange exchange);
}
