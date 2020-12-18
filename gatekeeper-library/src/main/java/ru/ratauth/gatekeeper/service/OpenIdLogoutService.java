package ru.ratauth.gatekeeper.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;
import ru.ratauth.gatekeeper.security.ClientAuthorization;
import ru.ratauth.gatekeeper.security.Tokens;

import java.util.List;
import java.util.Objects;

import static ru.ratauth.gatekeeper.security.AuthorizationContext.GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR;

@Service
public class OpenIdLogoutService implements LogoutService {
    private final Logger log = LoggerFactory.getLogger(OpenIdLogoutService.class);

    private final List<Client> clients;
    private final TokenEndpointService tokenEndpointService;
    private final RedirectService redirectService;

    public OpenIdLogoutService(GatekeeperProperties properties,
                               TokenEndpointService tokenEndpointService,
                               RedirectService redirectService) {
        this.clients = properties.getClients();
        this.tokenEndpointService = tokenEndpointService;
        this.redirectService = redirectService;
    }


    @Override
    public Mono<Void> performLogout(Client client, ServerWebExchange exchange) {
        return exchange.getSession()
                .flatMap(session -> {
                    log.info("perform logout");
                    if (client != null) {
                        AuthorizationContext context = (AuthorizationContext) session.getAttributes()
                                .computeIfAbsent(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, key -> new AuthorizationContext());
                        ClientAuthorization clientAuthorization = context.getClientAuthorizations()
                                .computeIfAbsent(client.getId(), key -> new ClientAuthorization());
                        Tokens clientTokens = clientAuthorization.getTokens();
                        if (clientTokens != null) {
                            log.debug("clientTokens present");
                            log.debug("send logout request to revocation endpoint and invalidate session");
                            return tokenEndpointService.logout(client, clientTokens.getRefreshToken())
                                    .onErrorResume(t -> {
                                        log.warn("clientTokens revocation failed", t);
                                        return Mono.empty();
                                    })
                                    .then(session.invalidate());
                        }

                        log.debug("clientTokens is empty");
                        log.debug("invalidate session");
                        return session.invalidate().then(Mono.empty());
                    }
                    return Mono.empty();
                });
    }

    @Override
    public Mono<Void> performLogoutAndRedirect(String clientId, ServerWebExchange exchange) {
        Client client = clients.stream()
                .filter(c -> Objects.equals(clientId, c.getId()))
                .findFirst().orElseThrow();
        return performLogout(client, exchange)
                .then(redirectService.sendRedirect(exchange, client));
    }
}
