package ru.ratauth.gatekeeper.service;

import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import static ru.ratauth.gatekeeper.security.AuthorizationContext.GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR;

public class WebSessionAuthorizeService implements AuthorizeService {
    private final List<Client> clients;
    private final TokenEndpointService tokenEndpointService;
    private final TokensVerificationService tokensVerificationService;

    public WebSessionAuthorizeService(GatekeeperProperties properties, TokenEndpointService tokenEndpointService, TokensVerificationService tokensVerificationService) {
        this.clients = properties.getClients();
        this.tokenEndpointService = tokenEndpointService;
        this.tokensVerificationService = tokensVerificationService;
    }

    public Mono<AuthorizationContext> getAuthorizedUserContextByCode(String clientId, String code, ServerWebExchange exchange) {
        return exchange.getSession()
                .flatMap(session -> session.changeSessionId().thenReturn(session))
                .flatMap(session -> {
                    AuthorizationContext context = session.getAttributeOrDefault(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, new AuthorizationContext());

                    Client client = clients.stream()
                            .filter(c -> Objects.equals(clientId, c.getId()))
                            .findFirst()
                            .orElseThrow();

                    if (context.getInitialRequestUri() == null) {
                        context.setInitialRequestUri(UriComponentsBuilder.fromUriString(client.getDefaultPageUri())
                                .build()
                                .toUri());
                    }

                    return tokenEndpointService.exchangeCodeForTokens(client, code)
                            .flatMap(tokens -> {
                                tokensVerificationService.verifyTokens(tokens, client);
                                context.setTokens(tokens);
                                tokens.setAccessTokenLastCheckTime(Instant.now());
                                return Mono.just(context);
                            });
                });
    }
}
