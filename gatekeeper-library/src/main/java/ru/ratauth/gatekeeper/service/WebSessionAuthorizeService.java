package ru.ratauth.gatekeeper.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
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

@Service
public class WebSessionAuthorizeService implements AuthorizeService {
    private Logger log = LoggerFactory.getLogger(WebSessionAuthorizeService.class);

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
                    log.debug("session id {}", session.getId());
                    log.debug("client id {}", clientId);
                    log.debug("authorization code {}", code);
                    log.debug("get or create authorization context for current session");
                    AuthorizationContext context = session.getAttributeOrDefault(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, new AuthorizationContext());
                    log.debug("check client id for existence");
                    Client client = clients.stream()
                            .filter(c -> Objects.equals(clientId, c.getId()))
                            .findFirst()
                            .orElseThrow();
                    log.debug("initial request uri {}", context.getInitialRequestUri());
                    if (context.getInitialRequestUri() == null) {
                        log.debug("initial request uri is empty");
                        log.debug("send to default page {}", client.getDefaultPageUri());
                        context.setInitialRequestUri(UriComponentsBuilder.fromUriString(client.getDefaultPageUri())
                                .build()
                                .toUri());
                    }

                    return tokenEndpointService.exchangeCodeForTokens(client, code)
                            .flatMap(tokens -> {
                                log.info("success exchange code for tokens");
                                log.debug("try to verify tokens");
                                tokensVerificationService.verifyTokens(tokens, client);
                                log.info("success verify tokens");
                                context.setTokens(tokens);
                                tokens.setAccessTokenLastCheckTime(Instant.now());
                                return Mono.just(context);
                            });
                });
    }
}
