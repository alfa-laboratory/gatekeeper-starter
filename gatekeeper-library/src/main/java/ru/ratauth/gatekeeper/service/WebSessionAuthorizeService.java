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
import ru.ratauth.gatekeeper.security.ClientAuthorization;

import java.time.Instant;
import java.util.List;
import java.util.Objects;

import static ru.ratauth.gatekeeper.security.AuthorizationContext.GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR;

@Service
public class WebSessionAuthorizeService implements AuthorizeService {
    private final Logger log = LoggerFactory.getLogger(WebSessionAuthorizeService.class);

    private final List<Client> clients;
    private final TokenEndpointService tokenEndpointService;
    private final TokensVerificationService tokensVerificationService;
    private final SessionIdRepository sessionIdRepository;

    public WebSessionAuthorizeService(GatekeeperProperties properties,
                                      TokenEndpointService tokenEndpointService,
                                      TokensVerificationService tokensVerificationService,
                                      SessionIdRepository sessionIdRepository) {
        this.clients = properties.getClients();
        this.tokenEndpointService = tokenEndpointService;
        this.tokensVerificationService = tokensVerificationService;
        this.sessionIdRepository = sessionIdRepository;
    }

    public Mono<AuthorizationContext> getAuthorizedUserContextByCode(String clientId, String code, ServerWebExchange exchange) {
        return exchange.getSession()
                .flatMap(session -> session.changeSessionId().thenReturn(session))
                .flatMap(session -> {
                    log.debug("session id {}", session.getId());
                    log.debug("client id {}", clientId);
                    log.debug("authorization code {}", code);
                    log.debug("get or create authorization context for current session");
                    AuthorizationContext context = (AuthorizationContext) session
                            .getAttributes()
                            .computeIfAbsent(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, key -> new AuthorizationContext());
                    log.debug("check client id for existence");
                    Client client = clients.stream()
                            .filter(c -> Objects.equals(clientId, c.getId()))
                            .findFirst()
                            .orElseThrow();
                    ClientAuthorization clientAuthorization = context.getClientAuthorizations()
                            .computeIfAbsent(client.getId(), key -> new ClientAuthorization());
                    log.debug("initial request uri {}", clientAuthorization.getInitialRequestUri());
                    if (clientAuthorization.getInitialRequestUri() == null) {
                        log.debug("initial request uri is empty");
                        log.debug("send to default page {}", client.getDefaultPageUri());
                        clientAuthorization.setInitialRequestUri(UriComponentsBuilder.fromUriString(client.getDefaultPageUri())
                                .build()
                                .toUri());
                    }

                    return tokenEndpointService.exchangeCodeForTokens(client, code)
                            .flatMap(tokens -> {
                                log.info("success exchange code for tokens");
                                log.debug("try to verify tokens");
                                tokensVerificationService.verifyTokens(tokens, client);
                                log.info("success verify tokens");
                                clientAuthorization.setTokens(tokens);
                                tokens.setAccessTokenLastCheckTime(Instant.now());
                                sessionIdRepository.connectWebSessionWithSessionId(session.getId(), tokens.getSessionId());
                                return Mono.just(context);
                            });
                });
    }
}
