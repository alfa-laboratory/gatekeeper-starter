package ru.ratauth.gatekeeper.filter;

import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;
import ru.ratauth.gatekeeper.security.Tokens;
import ru.ratauth.gatekeeper.service.TokenEndpointService;

import java.net.URI;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.springframework.cloud.gateway.filter.headers.XForwardedHeadersFilter.*;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;
import static ru.ratauth.gatekeeper.security.AuthorizationContext.GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR;

public class AuthorizationFilter implements GlobalFilter, Ordered {
    @Override
    public int getOrder() {
        return -1;
    }

    private final String authorizationPageUri;
    private final long checkTokenInterval;

    private final Map<String, Client> clients;

    private final TokenEndpointService tokenEndpointService;

    public AuthorizationFilter(GatekeeperProperties properties, TokenEndpointService tokenEndpointService) {
        this.authorizationPageUri = properties.getAuthorizationPageUri();
        this.checkTokenInterval = properties.getCheckTokenInterval();
        this.clients = properties.getClients().stream()
                .collect(Collectors.toMap(Client::getId, c -> c));
        this.tokenEndpointService = tokenEndpointService;
    }

    private static class AuthorizeResult {
        private final Client client;
        private final boolean success;

        AuthorizeResult(boolean success, Client client) {
            this.success = success;
            this.client = client;
        }
    }

    @Override
    public Mono<Void> filter(ServerWebExchange exchange, GatewayFilterChain chain) {
        return authorize(exchange)
                .flatMap(authorizeResult -> {
                    if (authorizeResult.success) {
                        return chain.filter(exchange);
                    }
                    return sendRedirectToAuthorizationPage(exchange, authorizeResult.client);
                });
    }

    private Mono<AuthorizeResult> authorize(ServerWebExchange exchange) {
        return exchange.getSession()
                .flatMap(session -> {
                    Route route = exchange.getRequiredAttribute(GATEWAY_ROUTE_ATTR);
                    Client client = clients.get(route.getId());
                    if (client != null) {
                        AuthorizationContext context = session.getAttributeOrDefault(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, new AuthorizationContext());
                        Tokens tokens = context.getTokens();

                        ServerHttpRequest request = exchange.getRequest();
                        String path = request.getPath().pathWithinApplication().value();

                        if (path.endsWith("/logout")) {
                            if (tokens != null) {
                                return tokenEndpointService.logout(client, tokens.getRefreshToken())
                                        .onErrorResume(t -> Mono.empty())
                                        .then(session.invalidate())
                                        .thenReturn(new AuthorizeResult(false, client));
                            }
                            return session.invalidate()
                                    .thenReturn(new AuthorizeResult(false, client));
                        }

                        if (tokens == null) {
                            return saveInitialRequestUri(request, session, context)
                                    .thenReturn(new AuthorizeResult(false, client));
                        }

                        Instant now = Instant.now();
                        Instant accessTokenExpirationTime = tokens.getAccessTokenExpirationTime();
                        if (accessTokenExpirationTime.isBefore(now)) {
                            return tokenEndpointService.refreshAccessToken(client, tokens.getRefreshToken())
                                    .map(accessToken -> {
                                        tokens.setAccessToken(accessToken);
                                        tokens.setAccessTokenLastCheckTime(Instant.now());
                                        return new AuthorizeResult(true, client);
                                    })
                                    .onErrorResume(t -> saveInitialRequestUri(request, session, context)
                                            .thenReturn(new AuthorizeResult(false, client))
                                    );
                        }

                        Instant accessTokenLastCheckTime = tokens.getAccessTokenLastCheckTime();
                        Instant checkTokenTime = accessTokenLastCheckTime.plus(Duration.ofSeconds(checkTokenInterval));
                        if (checkTokenTime.isBefore(now)) {
                            return tokenEndpointService.checkAccessToken(client, tokens.getAccessToken())
                                    .map(idToken -> {
                                        tokens.setIdToken(idToken);
                                        tokens.setAccessTokenLastCheckTime(Instant.now());
                                        return new AuthorizeResult(true, client);
                                    })
                                    .onErrorResume(t1 -> tokenEndpointService.refreshAccessToken(client, tokens.getRefreshToken())
                                            .map(accessToken -> {
                                                tokens.setAccessToken(accessToken);
                                                tokens.setAccessTokenLastCheckTime(Instant.now());
                                                return new AuthorizeResult(true, client);
                                            })
                                            .onErrorResume(t2 -> saveInitialRequestUri(request, session, context)
                                                    .thenReturn(new AuthorizeResult(false, client))
                                            )
                                    );
                        }
                    }
                    return Mono.just(new AuthorizeResult(true, null));
                });
    }

    private Mono<Void> saveInitialRequestUri(ServerHttpRequest request, WebSession session, AuthorizationContext context) {
        return Mono.fromRunnable(() -> {
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUri(request.getURI());
            HttpHeaders headers = request.getHeaders();
            String proto = headers.getFirst(X_FORWARDED_PROTO_HEADER);
            if (proto != null) {
                uriBuilder.scheme(proto);
            }
            String host = headers.getFirst(X_FORWARDED_HOST_HEADER);
            if (host != null) {
                uriBuilder.host(host);
            }
            String port = headers.getFirst(X_FORWARDED_PORT_HEADER);
            if (port != null && !port.isBlank()) {
                uriBuilder.port(port);
            }
            String prefix = headers.getFirst(X_FORWARDED_PREFIX_HEADER);
            if (prefix != null) {
                uriBuilder.replacePath(prefix);
            }

            context.setInitialRequestUri(uriBuilder.build().toUri());
            session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
        });
    }

    private Mono<Void> sendRedirectToAuthorizationPage(ServerWebExchange exchange, Client client) {
        Set<String> scopes = new LinkedHashSet<>();
        scopes.add("openid");
        scopes.addAll(client.getScope());

        URI location = UriComponentsBuilder.fromUriString(authorizationPageUri)
                .queryParam("response_type", "code")
                .queryParam("client_id", client.getId())
                .queryParam("scope", StringUtils.collectionToDelimitedString(scopes, " "))
                .build()
                .toUri();

        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(location);
        });
    }
}
