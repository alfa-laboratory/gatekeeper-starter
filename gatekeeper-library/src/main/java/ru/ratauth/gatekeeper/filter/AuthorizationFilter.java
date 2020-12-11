package ru.ratauth.gatekeeper.filter;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.filter.GlobalFilter;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.core.Ordered;
import org.springframework.http.HttpHeaders;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpRequest;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Component;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponents;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;
import ru.ratauth.gatekeeper.security.ClientAuthorization;
import ru.ratauth.gatekeeper.security.Tokens;
import ru.ratauth.gatekeeper.service.TokenEndpointService;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.time.Instant;
import java.util.LinkedHashSet;
import java.util.Map;
import java.util.Set;
import java.util.stream.Collectors;

import static org.springframework.cloud.gateway.filter.headers.XForwardedHeadersFilter.*;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;
import static ru.ratauth.gatekeeper.security.AuthorizationContext.GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR;

@Component
public class AuthorizationFilter implements GlobalFilter, Ordered {
    private Logger log = LoggerFactory.getLogger(AuthorizationFilter.class);

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
        log.debug("apply gatekeeper authorization filter");
        return authorize(exchange)
                .flatMap(authorizeResult -> {
                    log.info("authorization redirect {}", authorizeResult.success ? "not required" : "required");
                    if (authorizeResult.success) {
                        log.debug("continue filter chain");
                        return chain.filter(exchange);
                    }
                    return sendRedirect(exchange, authorizeResult.client);
                });
    }

    private Mono<AuthorizeResult> authorize(ServerWebExchange exchange) {
        return exchange.getSession()
                .flatMap(session -> {
                    Route route = exchange.getRequiredAttribute(GATEWAY_ROUTE_ATTR);
                    log.info("search client for route id {}", route.getId());
                    Client client = clients.get(route.getId());
                    if (client != null) {
                        log.info("client with id {} found", client.getId());
                        log.debug("start openid connect code flow");

                        AuthorizationContext context = (AuthorizationContext) session.getAttributes()
                                .computeIfAbsent(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, key -> new AuthorizationContext());
                        ClientAuthorization clientAuthorization = context.getClientAuthorizations()
                                .computeIfAbsent(client.getId(), key -> new ClientAuthorization());
                        Tokens clientTokens = clientAuthorization.getTokens();

                        ServerHttpRequest request = exchange.getRequest();
                        URI uri = request.getURI();
                        log.debug("request uri {}", request.getURI());
                        if (uri.getPath().endsWith("/logout")) {
                            log.debug("request path ends with /logout");
                            log.info("perform logout");
                            if (clientTokens != null) {
                                log.debug("clientTokens present");
                                log.debug("send logout request to revocation endpoint and invalidate session");
                                return tokenEndpointService.invalidateRemoteSession(client, uri, clientTokens.getRefreshToken())
                                        .onErrorResume(t -> {
                                            log.warn("cannot revocate tokens by URI " + uri, t);
                                            return Mono.empty();
                                        })
                                        .then(tokenEndpointService.logout(client, clientTokens.getRefreshToken())
                                        .onErrorResume(t -> {
                                            log.warn("clientTokens revocation failed", t);
                                            return Mono.empty();
                                        }))
                                        .then(session.invalidate())
                                        .thenReturn(new AuthorizeResult(false, client));
                            }
                            log.debug("clientTokens is empty");
                            log.debug("invalidate session");
                            return session.invalidate()
                                    .thenReturn(new AuthorizeResult(false, client));
                        }

                        if (clientTokens == null) {
                            log.debug("clientTokens is empty");
                            return saveInitialRequestUri(request, clientAuthorization)
                                    .thenReturn(new AuthorizeResult(false, client));
                        }
                        log.debug("access token value {}", clientTokens.getAccessToken().getValue());
                        Instant now = Instant.now();
                        log.debug("current time {}", now);
                        Instant accessTokenExpirationTime = clientTokens.getAccessTokenExpirationTime();
                        log.debug("access token expiration time {}", accessTokenExpirationTime);
                        if (accessTokenExpirationTime.isBefore(now)) {
                            log.info("access token expired");
                            return refreshToken(client, clientAuthorization, clientTokens, request);
                        }

                        Instant accessTokenLastCheckTime = clientTokens.getAccessTokenLastCheckTime();
                        log.debug("last access token check time {}", accessTokenExpirationTime);
                        Instant checkTokenTime = accessTokenLastCheckTime.plus(Duration.ofSeconds(checkTokenInterval));
                        log.debug("next check token time {}", checkTokenTime);
                        if (checkTokenTime.isBefore(now)) {
                            log.info("need to check access token");
                            return tokenEndpointService.checkAccessToken(client, clientTokens.getAccessToken())
                                    .map(idToken -> {
                                        log.info("success check access token");
                                        log.debug("update id token");
                                        clientTokens.setIdToken(idToken);
                                        clientTokens.setAccessTokenLastCheckTime(Instant.now());
                                        return new AuthorizeResult(true, client);
                                    })
                                    .onErrorResume(t -> {
                                        log.info("access token introspection failed", t);
                                        return refreshToken(client, clientAuthorization, clientTokens, request);
                                    });
                        }
                        log.debug("request success authorized for client: {}", client.getId());
                        return Mono.just(new AuthorizeResult(true, client));
                    }
                    log.info("client not found");
                    log.info("ignore authorization process for this route");
                    return Mono.just(new AuthorizeResult(true, null));
                });
    }

    private Mono<AuthorizeResult> refreshToken(Client client, ClientAuthorization clientAuthorization, Tokens tokens, ServerHttpRequest request) {
        log.info("try to refresh access token");
        log.debug("refresh token {}", tokens.getRefreshToken().getValue());
        return tokenEndpointService.refreshAccessToken(client, tokens.getRefreshToken())
                .map(accessToken -> {
                    log.debug("success refresh token");
                    log.debug("new access token {}", tokens.getAccessToken().getValue());
                    tokens.setAccessToken(accessToken);
                    tokens.setAccessTokenLastCheckTime(Instant.now());
                    return new AuthorizeResult(true, client);
                })
                .doOnError(t -> log.debug("refresh token failed"))
                .onErrorResume(t -> saveInitialRequestUri(request, clientAuthorization)
                        .thenReturn(new AuthorizeResult(false, client))
                );
    }

    private Mono<Void> saveInitialRequestUri(ServerHttpRequest request, ClientAuthorization clientAuthorization) {
        return Mono.fromRunnable(() -> {
            UriComponentsBuilder uriBuilder = UriComponentsBuilder.fromUri(request.getURI());
            HttpHeaders headers = request.getHeaders();
            String proto = headers.getFirst(X_FORWARDED_PROTO_HEADER);
            if (proto != null) {
                log.debug("{} = {}", X_FORWARDED_PROTO_HEADER, proto);
                uriBuilder.scheme(proto);
            }
            String host = headers.getFirst(X_FORWARDED_HOST_HEADER);
            if (host != null) {
                log.debug("{} = {}", X_FORWARDED_HOST_HEADER, host);
                uriBuilder.host(host);
            }
            /*
            TODO: у некоторых команд в этом параметре прилетает порт 80 хотя в X-Forwarded-Proto https
                  из-за невозможности установить причину такого поведения временно делается фикс на нашей стороне
            */
//            String port = headers.getFirst(X_FORWARDED_PORT_HEADER);
//            if (port != null && !port.isBlank()) {
//                log.debug("{} = {}", X_FORWARDED_PORT_HEADER, port);
//                uriBuilder.port(port);
//            }
            String prefix = headers.getFirst(X_FORWARDED_PREFIX_HEADER);
            if (prefix != null) {
                log.debug("{} = {}", X_FORWARDED_PREFIX_HEADER, prefix);
                UriComponents uriComponents = UriComponentsBuilder.fromUriString(prefix).build();
                uriBuilder.replacePath(uriComponents.getPath());
                uriBuilder.replaceQuery(uriComponents.getQuery());
            }
            clientAuthorization.setInitialRequestUri(uriBuilder.build().toUri());
            log.debug("save initial request {}", clientAuthorization.getInitialRequestUri());
        });
    }

    private Mono<Void> sendRedirect(ServerWebExchange exchange, Client client) {
        if (exchange.getRequest().getPath().pathWithinApplication().value().endsWith("/logout")) {
            String endUrl = exchange.getRequest().getQueryParams().getFirst("end_url");
            if (endUrl != null && !endUrl.isBlank()) {
                return sendRedirectToEndUrlPage(exchange, endUrl);
            }
        }
        return sendRedirectToAuthorizationPage(exchange, client);
    }

    private Mono<Void> sendRedirectToAuthorizationPage(ServerWebExchange exchange, Client client) {
        log.info("send redirect to authorization page");

        Set<String> scopes = new LinkedHashSet<>();
        scopes.add("openid");
        scopes.addAll(client.getScope());

        URI location = UriComponentsBuilder.fromUriString(authorizationPageUri)
                .queryParam("response_type", "code")
                .queryParam("client_id", client.getId())
                .queryParam("scope", StringUtils.collectionToDelimitedString(scopes, " "))
                .build()
                .toUri();

        log.debug("authorization redirect uri {}", location.toString());

        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(location);
        });
    }

    private Mono<Void> sendRedirectToEndUrlPage(ServerWebExchange exchange, String pageUri) {
        log.info("send redirect to 'end_url'");

        String decodedURL = pageUri;
        try {
            decodedURL = URLDecoder.decode(pageUri, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            log.error("Cannot decode URL {}", pageUri);
        }

        URI location = UriComponentsBuilder.fromUriString(decodedURL)
                .build()
                .toUri();

        log.debug("'end_url' redirect uri {}", location.toString());

        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(location);
        });
    }

}
