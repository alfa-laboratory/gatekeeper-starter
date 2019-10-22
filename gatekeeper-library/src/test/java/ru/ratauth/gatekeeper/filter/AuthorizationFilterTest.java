package ru.ratauth.gatekeeper.filter;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.Before;
import org.junit.Test;
import org.springframework.cloud.gateway.filter.GatewayFilterChain;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.util.MultiValueMap;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import reactor.test.StepVerifier;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;
import ru.ratauth.gatekeeper.security.Tokens;
import ru.ratauth.gatekeeper.service.TokenEndpointService;

import java.time.Duration;
import java.time.Instant;
import java.util.HashSet;
import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.cloud.gateway.filter.headers.XForwardedHeadersFilter.*;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;
import static org.springframework.http.HttpStatus.FOUND;
import static ru.ratauth.gatekeeper.security.AuthorizationContext.GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR;

public class AuthorizationFilterTest {
    private static final String AUTHORIZATION_PAGE_URI = "https://authorization-server.com/authorize";
    private static final String CLIENT_ID = "test-app";
    private static final Set<String> SCOPES = Set.of("roles", "profile");

    private static final String INITIAL_REQUEST_URI = "https://gateway.com/sample-app/dashboard";
    private static final String NEXT_FILTER_EXCEPTION_MESSAGE = "Next filter called!";

    private static final BearerAccessToken NOT_EXPIRED_ACCESS_TOKEN = new BearerAccessToken(3600L, null);
    private static final BearerAccessToken EXPIRED_ACCESS_TOKEN = new BearerAccessToken(0L, null);
    private static final Instant NOT_EXPIRED_LAST_CHECK_TIME = Instant.now().plus(Duration.ofDays(30L));
    private static final Instant EXPIRED_LAST_CHECK_TIME = Instant.now().minus(Duration.ofDays(30L));

    private MockServerWebExchange exchange;
    private Route route;
    private GatewayFilterChain chain;
    private TokenEndpointService tokenEndpointService;
    private AuthorizationFilter filter;

    @Before
    public void init() {
        GatekeeperProperties properties = new GatekeeperProperties();
        properties.setAuthorizationPageUri(AUTHORIZATION_PAGE_URI);
        Client client = new Client();
        client.setId(CLIENT_ID);
        client.setScope(SCOPES);
        properties.setClients(List.of(client));
        exchange = MockServerWebExchange.from(MockServerHttpRequest.get(INITIAL_REQUEST_URI));
        route = mock(Route.class);
        when(route.getId()).thenReturn(CLIENT_ID);
        exchange.getAttributes().put(GATEWAY_ROUTE_ATTR, route);
        chain = e -> {
            throw new RuntimeException(NEXT_FILTER_EXCEPTION_MESSAGE);
        };
        tokenEndpointService = mock(TokenEndpointService.class);
        filter = new AuthorizationFilter(properties, tokenEndpointService);
    }

    private void checkAuthorizationRedirect() {
        ServerHttpResponse response = exchange.getResponse();
        assertEquals(FOUND, response.getStatusCode());

        String redirectUri = requireNonNull(response.getHeaders().getLocation()).toString();
        assertTrue(redirectUri.startsWith(AUTHORIZATION_PAGE_URI));

        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUriString(redirectUri)
                .build()
                .getQueryParams();
        assertEquals(3, queryParams.size());
        assertEquals("code", queryParams.getFirst("response_type"));
        assertEquals(CLIENT_ID, queryParams.getFirst("client_id"));
        Set<String> scopes = Set.of(requireNonNull(queryParams.getFirst("scope")).split("%20"));
        Set<String> expectedScopes = new HashSet<>();
        expectedScopes.add("openid");
        expectedScopes.addAll(SCOPES);
        assertEquals(expectedScopes, scopes);
    }

    @Test
    public void shouldBePreFilter() {
        int preFilterOrder = -1;
        assertEquals(preFilterOrder, filter.getOrder());
    }

    @Test
    public void shouldContinueChainIfClientNotFoundForRoute() {
        when(route.getId()).thenReturn("other-app");

        StepVerifier.create(filter.filter(exchange, chain))
                .expectErrorMessage(NEXT_FILTER_EXCEPTION_MESSAGE)
                .verify();
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfTokensEmpty() {
        filter.filter(exchange, null).block();

        checkAuthorizationRedirect();

        assertEquals(INITIAL_REQUEST_URI, getContext().getInitialRequestUri().toString());
    }

    private AuthorizationContext getContext() {
        WebSession session = exchange.getSession().block();
        assert session != null;
        return session.getAttribute(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR);
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfTokensEmptyAndForwardedForHeadersPresent() {
        exchange = MockServerWebExchange.from(MockServerHttpRequest.get(INITIAL_REQUEST_URI)
                .header(X_FORWARDED_PROTO_HEADER, "http")
                .header(X_FORWARDED_HOST_HEADER, "forwarded-host")
                .header(X_FORWARDED_PORT_HEADER, "666")
                .header(X_FORWARDED_PREFIX_HEADER, "/forwarded-path?proxy=true")
        );
        exchange.getAttributes().put(GATEWAY_ROUTE_ATTR, route);

        filter.filter(exchange, null).block();

        checkAuthorizationRedirect();

        assertEquals("http://forwarded-host:666/forwarded-path?proxy=true", getContext().getInitialRequestUri().toString());
    }

    @Test
    public void shouldContinueChainIfAccessTokenNotExpired() {
        exchange.getSession()
                .doOnNext(session -> {
                    AuthorizationContext context = new AuthorizationContext();
                    Tokens tokens = new Tokens();
                    tokens.setAccessToken(NOT_EXPIRED_ACCESS_TOKEN);
                    tokens.setAccessTokenLastCheckTime(NOT_EXPIRED_LAST_CHECK_TIME);
                    context.setTokens(tokens);
                    session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
                })
                .block();

        StepVerifier.create(filter.filter(exchange, chain))
                .expectErrorMessage(NEXT_FILTER_EXCEPTION_MESSAGE)
                .verify();
    }

    @Test
    public void shouldContinueChainIfExpirationTimeHasComeAndSuccessRefresh() {
        BearerAccessToken newAccessToken = new BearerAccessToken();
        when(tokenEndpointService.refreshAccessToken(any(), any())).thenReturn(Mono.just(newAccessToken));

        Tokens tokens = new Tokens();
        exchange.getSession()
                .doOnNext(session -> {
                    AuthorizationContext context = new AuthorizationContext();
                    tokens.setRefreshToken(new RefreshToken());
                    tokens.setAccessToken(EXPIRED_ACCESS_TOKEN);
                    tokens.setAccessTokenLastCheckTime(NOT_EXPIRED_LAST_CHECK_TIME);
                    context.setTokens(tokens);
                    session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
                })
                .block();

        StepVerifier.create(filter.filter(exchange, chain))
                .expectErrorMessage(NEXT_FILTER_EXCEPTION_MESSAGE)
                .verify();
        assertEquals(newAccessToken, tokens.getAccessToken());
        assertNotEquals(NOT_EXPIRED_LAST_CHECK_TIME, tokens.getAccessTokenLastCheckTime());
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfExpirationTimeHasComeAndFailRefresh() {
        when(tokenEndpointService.refreshAccessToken(any(), any())).thenReturn(Mono.error(new RuntimeException()));

        exchange.getSession()
                .doOnNext(session -> {
                    Tokens tokens = new Tokens();
                    AuthorizationContext context = new AuthorizationContext();
                    tokens.setRefreshToken(new RefreshToken());
                    tokens.setAccessToken(EXPIRED_ACCESS_TOKEN);
                    tokens.setAccessTokenLastCheckTime(NOT_EXPIRED_LAST_CHECK_TIME);
                    context.setTokens(tokens);
                    session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
                })
                .block();

        filter.filter(exchange, null).block();

        checkAuthorizationRedirect();

        assertEquals(INITIAL_REQUEST_URI, getContext().getInitialRequestUri().toString());
    }

    @Test
    public void shouldContinueChainIfCheckTokenTimeHasComeAndSuccessIntrospect() {
        SignedJWT newIdToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), new JWTClaimsSet.Builder().build());
        when(tokenEndpointService.checkAccessToken(any(), any())).thenReturn(Mono.just(newIdToken));

        Tokens tokens = new Tokens();
        exchange.getSession()
                .doOnNext(session -> {
                    AuthorizationContext context = new AuthorizationContext();
                    tokens.setAccessToken(NOT_EXPIRED_ACCESS_TOKEN);
                    tokens.setAccessTokenLastCheckTime(EXPIRED_LAST_CHECK_TIME);
                    context.setTokens(tokens);
                    session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
                })
                .block();

        StepVerifier.create(filter.filter(exchange, chain))
                .expectErrorMessage(NEXT_FILTER_EXCEPTION_MESSAGE)
                .verify();
        assertEquals(newIdToken, tokens.getIdToken());
        assertTrue(EXPIRED_LAST_CHECK_TIME.isBefore(tokens.getAccessTokenLastCheckTime()));
    }

    @Test
    public void shouldContinueChainIfCheckTokenTimeHasComeFailIntrospectAndSuccessRefresh() {
        when(tokenEndpointService.checkAccessToken(any(), any())).thenReturn(Mono.error(new RuntimeException()));
        BearerAccessToken newAccessToken = new BearerAccessToken();
        when(tokenEndpointService.refreshAccessToken(any(), any())).thenReturn(Mono.just(newAccessToken));

        Tokens tokens = new Tokens();
        exchange.getSession()
                .doOnNext(session -> {
                    AuthorizationContext context = new AuthorizationContext();
                    tokens.setRefreshToken(new RefreshToken());
                    tokens.setAccessToken(NOT_EXPIRED_ACCESS_TOKEN);
                    tokens.setAccessTokenLastCheckTime(EXPIRED_LAST_CHECK_TIME);
                    context.setTokens(tokens);
                    session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
                })
                .block();

        StepVerifier.create(filter.filter(exchange, chain))
                .expectErrorMessage(NEXT_FILTER_EXCEPTION_MESSAGE)
                .verify();
        assertEquals(newAccessToken, tokens.getAccessToken());
        assertTrue(EXPIRED_LAST_CHECK_TIME.isBefore(tokens.getAccessTokenLastCheckTime()));
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfCheckTokenTimeHasComeFailIntrospectAndFailRefresh() {
        when(tokenEndpointService.checkAccessToken(any(), any())).thenReturn(Mono.error(new RuntimeException()));
        when(tokenEndpointService.refreshAccessToken(any(), any())).thenReturn(Mono.error(new RuntimeException()));

        Tokens tokens = new Tokens();
        exchange.getSession()
                .doOnNext(session -> {
                    AuthorizationContext context = new AuthorizationContext();
                    tokens.setRefreshToken(new RefreshToken());
                    tokens.setAccessToken(NOT_EXPIRED_ACCESS_TOKEN);
                    tokens.setAccessTokenLastCheckTime(EXPIRED_LAST_CHECK_TIME);
                    context.setTokens(tokens);
                    session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
                })
                .block();

        filter.filter(exchange, null).block();

        checkAuthorizationRedirect();

        assertEquals(INITIAL_REQUEST_URI, getContext().getInitialRequestUri().toString());
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfPathMatchLogoutAndTokensNotFound() {
        exchange = MockServerWebExchange.from(MockServerHttpRequest.get("https://gateway.com/sample-app/logout"));
        exchange.getAttributes().put(GATEWAY_ROUTE_ATTR, route);

        filter.filter(exchange, null).block();

        checkAuthorizationRedirect();

        assertNull(getContext());
    }

    private MockServerWebExchange getLogoutExchangeWithTokens() {
        MockServerWebExchange e = MockServerWebExchange.from(MockServerHttpRequest.get("https://gateway.com/logout"));
        e.getAttributes().put(GATEWAY_ROUTE_ATTR, route);
        e.getSession()
                .doOnNext(session -> {
                    Tokens tokens = new Tokens();
                    AuthorizationContext context = new AuthorizationContext();
                    context.setTokens(tokens);
                    session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
                })
                .block();
        return e;
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfPathMatchLogoutTokensPresentAndSuccessLogoutRequest() {
        when(tokenEndpointService.logout(any(), any())).thenReturn(Mono.just(ClientResponse.create(HttpStatus.OK).build()));

        exchange = getLogoutExchangeWithTokens();

        filter.filter(exchange, null).block();

        checkAuthorizationRedirect();

        assertNull(getContext());
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfPathMatchLogoutTokensPresentAndFailLogoutRequest() {
        when(tokenEndpointService.logout(any(), any())).thenReturn(Mono.error(new RuntimeException()));

        exchange = getLogoutExchangeWithTokens();

        filter.filter(exchange, null).block();

        checkAuthorizationRedirect();

        assertNull(getContext());
    }
}
