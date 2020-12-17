package ru.ratauth.gatekeeper.service;

import org.junit.Before;
import org.junit.Test;
import org.springframework.cloud.gateway.route.Route;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.util.MultiValueMap;
import org.springframework.util.StringUtils;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.server.WebSession;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;
import ru.ratauth.gatekeeper.security.ClientAuthorization;
import ru.ratauth.gatekeeper.security.Tokens;

import java.util.List;
import java.util.Set;

import static java.util.Objects.requireNonNull;
import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.cloud.gateway.support.ServerWebExchangeUtils.GATEWAY_ROUTE_ATTR;
import static org.springframework.http.HttpStatus.FOUND;
import static ru.ratauth.gatekeeper.security.AuthorizationContext.GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR;

public class LogoutServiceTest {
    private static final String AUTHORIZATION_PAGE_URI = "https://authorization-server.com/authorize";
    private static final String CLIENT_ID = "test-app";
    private static final Set<String> SCOPES = Set.of("roles", "profile");

    private static final String INITIAL_REQUEST_URI = "https://gateway.com/sample-app/dashboard";

    private static final String END_URL = "http://customredirectpage.com?name=me&ID=123";
    private static final String END_URL_ENCODED = "http://customredirectpage.com%3fname%3dme%26ID%3d123&param=param";

    private MockServerWebExchange exchange;
    private Route route;
    private TokenEndpointService tokenEndpointService;
    private RedirectService redirectService;
    private LogoutService logoutService;

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
        tokenEndpointService = mock(TokenEndpointService.class);
        redirectService = mock(RedirectService.class);
        logoutService = new OpenIdLogoutService(properties, tokenEndpointService, redirectService);
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfPathMatchLogoutAndTokensNotFound() {
        exchange = MockServerWebExchange.from(MockServerHttpRequest.get("https://gateway.com/sample-app/logout"));
        exchange.getAttributes().put(GATEWAY_ROUTE_ATTR, route);

        when(redirectService.sendRedirect(any(), any())).thenReturn(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(UriComponentsBuilder.fromUriString(AUTHORIZATION_PAGE_URI)
                    .queryParam("response_type", "code")
                    .queryParam("client_id", CLIENT_ID)
                    .queryParam("scope", StringUtils.collectionToDelimitedString(SCOPES, " "))
                    .build()
                    .toUri());
        }));

        logoutService.performLogoutAndRedirect(CLIENT_ID, exchange).block();

        checkAuthorizationRedirect();

        assertNull(getContext());
    }

    private MockServerWebExchange getLogoutExchangeWithTokens(String uriTemplate) {
        MockServerWebExchange e = MockServerWebExchange.from(MockServerHttpRequest.get(uriTemplate));
        e.getAttributes().put(GATEWAY_ROUTE_ATTR, route);
        e.getSession()
                .doOnNext(session -> {
                    Tokens tokens = new Tokens();
                    AuthorizationContext context = new AuthorizationContext();
                    ClientAuthorization clientAuthorization = new ClientAuthorization();
                    clientAuthorization.setTokens(tokens);
                    context.getClientAuthorizations().put(CLIENT_ID, clientAuthorization);
                    session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
                })
                .block();
        return e;
    }

    private MockServerWebExchange getLogoutExchangeWithTokens() {
        return getLogoutExchangeWithTokens("https://gateway.com/logout");
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfPathMatchLogoutTokensPresentAndSuccessLogoutRequest() {
        when(tokenEndpointService.logout(any(), any())).thenReturn(Mono.just(ClientResponse.create(HttpStatus.OK).build()));
        when(redirectService.sendRedirect(any(), any())).thenReturn(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(UriComponentsBuilder.fromUriString(AUTHORIZATION_PAGE_URI)
                    .queryParam("response_type", "code")
                    .queryParam("client_id", CLIENT_ID)
                    .queryParam("scope", StringUtils.collectionToDelimitedString(SCOPES, " "))
                    .build()
                    .toUri());
        }));
        exchange = getLogoutExchangeWithTokens();

        logoutService.performLogoutAndRedirect(CLIENT_ID, exchange).block();

        checkAuthorizationRedirect();

        assertNull(getContext());
    }

    @Test
    public void shouldRedirectToAuthorizationPageIfPathMatchLogoutTokensPresentAndFailLogoutRequest() {
        when(tokenEndpointService.logout(any(), any())).thenReturn(Mono.error(new RuntimeException()));
        when(redirectService.sendRedirect(any(), any())).thenReturn(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(UriComponentsBuilder.fromUriString(AUTHORIZATION_PAGE_URI)
                    .queryParam("response_type", "code")
                    .queryParam("client_id", CLIENT_ID)
                    .queryParam("scope", StringUtils.collectionToDelimitedString(SCOPES, " "))
                    .build()
                    .toUri());
        }));

        exchange = getLogoutExchangeWithTokens();

        logoutService.performLogoutAndRedirect(CLIENT_ID, exchange).block();

        checkAuthorizationRedirect();

        assertNull(getContext());
    }

    @Test
    public void shouldRedirectToCustomPageIfPathMatchLogoutTokensPresentAndSuccessLogoutRequest() {
        when(tokenEndpointService.logout(any(), any())).thenReturn(Mono.just(ClientResponse.create(HttpStatus.OK).build()));
        when(redirectService.sendRedirect(any(), any())).thenReturn(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(UriComponentsBuilder.fromUriString(END_URL)
                    .build()
                    .toUri());
        }));
        exchange = getLogoutExchangeWithTokens("https://gateway.com/logout?end_url=" + END_URL_ENCODED);

        logoutService.performLogoutAndRedirect(CLIENT_ID, exchange).block();

        checkAfterLogoutRedirect();

        assertNull(getContext());
    }

    @Test
    public void shouldRedirectToCustomPageIfPathMatchLogoutTokensPresentAndFailLogoutRequest() {
        when(tokenEndpointService.logout(any(), any())).thenReturn(Mono.error(new RuntimeException()));
        when(redirectService.sendRedirect(any(), any())).thenReturn(Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(UriComponentsBuilder.fromUriString(END_URL)
                    .build()
                    .toUri());
        }));
        exchange = getLogoutExchangeWithTokens("https://gateway.com/logout?end_url=" + END_URL_ENCODED);

        logoutService.performLogoutAndRedirect(CLIENT_ID, exchange).block();

        checkAfterLogoutRedirect();

        assertNull(getContext());
    }

    private void checkAfterLogoutRedirect() {
        ServerHttpResponse response = exchange.getResponse();
        assertEquals(FOUND, response.getStatusCode());

        String redirectUri = requireNonNull(response.getHeaders().getLocation()).toString();
        assertTrue(redirectUri.startsWith(END_URL));

        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromUriString(redirectUri)
                .build()
                .getQueryParams();
        assertEquals(2, queryParams.size());
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
    }


    private AuthorizationContext getContext() {
        WebSession session = exchange.getSession().block();
        assert session != null;
        return session.getAttribute(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR);
    }

}
