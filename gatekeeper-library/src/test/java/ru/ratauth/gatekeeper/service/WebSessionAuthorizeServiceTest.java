package ru.ratauth.gatekeeper.service;

import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import org.junit.Before;
import org.junit.Test;
import org.springframework.mock.http.server.reactive.MockServerHttpRequest;
import org.springframework.mock.web.server.MockServerWebExchange;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.server.WebSession;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;
import ru.ratauth.gatekeeper.security.ClientAuthorization;
import ru.ratauth.gatekeeper.security.Tokens;

import java.net.URI;
import java.util.List;
import java.util.UUID;

import static org.junit.Assert.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static ru.ratauth.gatekeeper.security.AuthorizationContext.GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR;

public class WebSessionAuthorizeServiceTest {
    private static final String CLIENT_ID = "test-app";
    private static final String INITIAL_REQUEST_URI = "http://gateway.com/sample-app/dashboard";
    private static final String DEFAULT_PAGE_URI = "http://gateway.com/sample-app/home";
    private static final BearerAccessToken ACCESS_TOKEN = new BearerAccessToken();
    private static final String CODE = UUID.randomUUID().toString();

    private AuthorizeService authorizeService;
    private SessionIdRepository sessionIdRepository;

    @Before
    public void init() {
        GatekeeperProperties properties = new GatekeeperProperties();
        Client client = new Client();
        client.setId(CLIENT_ID);
        client.setDefaultPageUri(DEFAULT_PAGE_URI);
        properties.setClients(List.of(client));
        TokensVerificationService tokensVerificationService = (tokens, client1) -> {
        };
        TokenEndpointService tokenEndpointService = mock(TokenEndpointService.class);
        Tokens tokens = new Tokens();
        tokens.setAccessToken(ACCESS_TOKEN);
        when(tokenEndpointService.exchangeCodeForTokens(any(), any())).thenReturn(Mono.just(tokens));
        authorizeService = new WebSessionAuthorizeService(properties, tokenEndpointService, tokensVerificationService, sessionIdRepository);
    }

    @Test
    public void shouldReturnContextWithTokensAndNewSessionId() {
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
        String initialSessionId = exchange.getSession()
                .doOnNext(session -> {
                    AuthorizationContext context = new AuthorizationContext();
                    ClientAuthorization clientAuthorization = new ClientAuthorization();
                    clientAuthorization.setInitialRequestUri(URI.create(INITIAL_REQUEST_URI));
                    context.getClientAuthorizations().put(CLIENT_ID, clientAuthorization);
                    session.getAttributes().put(GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR, context);
                })
                .map(WebSession::getId)
                .block();

        AuthorizationContext context = authorizeService.getAuthorizedUserContextByCode(CLIENT_ID, CODE, exchange).block();

        assertNotNull(context);
        assertEquals(ACCESS_TOKEN, context.getClientAuthorizations().get(CLIENT_ID).getTokens().getAccessToken());
        assertEquals(INITIAL_REQUEST_URI, context.getClientAuthorizations().get(CLIENT_ID).getInitialRequestUri().toString());
        String sessionId = exchange.getSession().map(WebSession::getId).block();
        assertNotEquals(initialSessionId, sessionId);
    }

    @Test
    public void shouldReturnNewContextWithTokensAndDefaultPage() {
        ServerWebExchange exchange = MockServerWebExchange.from(MockServerHttpRequest.get("/"));
        AuthorizationContext context = authorizeService.getAuthorizedUserContextByCode(CLIENT_ID, CODE, exchange).block();

        assertNotNull(context);
        assertEquals(ACCESS_TOKEN, context.getClientAuthorizations().get(CLIENT_ID).getTokens().getAccessToken());
        assertEquals(DEFAULT_PAGE_URI, context.getClientAuthorizations().get(CLIENT_ID).getInitialRequestUri().toString());
    }
}
