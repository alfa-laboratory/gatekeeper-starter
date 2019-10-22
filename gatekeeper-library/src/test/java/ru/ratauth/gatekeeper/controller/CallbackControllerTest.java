package ru.ratauth.gatekeeper.controller;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.Before;
import org.junit.Test;
import org.springframework.http.ResponseEntity;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.AuthorizationContext;
import ru.ratauth.gatekeeper.security.Tokens;
import ru.ratauth.gatekeeper.service.AuthorizeService;

import java.net.URI;
import java.util.Objects;

import static org.junit.Assert.assertEquals;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpStatus.FOUND;

public class CallbackControllerTest {
    private static final String ERROR_PAGE_URI = "https://authorization-server.com/error";

    private AuthorizeService authorizeService;
    private CallbackController callbackController;

    @Before
    public void init() {
        authorizeService = mock(AuthorizeService.class);
        GatekeeperProperties properties = new GatekeeperProperties();
        properties.setErrorPageUri(ERROR_PAGE_URI);
        callbackController = new CallbackController(authorizeService, properties);
    }

    @Test
    public void shouldRedirectToInitialRequest() {
        URI initialRequest = URI.create("http://gateway.com/sample-app/dashboard");
        when(authorizeService.getAuthorizedUserContextByCode(any(), any(), any())).then(a -> {
            AuthorizationContext context = new AuthorizationContext();
            Tokens tokens = new Tokens();
            tokens.setIdToken(SignedJWT.parse("eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwI" +
                    "wibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"));
            tokens.setAccessToken(new BearerAccessToken());
            tokens.setRefreshToken(new RefreshToken());
            context.setTokens(tokens);
            context.setInitialRequestUri(initialRequest);
            return Mono.just(context);
        });
        //zero logic, just delegate to authorize service
        ResponseEntity<String> response = callbackController.callback(null, null, null).block();
        assert response != null;
        assertEquals(FOUND, response.getStatusCode());
        assertEquals(initialRequest, response.getHeaders().getLocation());
    }

    @Test
    public void shouldRedirectToErrorPageIfFailAuthorize() {
        when(authorizeService.getAuthorizedUserContextByCode(any(), any(), any())).then(a -> Mono.error(new RuntimeException()));
        ResponseEntity<String> response = callbackController.callback(null, null, null).block();
        assert response != null;
        assertEquals(FOUND, response.getStatusCode());
        assertEquals(ERROR_PAGE_URI, Objects.requireNonNull(response.getHeaders().getLocation()).toString());
    }
}