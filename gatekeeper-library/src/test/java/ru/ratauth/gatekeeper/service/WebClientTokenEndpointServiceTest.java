package ru.ratauth.gatekeeper.service;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.junit.Before;
import org.junit.Test;
import org.mockito.ArgumentCaptor;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.HttpHeaders;
import org.springframework.mock.http.client.reactive.MockClientHttpRequest;
import org.springframework.web.reactive.function.client.ClientRequest;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.ExchangeFunction;
import org.springframework.web.reactive.function.client.ExchangeStrategies;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.Tokens;

import java.util.Map;
import java.util.UUID;
import java.util.stream.Collectors;
import java.util.stream.Stream;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;
import static org.springframework.http.HttpMethod.POST;
import static org.springframework.http.HttpStatus.OK;
import static org.springframework.http.MediaType.APPLICATION_FORM_URLENCODED;
import static org.springframework.http.MediaType.APPLICATION_JSON;

public class WebClientTokenEndpointServiceTest {
    private static final ParameterizedTypeReference<Map<String, Object>> RESPONSE_TYPE = new ParameterizedTypeReference<>() {
    };
    private static final String ID_TOKEN_STR = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c";
    private static final BearerAccessToken ACCESS_TOKEN = new BearerAccessToken(360L, null);
    private static final String TOKEN_TYPE = "BEARER";
    private static final RefreshToken REFRESH_TOKEN = new RefreshToken();
    private static final String CODE = UUID.randomUUID().toString();
    private static final String TOKEN_ENDPOINT_URI = "https://authorization-server.com/token";
    private static final String INTROSPECTION_ENDPOINT_URI = "https://authorization-server.com/check_token";
    private static final String REVOCATION_ENDPOINT_URI = "https://authorization-server.com/logout";
    private static final String CLIENT_ID = "test-app";
    private static final String PASSWORD = "pass";
    private static final String BASIC_AUTH = "Basic dGVzdC1hcHA6cGFzcw==";

    private ClientResponse mockResponse;
    private ExchangeFunction exchangeFunction;
    private ArgumentCaptor<ClientRequest> captor;
    private Client client;
    private TokenEndpointService tokenEndpointService;

    @Before
    public void init() {
        mockResponse = mock(ClientResponse.class);
        exchangeFunction = mock(ExchangeFunction.class);
        captor = ArgumentCaptor.forClass(ClientRequest.class);
        WebClient webClient = WebClient.builder().exchangeFunction(exchangeFunction).build();
        GatekeeperProperties properties = new GatekeeperProperties();
        properties.setTokenEndpointUri(TOKEN_ENDPOINT_URI);
        properties.setIntrospectionEndpointUri(INTROSPECTION_ENDPOINT_URI);
        properties.setRevocationEndpointUri(REVOCATION_ENDPOINT_URI);
        tokenEndpointService = new WebClientTokenEndpointService(webClient, properties);
        client = new Client();
        client.setId(CLIENT_ID);
        client.setPassword(PASSWORD);
        when(exchangeFunction.exchange(captor.capture())).thenReturn(Mono.just(mockResponse));
    }

    private void checkRequestMetadata(String expectedUri) {
        ClientRequest request = captor.getValue();
        assertEquals(POST, request.method());
        assertEquals(expectedUri, request.url().toString());
        HttpHeaders requestHeaders = request.headers();
        assertEquals(APPLICATION_JSON, requestHeaders.getAccept().get(0));
        assertEquals(APPLICATION_FORM_URLENCODED, requestHeaders.getContentType());
        assertEquals(BASIC_AUTH, requestHeaders.getFirst("Authorization"));
    }

    private Map<String, String> getRequestFormDataBodyAsMap() {
        MockClientHttpRequest request = new MockClientHttpRequest(POST, "/");
        ExchangeStrategies strategies = ExchangeStrategies.withDefaults();
        captor.getValue().writeTo(request, strategies).block();
        return request.getBodyAsString()
                .map(body -> Stream.of(body.split("&"))
                        .map(s -> s.split("="))
                        .collect(Collectors.toMap(e -> e[0], e -> e[1])))
                .block();
    }

    @Test
    public void shouldSuccessExchangeCodeForTokens() {
        when(mockResponse.bodyToMono(RESPONSE_TYPE)).thenReturn(Mono.just(
                Map.of("access_token", ACCESS_TOKEN.getValue(),
                        "token_type", TOKEN_TYPE,
                        "expires_in", ACCESS_TOKEN.getLifetime(),
                        "refresh_token", REFRESH_TOKEN.getValue(),
                        "id_token", ID_TOKEN_STR)));

        Tokens tokens = tokenEndpointService.exchangeCodeForTokens(client, CODE).block();
        assertNotNull(tokens);
        assertEquals(ACCESS_TOKEN, tokens.getAccessToken());
        assertEquals(REFRESH_TOKEN, tokens.getRefreshToken());
        assertEquals(ID_TOKEN_STR, tokens.getIdToken().getParsedString());

        checkRequestMetadata(TOKEN_ENDPOINT_URI);

        Map<String, String> requestData = getRequestFormDataBodyAsMap();
        assertEquals(3, requestData.size());
        assertEquals("authorization_code", requestData.get("grant_type"));
        assertEquals("token", requestData.get("response_type"));
        assertEquals(CODE, requestData.get("code"));
    }

    @Test
    public void shouldSuccessRefreshAccessToken() {
        when(mockResponse.bodyToMono(RESPONSE_TYPE)).thenReturn(Mono.just(
                Map.of("access_token", ACCESS_TOKEN.getValue(),
                        "token_type", TOKEN_TYPE)
        ));

        BearerAccessToken newAccessToken = tokenEndpointService.refreshAccessToken(client, REFRESH_TOKEN).block();
        assertEquals(ACCESS_TOKEN, newAccessToken);

        checkRequestMetadata(TOKEN_ENDPOINT_URI);

        Map<String, String> requestData = getRequestFormDataBodyAsMap();
        assertEquals(3, requestData.size());
        assertEquals("refresh_token", requestData.get("grant_type"));
        assertEquals("access_token", requestData.get("response_type"));
        assertEquals(REFRESH_TOKEN.getValue(), requestData.get("refresh_token"));
    }

    @Test
    public void shouldSuccessIntrospectAccessToken() {
        when(mockResponse.bodyToMono(RESPONSE_TYPE)).thenReturn(Mono.just(Map.of("id_token", ID_TOKEN_STR)));

        SignedJWT idToken = tokenEndpointService.checkAccessToken(client, ACCESS_TOKEN).block();
        assertNotNull(idToken);
        assertEquals(ID_TOKEN_STR, idToken.getParsedString());

        checkRequestMetadata(INTROSPECTION_ENDPOINT_URI);

        Map<String, String> requestData = getRequestFormDataBodyAsMap();
        assertEquals(1, requestData.size());
        assertEquals(ACCESS_TOKEN.getValue(), requestData.get("token"));
    }

    @Test
    public void shouldSuccessRevokeTokens() {
        when(exchangeFunction.exchange(captor.capture())).thenReturn(Mono.just(ClientResponse.create(OK).build()));

        ClientResponse clientResponse = tokenEndpointService.logout(client, REFRESH_TOKEN).block();
        assertNotNull(clientResponse);
        assertEquals(OK, clientResponse.statusCode());
        checkRequestMetadata(REVOCATION_ENDPOINT_URI);

        Map<String, String> requestData = getRequestFormDataBodyAsMap();
        assertEquals(1, requestData.size());
        assertEquals(REFRESH_TOKEN.getValue(), requestData.get("refresh_token"));
    }
}