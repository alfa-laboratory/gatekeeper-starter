package ru.ratauth.gatekeeper.service;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.ParseException;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import lombok.extern.slf4j.Slf4j;
import net.minidev.json.JSONObject;
import org.springframework.core.ParameterizedTypeReference;
import org.springframework.http.MediaType;
import org.springframework.stereotype.Service;
import org.springframework.web.reactive.function.BodyInserters;
import org.springframework.web.reactive.function.client.ClientResponse;
import org.springframework.web.reactive.function.client.WebClient;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.security.Tokens;

import java.util.Map;

@Slf4j
@Service
public class WebClientTokenEndpointService implements TokenEndpointService {

    private final static String SESSION_ID = "sid";

    private final WebClient webClient;
    private final String tokenEndpointUri;
    private final String introspectionEndpointUri;
    private final String revocationEndpointUri;

    public WebClientTokenEndpointService(WebClient webClient, GatekeeperProperties properties) {
        this.webClient = webClient;
        this.tokenEndpointUri = properties.getTokenEndpointUri();
        this.introspectionEndpointUri = properties.getIntrospectionEndpointUri();
        this.revocationEndpointUri = properties.getRevocationEndpointUri();
    }

    @Override
    public Mono<Tokens> exchangeCodeForTokens(Client client, String code) {
        return webClient.post()
                .uri(tokenEndpointUri)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .headers(headers -> headers.setBasicAuth(client.getId(), client.getPassword()))
                .body(BodyInserters.fromFormData("grant_type", "authorization_code")
                        .with("response_type", "token")
                        .with("code", code))
                .exchange()
                .flatMap(response -> {
                    var type = new ParameterizedTypeReference<Map<String, Object>>() {
                    };
                    return response.bodyToMono(type);
                })
                .map(map -> {
                    try {
                        JSONObject jsonObject = new JSONObject(map);
                        BearerAccessToken accessToken = BearerAccessToken.parse(jsonObject);
                        RefreshToken refreshToken = RefreshToken.parse(jsonObject);
                        SignedJWT idToken = SignedJWT.parse(jsonObject.getAsString("id_token"));
                        Tokens tokens = new Tokens();
                        tokens.setAccessToken(accessToken);
                        tokens.setRefreshToken(refreshToken);
                        tokens.setIdToken(idToken);
                        tokens.setSessionId(idToken.getJWTClaimsSet().getStringClaim(SESSION_ID));
                        return tokens;
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    @Override
    public Mono<Tokens> refreshAccessToken(Client client, RefreshToken refreshToken) {
        return webClient.post()
                .uri(tokenEndpointUri)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .headers(headers -> headers.setBasicAuth(client.getId(), client.getPassword()))
                .body(BodyInserters.fromFormData("grant_type", "refresh_token")
                        .with("refresh_token", refreshToken.getValue())
                        .with("response_type", "access_token"))
                .exchange()
                .flatMap(response -> {
                    var type = new ParameterizedTypeReference<Map<String, Object>>() {
                    };
                    return response.bodyToMono(type);
                })
                .map(map -> {
                    JSONObject jsonObject = new JSONObject(map);
                    try {
                        Tokens tokens = new Tokens();
                        tokens.setAccessToken(BearerAccessToken.parse(jsonObject));
                        tokens.setRefreshToken(RefreshToken.parse(jsonObject));
                        return tokens;
                    } catch (ParseException e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    @Override
    public Mono<SignedJWT> checkAccessToken(Client client, BearerAccessToken accessToken) {
        return webClient.post()
                .uri(introspectionEndpointUri)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .headers(headers -> headers.setBasicAuth(client.getId(), client.getPassword()))
                .body(BodyInserters.fromFormData("token", accessToken.getValue()))
                .exchange()
                .flatMap(response -> {
                    var type = new ParameterizedTypeReference<Map<String, Object>>() {
                    };
                    return response.bodyToMono(type);
                })
                .map(map -> {
                    try {
                        JSONObject jsonObject = new JSONObject(map);
                        return SignedJWT.parse(jsonObject.getAsString("id_token"));
                    } catch (Exception e) {
                        throw new RuntimeException(e);
                    }
                });
    }

    @Override
    public Mono<ClientResponse> logout(Client client, RefreshToken refreshToken) {
        log.debug("performing logout");
        return webClient.post()
                .uri(revocationEndpointUri)
                .accept(MediaType.APPLICATION_JSON)
                .contentType(MediaType.APPLICATION_FORM_URLENCODED)
                .headers(headers -> headers.setBasicAuth(client.getId(), client.getPassword()))
                .body(BodyInserters.fromFormData("refresh_token", refreshToken.getValue()))
                .exchange();
    }

}
