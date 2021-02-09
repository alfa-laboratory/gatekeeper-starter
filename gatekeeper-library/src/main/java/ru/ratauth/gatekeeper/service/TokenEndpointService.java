package ru.ratauth.gatekeeper.service;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;
import org.springframework.web.reactive.function.client.ClientResponse;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.security.Tokens;

public interface TokenEndpointService {
    Mono<Tokens> exchangeCodeForTokens(Client client, String code);

    Mono<Tokens> refreshAccessToken(Client client, RefreshToken refreshToken);

    Mono<SignedJWT> checkAccessToken(Client client, BearerAccessToken accessToken);

    Mono<ClientResponse> logout(Client client, RefreshToken refreshToken);
}
