package ru.ratauth.gatekeeper.security;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.oauth2.sdk.token.BearerAccessToken;
import com.nimbusds.oauth2.sdk.token.RefreshToken;

import java.io.Serializable;
import java.time.Duration;
import java.time.Instant;

public class Tokens implements Serializable {

    static final long serialVersionUID = 2798694009231615899L;

    private BearerAccessToken accessToken;
    private RefreshToken refreshToken;
    private SignedJWT idToken;
    private String sessionId;

    private Instant accessTokenExpirationTime;
    private Instant accessTokenLastCheckTime;

    public BearerAccessToken getAccessToken() {
        return accessToken;
    }

    public void setAccessToken(BearerAccessToken accessToken) {
        accessTokenExpirationTime = Instant.now().plus(Duration.ofSeconds(accessToken.getLifetime()));
        this.accessToken = accessToken;
    }

    public RefreshToken getRefreshToken() {
        return refreshToken;
    }

    public void setRefreshToken(RefreshToken refreshToken) {
        this.refreshToken = refreshToken;
    }

    public SignedJWT getIdToken() {
        return idToken;
    }

    public void setIdToken(SignedJWT idToken) {
        this.idToken = idToken;
    }

    public Instant getAccessTokenExpirationTime() {
        return accessTokenExpirationTime;
    }

    public Instant getAccessTokenLastCheckTime() {
        return accessTokenLastCheckTime;
    }

    public void setAccessTokenLastCheckTime(Instant accessTokenLastCheckTime) {
        this.accessTokenLastCheckTime = accessTokenLastCheckTime;
    }

    public String getSessionId() {
        return sessionId;
    }

    public void setSessionId(String sessionId) {
        this.sessionId = sessionId;
    }
}
