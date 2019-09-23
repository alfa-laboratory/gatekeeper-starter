package ru.ratauth.gatekeeper.security;

import java.io.Serializable;
import java.net.URI;

public class AuthorizationContext implements Serializable {
    public static final String GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR = "GATEKEEPER_AUTHORIZATION_CONTEXT";

    private Tokens tokens;
    private URI initialRequestUri;

    public Tokens getTokens() {
        return tokens;
    }

    public void setTokens(Tokens tokens) {
        this.tokens = tokens;
    }

    public URI getInitialRequestUri() {
        return initialRequestUri;
    }

    public void setInitialRequestUri(URI initialRequestUri) {
        this.initialRequestUri = initialRequestUri;
    }
}
