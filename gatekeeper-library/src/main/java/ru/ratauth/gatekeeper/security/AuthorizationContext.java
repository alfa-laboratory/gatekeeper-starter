package ru.ratauth.gatekeeper.security;

import java.io.Serializable;
import java.util.Map;
import java.util.concurrent.ConcurrentHashMap;

public class AuthorizationContext implements Serializable {
    public static final String GATEKEEPER_AUTHORIZATION_CONTEXT_ATTR = "GATEKEEPER_AUTHORIZATION_CONTEXT";

    private final Map<String, ClientAuthorization> clientAuthorizations = new ConcurrentHashMap<>();

    public Map<String, ClientAuthorization> getClientAuthorizations() {
        return clientAuthorizations;
    }
}