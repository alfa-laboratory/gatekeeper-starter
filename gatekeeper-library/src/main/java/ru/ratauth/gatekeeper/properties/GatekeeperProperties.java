package ru.ratauth.gatekeeper.properties;

import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@ConfigurationProperties("gatekeeper")
public class GatekeeperProperties {
    private String authorizationPageUri;
    private String errorPageUri;
    private String tokenEndpointUri;
    private String introspectionEndpointUri;
    private String revocationEndpointUri;
    private long checkTokenInterval = 30L;
    private List<Client> clients = new ArrayList<>();

    public String getAuthorizationPageUri() {
        return authorizationPageUri;
    }

    public void setAuthorizationPageUri(String authorizationPageUri) {
        this.authorizationPageUri = authorizationPageUri;
    }

    public String getErrorPageUri() {
        return errorPageUri;
    }

    public void setErrorPageUri(String errorPageUri) {
        this.errorPageUri = errorPageUri;
    }

    public String getTokenEndpointUri() {
        return tokenEndpointUri;
    }

    public void setTokenEndpointUri(String tokenEndpointUri) {
        this.tokenEndpointUri = tokenEndpointUri;
    }

    public String getIntrospectionEndpointUri() {
        return introspectionEndpointUri;
    }

    public void setIntrospectionEndpointUri(String introspectionEndpointUri) {
        this.introspectionEndpointUri = introspectionEndpointUri;
    }

    public String getRevocationEndpointUri() {
        return revocationEndpointUri;
    }

    public void setRevocationEndpointUri(String revocationEndpointUri) {
        this.revocationEndpointUri = revocationEndpointUri;
    }

    public long getCheckTokenInterval() {
        return checkTokenInterval;
    }

    public void setCheckTokenInterval(long checkTokenInterval) {
        this.checkTokenInterval = checkTokenInterval;
    }

    public List<Client> getClients() {
        return clients;
    }

    public void setClients(List<Client> clients) {
        this.clients = clients;
    }
}
