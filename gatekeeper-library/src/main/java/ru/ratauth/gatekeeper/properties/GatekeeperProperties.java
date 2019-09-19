package ru.ratauth.gatekeeper.properties;

import java.util.ArrayList;
import java.util.List;

public class GatekeeperProperties {
    private String authorizationPageUri;
    private long checkTokenInterval = 30L;
    private List<Client> clients = new ArrayList<>();

    public String getAuthorizationPageUri() {
        return authorizationPageUri;
    }

    public void setAuthorizationPageUri(String authorizationPageUri) {
        this.authorizationPageUri = authorizationPageUri;
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
