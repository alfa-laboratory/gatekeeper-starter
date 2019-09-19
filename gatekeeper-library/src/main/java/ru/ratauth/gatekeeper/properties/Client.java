package ru.ratauth.gatekeeper.properties;

import java.util.LinkedHashSet;
import java.util.Set;

public class Client {
    private String id;
    private Set<String> scope = new LinkedHashSet<>();
    private String defaultPageUri;

    public String getId() {
        return id;
    }

    public void setId(String id) {
        this.id = id;
    }

    public Set<String> getScope() {
        return scope;
    }

    public void setScope(Set<String> scope) {
        this.scope = scope;
    }

    public String getDefaultPageUri() {
        return defaultPageUri;
    }

    public void setDefaultPageUri(String defaultPageUri) {
        this.defaultPageUri = defaultPageUri;
    }
}
