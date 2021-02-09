package ru.ratauth.gatekeeper.properties;

import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

import java.util.ArrayList;
import java.util.List;

@Data
@ConfigurationProperties("gatekeeper")
public class GatekeeperProperties {
    private String authorizationPageUri;
    private String errorPageUri;
    private String tokenEndpointUri;
    private String introspectionEndpointUri;
    private String revocationEndpointUri;
    private long checkTokenInterval = 30L;
    private List<Client> clients = new ArrayList<>();
    private List<String> ignoredPatterns = new ArrayList<>();
}
