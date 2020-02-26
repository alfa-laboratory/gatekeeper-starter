package ru.ratauth.gatekeeper.controller;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.service.AuthorizeService;

import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.Objects;

@RestController
public class CallbackController {
    private Logger log = LoggerFactory.getLogger(CallbackController.class);

    private final AuthorizeService authorizeService;
    private final URI errorPageUri;
    private final List<Client> clients;

    public CallbackController(
            AuthorizeService authorizeService,
            GatekeeperProperties properties
    ) {
        this.authorizeService = authorizeService;
        this.errorPageUri = URI.create(properties.getErrorPageUri());
        this.clients = properties.getClients();
    }

    @GetMapping("/openid/authorize/{client_id}")
    public Mono<ResponseEntity<String>> callback(@PathVariable("client_id") String clientId, @RequestParam String code, ServerWebExchange exchange) {
        log.info("handle openid connect authentication code callback");
        log.debug("try to get user authentication context for client id {} by code {}", clientId, code);
        return authorizeService.getAuthorizedUserContextByCode(clientId, code, exchange)
                .map(authorizationContext -> authorizationContext.getClientAuthorizations().get(clientId))
                .map(clientAuthorization -> {
                    log.info("success authenticate user");
                    URI initialRequestUri = clientAuthorization.getInitialRequestUri();
                    Client client = getClientById(clientId);
                    URI defaultPageUri = getDefaultPageUri(client);
                    if (log.isDebugEnabled()) {
                        String idToken = clientAuthorization.getTokens().getIdToken().getParsedString();
                        String accessToken = clientAuthorization.getTokens().getAccessToken().getValue();
                        String refreshToken = clientAuthorization.getTokens().getRefreshToken().getValue();
                        log.debug("id token {}", idToken);
                        log.debug("access token {}", accessToken);
                        log.debug("refresh token {}", refreshToken);
                        log.debug("initial request uri {}", initialRequestUri);
                        log.debug("default page uri {}", defaultPageUri);
                    }
                    return client.isDefaultPageUriPriority() && defaultPageUri != null ? defaultPageUri : initialRequestUri;
                })
                .onErrorResume(t -> {
                    log.error("user authentication failed", t);
                    log.debug("set location to error page {}", errorPageUri);
                    return Mono.just(errorPageUri);
                })
                .map(location -> {
                    log.info("redirect to {}", location);
                    return ResponseEntity.status(HttpStatus.FOUND)
                            .location(location)
                            .build();
                });
    }

    private URI getDefaultPageUri(Client client) {
        URI defaultPageUri = null;
        try {
            defaultPageUri = new URI(client.getDefaultPageUri());
        } catch (URISyntaxException e) {
            log.error("Can not parse default page uri property. Exception:", e);
        }
        return defaultPageUri;
    }

    private Client getClientById(String clientId) {
        return clients.stream()
                .filter(c -> Objects.equals(clientId, c.getId()))
                .findFirst()
                .orElseThrow();
    }
}
