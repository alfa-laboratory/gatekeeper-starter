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
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;
import ru.ratauth.gatekeeper.service.AuthorizeService;

import java.net.URI;

@RestController
public class CallbackController {
    private Logger log = LoggerFactory.getLogger(CallbackController.class);

    private final AuthorizeService authorizeService;
    private final URI errorPageUri;

    public CallbackController(AuthorizeService authorizeService, GatekeeperProperties properties) {
        this.authorizeService = authorizeService;
        this.errorPageUri = URI.create(properties.getErrorPageUri());
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
                    if (log.isDebugEnabled()) {
                        String idToken = clientAuthorization.getTokens().getIdToken().getParsedString();
                        String accessToken = clientAuthorization.getTokens().getAccessToken().getValue();
                        String refreshToken = clientAuthorization.getTokens().getRefreshToken().getValue();
                        log.debug("id token {}", idToken);
                        log.debug("access token {}", accessToken);
                        log.debug("refresh token {}", refreshToken);
                        log.debug("initial request uri {}", initialRequestUri);
                    }
                    return initialRequestUri;
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
}
