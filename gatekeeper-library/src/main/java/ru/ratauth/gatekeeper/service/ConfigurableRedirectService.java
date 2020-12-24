package ru.ratauth.gatekeeper.service;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.HttpStatus;
import org.springframework.http.server.reactive.ServerHttpResponse;
import org.springframework.stereotype.Service;
import org.springframework.util.StringUtils;
import org.springframework.web.server.ServerWebExchange;
import org.springframework.web.util.UriComponentsBuilder;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.properties.GatekeeperProperties;

import java.io.UnsupportedEncodingException;
import java.net.URI;
import java.net.URLDecoder;
import java.nio.charset.StandardCharsets;
import java.util.LinkedHashSet;
import java.util.Set;

@Service
public class ConfigurableRedirectService implements RedirectService {
    private final Logger log = LoggerFactory.getLogger(ConfigurableRedirectService.class);

    private final String authorizationPageUri;

    public ConfigurableRedirectService(GatekeeperProperties properties) {
        this.authorizationPageUri = properties.getAuthorizationPageUri();
    }

    @Override
    public Mono<Void> sendRedirect(ServerWebExchange exchange, Client client) {
        if (exchange.getRequest().getPath().pathWithinApplication().value().contains("/logout")) {
            String endUrl = exchange.getRequest().getQueryParams().getFirst("end_url");
            if (endUrl != null && !endUrl.isBlank()) {
                return sendRedirectToEndUrlPage(exchange, endUrl);
            }
        }
        return sendRedirectToAuthorizationPage(exchange, client);
    }

    @Override
    public Mono<Void> sendRedirectToAuthorizationPage(ServerWebExchange exchange, Client client) {
        log.info("send redirect to authorization page");

        Set<String> scopes = new LinkedHashSet<>();
        scopes.add("openid");
        scopes.addAll(client.getScope());

        URI location = UriComponentsBuilder.fromUriString(authorizationPageUri)
                .queryParam("response_type", "code")
                .queryParam("client_id", client.getId())
                .queryParam("scope", StringUtils.collectionToDelimitedString(scopes, " "))
                .build()
                .toUri();

        log.debug("authorization redirect uri {}", location.toString());

        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(location);
        });
    }

    @Override
    public Mono<Void> sendRedirectToEndUrlPage(ServerWebExchange exchange, String pageUri) {
        log.info("send redirect to 'end_url'");

        String decodedURL = pageUri;
        try {
            decodedURL = URLDecoder.decode(pageUri, StandardCharsets.UTF_8.name());
        } catch (UnsupportedEncodingException e) {
            log.error("Cannot decode URL {}", pageUri);
        }

        URI location = UriComponentsBuilder.fromUriString(decodedURL)
                .build()
                .toUri();

        log.debug("'end_url' redirect uri {}", location.toString());

        return Mono.fromRunnable(() -> {
            ServerHttpResponse response = exchange.getResponse();
            response.setStatusCode(HttpStatus.FOUND);
            response.getHeaders().setLocation(location);
        });
    }
}
