package ru.ratauth.gatekeeper.controller;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.PathVariable;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.service.LogoutService;

@AllArgsConstructor
@RestController
public class LogoutController {

    private final LogoutService logoutService;

    @GetMapping("/openid/logout/{client_id}")
    public Mono<Void> callback(@PathVariable("client_id") String clientId, ServerWebExchange exchange) {
        return logoutService.performLogoutAndRedirect(clientId, exchange);
    }
}
