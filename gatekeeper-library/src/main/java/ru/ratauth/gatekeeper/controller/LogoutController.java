package ru.ratauth.gatekeeper.controller;

import lombok.AllArgsConstructor;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestParam;
import org.springframework.web.bind.annotation.RestController;
import org.springframework.web.server.ServerWebExchange;
import reactor.core.publisher.Mono;
import ru.ratauth.gatekeeper.service.LogoutService;

@AllArgsConstructor
@RestController
public class LogoutController {

    private final LogoutService logoutService;

    @GetMapping("/openid/logout")
    public Mono<Void> callback(@RequestParam("client_id") String clientId, ServerWebExchange exchange) {
        return logoutService.performLogoutAndRedirect(clientId, exchange);
    }
}
