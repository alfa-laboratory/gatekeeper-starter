package ru.ratauth.gatekeeper.service;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;

@Slf4j
@Component
public class DummySessionTokenRepository implements SessionIdRepository {
    @Override
    public void removeWebSessionsBySessionId(String sessionToken) {
        log.warn("This instance not support back chanel logout");
    }

    @Override
    public void connectWebSessionWithSessionId(String webSession, String sessionId) {
        log.warn("This instance not support back chanel logout");
    }
}
