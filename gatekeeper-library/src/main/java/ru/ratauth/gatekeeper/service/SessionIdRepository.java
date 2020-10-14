package ru.ratauth.gatekeeper.service;

public interface SessionIdRepository {

    void removeWebSessionsBySessionId(String sid);

    void connectWebSessionWithSessionId(String webSession, String sessionId);
}
