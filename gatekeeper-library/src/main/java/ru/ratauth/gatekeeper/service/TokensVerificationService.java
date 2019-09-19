package ru.ratauth.gatekeeper.service;

import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.security.Tokens;

public interface TokensVerificationService {
    void verifyTokens(Tokens tokens, Client client);
}
