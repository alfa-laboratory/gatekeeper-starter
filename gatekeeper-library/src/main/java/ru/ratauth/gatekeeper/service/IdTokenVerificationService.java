package ru.ratauth.gatekeeper.service;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.yaml.snakeyaml.external.biz.base64Coder.Base64Coder;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.security.Tokens;

import java.util.List;

public class IdTokenVerificationService implements TokensVerificationService {
    @Override
    public void verifyTokens(Tokens tokens, Client client) {
        try {
            JWSVerifier verifier = new MACVerifier(Base64Coder.decodeLines(client.getSecret()));
            SignedJWT signedJWT = tokens.getIdToken();
            if (!signedJWT.verify(verifier)) {
                throw new RuntimeException("User info extraction error!");
            }
            List<String> aud = signedJWT.getJWTClaimsSet().getAudience();
            if (aud == null || !aud.contains(client.getId())) {
                throw new RuntimeException("Audience is wrong!");
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
