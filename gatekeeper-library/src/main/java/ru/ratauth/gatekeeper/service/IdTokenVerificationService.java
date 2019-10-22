package ru.ratauth.gatekeeper.service;

import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jwt.SignedJWT;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.stereotype.Service;
import org.yaml.snakeyaml.external.biz.base64Coder.Base64Coder;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.security.Tokens;

import java.util.List;

@Service
public class IdTokenVerificationService implements TokensVerificationService {
    private Logger log = LoggerFactory.getLogger(IdTokenVerificationService.class);

    @Override
    public void verifyTokens(Tokens tokens, Client client) {
        try {
            log.debug("try to verify id token");
            JWSVerifier verifier = new MACVerifier(Base64Coder.decodeLines(client.getSecret()));
            SignedJWT signedJWT = tokens.getIdToken();
            log.debug("id token {}", signedJWT.getParsedString());
            if (!signedJWT.verify(verifier)) {
                log.error("bad jwt signature");
                throw new RuntimeException("User info extraction error!");
            }
            List<String> aud = signedJWT.getJWTClaimsSet().getAudience();
            log.debug("jwt audience {}", aud);
            log.debug("client audience {}", client.getId());
            if (aud == null || !aud.contains(client.getId())) {
                log.error("bad audience");
                throw new RuntimeException("Audience is wrong!");
            }
            log.debug("success verify id token");
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}
