package ru.ratauth.gatekeeper.service;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import org.junit.Before;
import org.junit.Rule;
import org.junit.Test;
import org.junit.rules.ExpectedException;
import org.yaml.snakeyaml.external.biz.base64Coder.Base64Coder;
import ru.ratauth.gatekeeper.properties.Client;
import ru.ratauth.gatekeeper.security.Tokens;

public class IdTokenVerificationServiceTest {
    @Rule
    public ExpectedException thrown = ExpectedException.none();

    private static final String CLIENT_ID = "test-app";
    private static final String SECRET = "t1X23HldJAncMr3zOOY7dLp8EvKFKCIZ81C+y2z99Oo=";

    private Tokens tokens;
    private TokensVerificationService verificationService;

    @Before
    public void init() throws Exception {
        MACSigner signer = new MACSigner(Base64Coder.decodeLines(SECRET));
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .audience(CLIENT_ID)
                .build();
        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        idToken.sign(signer);

        tokens = new Tokens();
        tokens.setIdToken(idToken);

        verificationService = new IdTokenVerificationService();
    }

    @Test
    public void shouldSuccessVerify() {
        Client client = new Client();
        client.setId(CLIENT_ID);
        client.setSecret(SECRET);

        verificationService.verifyTokens(tokens, client);
    }

    @Test
    public void shouldFailVerifyIfBadSecret() {
        Client client = new Client();
        client.setId(CLIENT_ID);
        client.setSecret("dDFYMjNIbGRKQW5jTXIzek9PWTdkTHA4RXZLRktDSVo4MUMreTJ6OTlPbz0=");

        thrown.expectMessage("User info extraction error!");
        verificationService.verifyTokens(tokens, client);
    }

    @Test
    public void shouldFailVerifyIfAudienceWrong() {
        Client client = new Client();
        client.setId("other-app");
        client.setSecret(SECRET);

        thrown.expect(RuntimeException.class);
        thrown.expectMessage("Audience is wrong!");
        verificationService.verifyTokens(tokens, client);
    }
}
