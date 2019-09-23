package ru.ratauth.gatekeeper.example;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import io.restassured.http.Cookie;
import io.restassured.module.webtestclient.response.WebTestClientResponse;
import io.restassured.response.ExtractableResponse;
import net.minidev.json.JSONObject;
import org.hamcrest.core.IsEqual;
import org.hamcrest.core.StringStartsWith;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.cloud.contract.wiremock.AutoConfigureWireMock;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.test.context.junit4.SpringRunner;
import org.springframework.test.web.reactive.server.WebTestClient;
import org.springframework.util.MultiValueMap;
import org.springframework.web.util.UriComponentsBuilder;
import org.yaml.snakeyaml.external.biz.base64Coder.Base64Coder;

import java.net.URI;
import java.net.URLDecoder;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.UUID;

import static com.github.tomakehurst.wiremock.client.WireMock.*;
import static io.restassured.module.webtestclient.RestAssuredWebTestClient.given;
import static java.nio.charset.StandardCharsets.UTF_8;
import static org.assertj.core.api.Assertions.assertThat;
import static org.springframework.http.HttpStatus.FOUND;
import static org.springframework.http.HttpStatus.OK;

@RunWith(SpringRunner.class)
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.DEFINED_PORT)
@AutoConfigureWireMock(port = 9081)
public class FirstExampleAppTest {
    private final static String APP_BASE_URL = "http://localhost:9082";
    private final static String AUTHORIZATION_PAGE_URI = "http://localhost:9081/authorize";
    private final static String CLIENT_ID = "test-app";
    private final static String PASSWORD = "pass";
    private final static String SCOPE = "profile";
    private final static String SECRET = "t1X23HldJAncMr3zOOY7dLp8EvKFKCIZ81C+y2z99Oo=";

    @Test
    public void shouldSuccessCompleteCodeFlow() throws Exception {
        WebTestClient webTestClient = WebTestClient.bindToServer()
                .baseUrl(APP_BASE_URL)
                .build();

        ExtractableResponse<WebTestClientResponse> authorizeRedirectResponse = given().webTestClient(webTestClient)
                .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                .when()
                .get("/sample-app/hello?param=value")
                .then()
                .status(FOUND)
                .header("Location", StringStartsWith.startsWith(AUTHORIZATION_PAGE_URI))
                .extract();

        Cookie unauthorizedCookie = authorizeRedirectResponse.detailedCookie("SESSION");
        assertThat(unauthorizedCookie.getValue())
                .isNotEmpty();

        String authorizationUriLocation = authorizeRedirectResponse.header("Location");

        MultiValueMap<String, String> queryParams = UriComponentsBuilder.fromHttpUrl(authorizationUriLocation)
                .build()
                .getQueryParams();

        assertThat(queryParams.size()).isEqualTo(3);
        assertThat(queryParams.getFirst("response_type")).isEqualTo("code");
        assertThat(queryParams.getFirst("client_id")).isEqualTo(CLIENT_ID);
        String scope = queryParams.getFirst("scope");
        assertThat(scope).isNotNull();
        assertThat(URLDecoder.decode(scope, UTF_8)).isEqualTo("openid " + SCOPE);

        //perform redirect to client with code and state
        String authCode = UUID.randomUUID().toString();
        URI authorizeRedirectPath = UriComponentsBuilder.fromUriString(APP_BASE_URL + "/openid/authorize/" + CLIENT_ID)
                .queryParam("code", authCode)
                .build()
                .toUri();

        stubFor(post(urlEqualTo("/token"))
                .withBasicAuth(CLIENT_ID, PASSWORD)
                .withHeader(HttpHeaders.CONTENT_TYPE, containing(MediaType.APPLICATION_FORM_URLENCODED_VALUE))
                .withRequestBody(containing("grant_type=authorization_code"))
                .withRequestBody(containing("code=" + authCode))
                .willReturn(aResponse()
                        .withStatus(OK.value())
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.APPLICATION_JSON_VALUE)
                        .withBody(getTokenMockResponseBody())
                )
        );

        Cookie authorizedCookie = given().webTestClient(webTestClient)
                .cookie(unauthorizedCookie)
                .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                .when()
                .get(authorizeRedirectPath)
                .then()
                .status(FOUND)
                .header("Location", IsEqual.equalTo(APP_BASE_URL + "/sample-app/hello?param=value"))
                .extract()
                .detailedCookie("SESSION");

        assertThat(authorizedCookie.getValue()).isNotEqualTo(unauthorizedCookie.getValue());

        stubFor(get(urlMatching("/hello"))
                .withCookie("SESSION", equalTo(authorizedCookie.getValue()))
                .willReturn(aResponse()
                        .withHeader(HttpHeaders.CONTENT_TYPE, MediaType.TEXT_HTML_VALUE)
                        .withStatus(OK.value())
                        .withBody("Hello!")
                )
        );

        String helloResponseBody = given().webTestClient(webTestClient)
                .cookie(authorizedCookie)
                .header(HttpHeaders.ACCEPT, MediaType.TEXT_HTML_VALUE)
                .when()
                .get("/sample-app/hello")
                .then()
                .statusCode(OK.value())
                .extract()
                .body()
                .asString();

        assertThat(helloResponseBody).isEqualTo("Hello!");
    }

    private String getTokenMockResponseBody() throws Exception {
        String idToken = getSignedIdToken();
        String accessToken = UUID.randomUUID().toString();
        String refreshToken = UUID.randomUUID().toString();
        String tokenType = "BEARER";
        long expiresIn = 60; //sec
        return new JSONObject().appendField("id_token", idToken)
                .appendField("access_token", accessToken)
                .appendField("refresh_token", refreshToken)
                .appendField("token_type", tokenType)
                .appendField("expires_in", expiresIn)
                .toJSONString();
    }

    private String getSignedIdToken() throws Exception {
        MACSigner signer = new MACSigner(Base64Coder.decodeLines(SECRET));
        Instant now = Instant.now();
        Date expirationTime = Date.from(now.plus(Duration.ofSeconds(120)));
        Date issueTime = Date.from(now); //iat
        JWTClaimsSet claimsSet = new JWTClaimsSet.Builder()
                .issuer("http://www.example-1.com/")
                .subject("QWE123")
                .audience(CLIENT_ID)
                .expirationTime(expirationTime)
                .issueTime(issueTime)
                .build();
        SignedJWT idToken = new SignedJWT(new JWSHeader(JWSAlgorithm.HS256), claimsSet);
        idToken.sign(signer);
        return idToken.serialize();
    }
}
