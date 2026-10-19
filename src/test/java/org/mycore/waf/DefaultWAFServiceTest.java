package org.mycore.waf;

import static org.junit.jupiter.api.Assertions.assertEquals;

import com.auth0.jwt.JWT;
import com.auth0.jwt.algorithms.Algorithm;
import com.auth0.jwt.interfaces.DecodedJWT;
import java.time.Instant;
import org.junit.jupiter.api.Test;

class DefaultWAFServiceTest {

    private static final Algorithm ALGORITHM = Algorithm.HMAC256("test-secret");

    @Test
    void elapsedTimeHasMillisecondPrecision() {
        Instant issued = Instant.parse("2026-10-19T10:00:00.900Z");
        DecodedJWT jwt = JWT.decode(JWT.create()
            .withClaim(DefaultWAFService.ISSUED_MILLIS_CLAIM, issued.toEpochMilli())
            .sign(ALGORITHM));

        // A submit directly after issuing must not gain the up to one second lost by the iat claim
        assertEquals(0, DefaultWAFService.getMillisSinceIssue(jwt, issued));
        assertEquals(50, DefaultWAFService.getMillisSinceIssue(jwt, issued.plusMillis(50)));
        assertEquals(1600, DefaultWAFService.getMillisSinceIssue(jwt, issued.plusMillis(1600)));
    }

    @Test
    void tokenWithoutIssueTimeIsIncomplete() {
        DecodedJWT jwt = JWT.decode(JWT.create().withIssuedAt(Instant.now()).sign(ALGORITHM));
        assertEquals(-1, DefaultWAFService.getMillisSinceIssue(jwt, Instant.now()));
    }

}
