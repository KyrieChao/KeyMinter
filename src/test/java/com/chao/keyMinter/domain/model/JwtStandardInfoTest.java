package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.util.Date;

import static org.junit.jupiter.api.Assertions.*;

class JwtStandardInfoTest {

    @Test
    void testBuilderAndGetters() {
        String subject = "test-subject";
        String issuer = "test-issuer";
        Date issuedAt = new Date();
        Date expiration = new Date(System.currentTimeMillis() + 3600000);

        JwtStandardInfo jwtStandardInfo = JwtStandardInfo.builder()
                .subject(subject)
                .issuer(issuer)
                .issuedAt(issuedAt)
                .expiration(expiration)
                .build();

        assertEquals(subject, jwtStandardInfo.getSubject());
        assertEquals(issuer, jwtStandardInfo.getIssuer());
        assertEquals(issuedAt, jwtStandardInfo.getIssuedAt());
        assertEquals(expiration, jwtStandardInfo.getExpiration());
    }

    @Test
    void testGetRemainingTimeWithNonNullExpiration() {
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        JwtStandardInfo jwtStandardInfo = JwtStandardInfo.builder()
                .expiration(expiration)
                .build();

        long remainingTime = jwtStandardInfo.getRemainingTime();
        assertTrue(remainingTime > 0);
        assertTrue(remainingTime <= 3600000);
    }

    @Test
    void testGetRemainingTimeWithNullExpiration() {
        JwtStandardInfo jwtStandardInfo = JwtStandardInfo.builder()
                .expiration(null)
                .build();

        assertEquals(0, jwtStandardInfo.getRemainingTime());
    }

    @Test
    void testIsExpiredWithFutureExpiration() {
        Date expiration = new Date(System.currentTimeMillis() + 3600000);
        JwtStandardInfo jwtStandardInfo = JwtStandardInfo.builder()
                .expiration(expiration)
                .build();

        assertFalse(jwtStandardInfo.isExpired());
    }

    @Test
    void testIsExpiredWithPastExpiration() {
        Date expiration = new Date(System.currentTimeMillis() - 3600000);
        JwtStandardInfo jwtStandardInfo = JwtStandardInfo.builder()
                .expiration(expiration)
                .build();

        assertTrue(jwtStandardInfo.isExpired());
    }

    @Test
    void testIsExpiredWithNullExpiration() {
        JwtStandardInfo jwtStandardInfo = JwtStandardInfo.builder()
                .expiration(null)
                .build();

        assertTrue(jwtStandardInfo.isExpired());
    }

    @Test
    void testEqualsAndHashCode() {
        Date issuedAt = new Date();
        Date expiration = new Date(System.currentTimeMillis() + 3600000);

        JwtStandardInfo jwtStandardInfo1 = JwtStandardInfo.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .issuedAt(issuedAt)
                .expiration(expiration)
                .build();

        JwtStandardInfo jwtStandardInfo2 = JwtStandardInfo.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .issuedAt(issuedAt)
                .expiration(expiration)
                .build();

        JwtStandardInfo jwtStandardInfo3 = JwtStandardInfo.builder()
                .subject("different-subject")
                .issuer("test-issuer")
                .issuedAt(issuedAt)
                .expiration(expiration)
                .build();

        // 测试equals
        assertEquals(jwtStandardInfo1, jwtStandardInfo2);
        assertNotEquals(jwtStandardInfo1, jwtStandardInfo3);
        assertNotEquals(jwtStandardInfo1, null);
        assertNotEquals(jwtStandardInfo1, "not a JwtStandardInfo");

        // 测试hashCode
        assertEquals(jwtStandardInfo1.hashCode(), jwtStandardInfo2.hashCode());
        assertNotEquals(jwtStandardInfo1.hashCode(), jwtStandardInfo3.hashCode());
    }

    @Test
    void testToString() {
        JwtStandardInfo jwtStandardInfo = JwtStandardInfo.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600000))
                .build();

        String toString = jwtStandardInfo.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("test-subject"));
        assertTrue(toString.contains("test-issuer"));
    }
}
