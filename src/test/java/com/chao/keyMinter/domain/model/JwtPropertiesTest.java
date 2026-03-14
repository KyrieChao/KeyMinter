package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.*;

class JwtPropertiesTest {

    @Test
    void testNoArgsConstructor() {
        JwtProperties jwtProperties = new JwtProperties();
        assertNull(jwtProperties.getSubject());
        assertNull(jwtProperties.getIssuer());
        assertNull(jwtProperties.getExpiration());
    }

    @Test
    void testAllArgsConstructor() {
        String subject = "test-subject";
        String issuer = "test-issuer";
        Instant expiration = Instant.now().plusSeconds(3600);

        JwtProperties jwtProperties = new JwtProperties(subject, issuer, expiration);
        assertEquals(subject, jwtProperties.getSubject());
        assertEquals(issuer, jwtProperties.getIssuer());
        assertEquals(expiration, jwtProperties.getExpiration());
    }

    @Test
    void testBuilder() {
        String subject = "test-subject";
        String issuer = "test-issuer";
        Instant expiration = Instant.now().plusSeconds(3600);

        JwtProperties jwtProperties = JwtProperties.builder()
                .subject(subject)
                .issuer(issuer)
                .expiration(expiration)
                .build();

        assertEquals(subject, jwtProperties.getSubject());
        assertEquals(issuer, jwtProperties.getIssuer());
        assertEquals(expiration, jwtProperties.getExpiration());
    }

    @Test
    void testSetters() {
        JwtProperties jwtProperties = new JwtProperties();

        String subject = "test-subject";
        String issuer = "test-issuer";
        Instant expiration = Instant.now().plusSeconds(3600);

        jwtProperties.setSubject(subject);
        jwtProperties.setIssuer(issuer);
        jwtProperties.setExpiration(expiration);

        assertEquals(subject, jwtProperties.getSubject());
        assertEquals(issuer, jwtProperties.getIssuer());
        assertEquals(expiration, jwtProperties.getExpiration());
    }

    @Test
    void testEqualsAndHashCode() {
        Instant expiration = Instant.now().plusSeconds(3600);

        JwtProperties jwtProperties1 = JwtProperties.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .expiration(expiration)
                .build();

        JwtProperties jwtProperties2 = JwtProperties.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .expiration(expiration)
                .build();

        JwtProperties jwtProperties3 = JwtProperties.builder()
                .subject("different-subject")
                .issuer("test-issuer")
                .expiration(expiration)
                .build();

        // 测试equals
        assertEquals(jwtProperties1, jwtProperties2);
        assertNotEquals(jwtProperties1, jwtProperties3);
        assertNotEquals(jwtProperties1, null);
        assertNotEquals(jwtProperties1, "not a JwtProperties");

        // 测试hashCode
        assertEquals(jwtProperties1.hashCode(), jwtProperties2.hashCode());
        assertNotEquals(jwtProperties1.hashCode(), jwtProperties3.hashCode());
    }

    @Test
    void testToString() {
        JwtProperties jwtProperties = JwtProperties.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .expiration(Instant.now())
                .build();

        String toString = jwtProperties.toString();
        assertNotNull(toString);
        assertTrue(toString.contains("test-subject"));
        assertTrue(toString.contains("test-issuer"));
    }
}
