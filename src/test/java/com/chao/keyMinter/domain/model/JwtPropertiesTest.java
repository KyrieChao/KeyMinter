package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;

import static org.junit.jupiter.api.Assertions.assertEquals;

class JwtPropertiesTest {

    @Test
    void testToString() {
        Instant fixedTime = Instant.parse("2026-03-13T01:54:24.109182500Z");
        JwtProperties jwtProperties = JwtProperties.builder()
                .subject("test")
                .issuer("test")
                .expiration(fixedTime)
                .build();
        String expected = "JwtProperties(subject=test, issuer=test, expiration=2026-03-13T01:54:24.109182500Z)";
        assertEquals(expected, jwtProperties.toString());
    }
}