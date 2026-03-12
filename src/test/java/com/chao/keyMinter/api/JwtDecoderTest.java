package com.chao.keyMinter.api;

import com.chao.keyMinter.domain.service.JwtAlgo;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import lombok.Data;
import org.junit.jupiter.api.Test;
import org.mockito.Mockito;

import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class JwtDecoderTest {

    @Test
    void testDecodeToObject() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        Claims claims = Jwts.claims()
                .add("username", "test-user")
                .add("age", 30)
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        TestUser user = JwtDecoder.decodeToObject(token, TestUser.class, jwtAlgo);
        assertNotNull(user);
        assertEquals("test-user", user.getUsername());
        assertEquals(30, user.getAge());
    }

    @Test
    void testDecodeStandardInfo() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";
        Date now = new Date();
        Date exp = new Date(now.getTime() + 3600000);
        
        Claims claims = Jwts.claims()
                .subject("sub")
                .issuer("iss")
                .issuedAt(now)
                .expiration(exp)
                .build();
        
        when(jwtAlgo.decodePayload(token)).thenReturn(claims);
        
        var info = JwtDecoder.decodeStandardInfo(token, jwtAlgo);
        assertNotNull(info);
        assertEquals("sub", info.getSubject());
        assertEquals("iss", info.getIssuer());
        
        // Use tolerance for date comparison due to JWT seconds precision vs Java milliseconds
        long tolerance = 1000;
        assertTrue(Math.abs(now.getTime() - info.getIssuedAt().getTime()) <= tolerance);
        assertTrue(Math.abs(exp.getTime() - info.getExpiration().getTime()) <= tolerance);
    }

    @Test
    void testDecodeToFullMap() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        Claims claims = Jwts.claims()
                .subject("sub")
                .add("custom", "value")
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        Map<String, Object> map = JwtDecoder.decodeToFullMap(token, jwtAlgo);
        assertEquals("sub", map.get("subject"));
        assertEquals("value", map.get("custom"));
    }

    @Test
    void testInvalidInputs() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeToObject(null, TestUser.class, jwtAlgo));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeToObject("token", TestUser.class, null));
    }

    // Helper class for testing
    @Data
    static class TestUser {
        private String username;
        private int age;
    }
}



