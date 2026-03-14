package com.chao.keyMinter.api;

import com.chao.keyMinter.domain.service.JwtAlgo;
import com.chao.keyMinter.domain.model.JwtFullInfo;
import com.chao.keyMinter.domain.model.JwtStandardInfo;
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
    void testDecodeToObjectException() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));

        assertThrows(JwtDecoder.JwtDecodeException.class, () -> {
            JwtDecoder.decodeToObject(token, TestUser.class, jwtAlgo);
        });
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
        
        JwtStandardInfo info = JwtDecoder.decodeStandardInfo(token, jwtAlgo);
        assertNotNull(info);
        assertEquals("sub", info.getSubject());
        assertEquals("iss", info.getIssuer());
        
        // Use tolerance for date comparison due to JWT seconds precision vs Java milliseconds
        long tolerance = 1000;
        assertTrue(Math.abs(now.getTime() - info.getIssuedAt().getTime()) <= tolerance);
        assertTrue(Math.abs(exp.getTime() - info.getExpiration().getTime()) <= tolerance);
    }

    @Test
    void testDecodeStandardInfoException() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));

        JwtStandardInfo info = JwtDecoder.decodeStandardInfo(token, jwtAlgo);
        assertNull(info);
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
    void testDecodeToFullMapException() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));

        assertThrows(JwtDecoder.JwtDecodeException.class, () -> {
            JwtDecoder.decodeToFullMap(token, jwtAlgo);
        });
    }

    @Test
    void testDecodeToFullInfo() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";
        Date now = new Date();
        Date exp = new Date(now.getTime() + 3600000);

        Claims claims = Jwts.claims()
                .subject("sub")
                .issuer("iss")
                .issuedAt(now)
                .expiration(exp)
                .add("username", "test-user")
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        JwtFullInfo<TestUser> fullInfo = JwtDecoder.decodeToFullInfo(token, TestUser.class, jwtAlgo);
        assertNotNull(fullInfo);
        assertNotNull(fullInfo.getStandardInfo());
        assertEquals("sub", fullInfo.getStandardInfo().getSubject());
        assertNotNull(fullInfo.getCustomClaims());
        assertEquals("test-user", fullInfo.getCustomClaims().getUsername());
        assertNotNull(fullInfo.getAllClaims());
    }

    @Test
    void testDecodeToFullInfoException() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));

        assertThrows(JwtDecoder.JwtDecodeException.class, () -> {
            JwtDecoder.decodeToFullInfo(token, TestUser.class, jwtAlgo);
        });
    }

    @Test
    void testDecodeToFullInfoSafe() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";
        Date now = new Date();
        Date exp = new Date(now.getTime() + 3600000);

        Claims claims = Jwts.claims()
                .subject("sub")
                .issuer("iss")
                .issuedAt(now)
                .expiration(exp)
                .add("username", "test-user")
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        // Test with valid inputs
        JwtFullInfo<TestUser> fullInfo = JwtDecoder.decodeToFullInfoSafe(token, TestUser.class, jwtAlgo);
        assertNotNull(fullInfo);

        // Test with null token
        JwtFullInfo<TestUser> nullTokenResult = JwtDecoder.decodeToFullInfoSafe(null, TestUser.class, jwtAlgo);
        assertNull(nullTokenResult);

        // Test with null jwtAlgo
        JwtFullInfo<TestUser> nullAlgoResult = JwtDecoder.decodeToFullInfoSafe(token, TestUser.class, null);
        assertNull(nullAlgoResult);

        // Test with null clazz
        JwtFullInfo<TestUser> nullClazzResult = JwtDecoder.decodeToFullInfoSafe(token, null, jwtAlgo);
        assertNull(nullClazzResult);

        // Test with exception
        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));
        JwtFullInfo<TestUser> exceptionResult = JwtDecoder.decodeToFullInfoSafe(token, TestUser.class, jwtAlgo);
        assertNull(exceptionResult);
    }

    @Test
    void testDecodeExpiration() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";
        Date exp = new Date();

        Claims claims = Jwts.claims()
                .expiration(exp)
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        Date result = JwtDecoder.decodeExpiration(token, jwtAlgo);
        assertNotNull(result);

        // Test with null token
        Date nullTokenResult = JwtDecoder.decodeExpiration(null, jwtAlgo);
        assertNull(nullTokenResult);

        // Test with null jwtAlgo
        Date nullAlgoResult = JwtDecoder.decodeExpiration(token, null);
        assertNull(nullAlgoResult);

        // Test with exception
        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));
        Date exceptionResult = JwtDecoder.decodeExpiration(token, jwtAlgo);
        assertNull(exceptionResult);
    }

    @Test
    void testDecodeIssuedAt() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";
        Date iat = new Date();

        Claims claims = Jwts.claims()
                .issuedAt(iat)
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        Date result = JwtDecoder.decodeIssuedAt(token, jwtAlgo);
        assertNotNull(result);

        // Test with null token
        Date nullTokenResult = JwtDecoder.decodeIssuedAt(null, jwtAlgo);
        assertNull(nullTokenResult);

        // Test with null jwtAlgo
        Date nullAlgoResult = JwtDecoder.decodeIssuedAt(token, null);
        assertNull(nullAlgoResult);

        // Test with exception
        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));
        Date exceptionResult = JwtDecoder.decodeIssuedAt(token, jwtAlgo);
        assertNull(exceptionResult);
    }

    @Test
    void testDecodeCustomClaims() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .add("age", 30)
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        TestUser result = JwtDecoder.decodeCustomClaims(token, jwtAlgo, TestUser.class);
        assertNotNull(result);
        assertEquals("test-user", result.getUsername());
        assertEquals(30, result.getAge());

        // Test with exception
        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));
        TestUser exceptionResult = JwtDecoder.decodeCustomClaims(token, jwtAlgo, TestUser.class);
        assertNull(exceptionResult);
    }

    @Test
    void testDecodeCustomClaimsSafe() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .add("age", 30)
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        // Test with valid inputs
        TestUser result = JwtDecoder.decodeCustomClaimsSafe(token, jwtAlgo, TestUser.class);
        assertNotNull(result);

        // Test with null token
        TestUser nullTokenResult = JwtDecoder.decodeCustomClaimsSafe(null, jwtAlgo, TestUser.class);
        assertNull(nullTokenResult);

        // Test with null jwtAlgo
        TestUser nullAlgoResult = JwtDecoder.decodeCustomClaimsSafe(token, null, TestUser.class);
        assertNull(nullAlgoResult);

        // Test with null clazz
        TestUser nullClazzResult = JwtDecoder.decodeCustomClaimsSafe(token, jwtAlgo, null);
        assertNull(nullClazzResult);

        // Test with exception
        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));
        TestUser exceptionResult = JwtDecoder.decodeCustomClaimsSafe(token, jwtAlgo, TestUser.class);
        assertNull(exceptionResult);
    }

    @Test
    void testIsTokenDecodable() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        when(jwtAlgo.decodePayload(token)).thenReturn(Jwts.claims().build());

        // Test with valid token
        boolean result = JwtDecoder.isTokenDecodable(token, jwtAlgo);
        assertTrue(result);

        // Test with null token
        boolean nullTokenResult = JwtDecoder.isTokenDecodable(null, jwtAlgo);
        assertFalse(nullTokenResult);

        // Test with null jwtAlgo
        boolean nullAlgoResult = JwtDecoder.isTokenDecodable(token, null);
        assertFalse(nullAlgoResult);

        // Test with exception
        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));
        boolean exceptionResult = JwtDecoder.isTokenDecodable(token, jwtAlgo);
        assertFalse(exceptionResult);
    }

    @Test
    void testInvalidInputs() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeToObject(null, TestUser.class, jwtAlgo));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeToObject("token", TestUser.class, null));
        assertThrows(NullPointerException.class, () -> JwtDecoder.decodeToObject("token", null, jwtAlgo));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeToFullMap(null, jwtAlgo));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeToFullMap("token", null));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeToFullInfo(null, TestUser.class, jwtAlgo));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeToFullInfo("token", TestUser.class, null));
        assertThrows(NullPointerException.class, () -> JwtDecoder.decodeToFullInfo("token", null, jwtAlgo));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeStandardInfo(null, jwtAlgo));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeStandardInfo("token", null));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeCustomClaims(null, jwtAlgo, TestUser.class));
        assertThrows(IllegalArgumentException.class, () -> JwtDecoder.decodeCustomClaims("token", null, TestUser.class));
        assertThrows(NullPointerException.class, () -> JwtDecoder.decodeCustomClaims("token", jwtAlgo, null));
    }

    @Test
    void testConvertCustomClaimsWithMap() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .add("age", 30)
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        Map<String, Object> result = JwtDecoder.decodeCustomClaims(token, jwtAlgo, Map.class);
        assertNotNull(result);
        assertEquals("test-user", result.get("username"));
        assertEquals(30, result.get("age"));
    }

    @Test
    void testConvertCustomClaimsWithEmptyMap() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        // Create claims with only standard claims
        Claims claims = Jwts.claims()
                .subject("sub")
                .issuer("iss")
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        // Test with Map class
        Map<String, Object> result = JwtDecoder.decodeCustomClaims(token, jwtAlgo, Map.class);
        assertNotNull(result);
        assertTrue(result.isEmpty());
    }

    @Test
    void testJwtDecodeException() {
        // Test default constructor
        JwtDecoder.JwtDecodeException exception1 = new JwtDecoder.JwtDecodeException("Test message");
        assertEquals("Test message", exception1.getMessage());

        // Test constructor with cause
        RuntimeException cause = new RuntimeException("Cause");
        JwtDecoder.JwtDecodeException exception2 = new JwtDecoder.JwtDecodeException("Test message", cause);
        assertEquals("Test message", exception2.getMessage());
        assertEquals(cause, exception2.getCause());
    }

    @Test
    void testDecodeCustomClaimsSafeWithException() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        // Mock decodePayload to throw an exception
        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));

        // Test with exception
        TestUser result = JwtDecoder.decodeCustomClaimsSafe(token, jwtAlgo, TestUser.class);
        assertNull(result);
    }

    @Test
    void testDecodeCustomClaimsSafeAllConditions() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "dummy-token";

        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .build();

        when(jwtAlgo.decodePayload(token)).thenReturn(claims);

        // Test with valid inputs
        TestUser result = JwtDecoder.decodeCustomClaimsSafe(token, jwtAlgo, TestUser.class);
        assertNotNull(result);
        assertEquals("test-user", result.getUsername());

        // Test with null token
        TestUser nullTokenResult = JwtDecoder.decodeCustomClaimsSafe(null, jwtAlgo, TestUser.class);
        assertNull(nullTokenResult);

        // Test with null jwtAlgo
        TestUser nullAlgoResult = JwtDecoder.decodeCustomClaimsSafe(token, null, TestUser.class);
        assertNull(nullAlgoResult);

        // Test with null clazz
        TestUser nullClazzResult = JwtDecoder.decodeCustomClaimsSafe(token, jwtAlgo, null);
        assertNull(nullClazzResult);

        // Test with exception
        when(jwtAlgo.decodePayload(token)).thenThrow(new RuntimeException("Test exception"));
        TestUser exceptionResult = JwtDecoder.decodeCustomClaimsSafe(token, jwtAlgo, TestUser.class);
        assertNull(exceptionResult);
    }

    @Test
    void testDecodeCustomClaimsSafeWithEmptyToken() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "";

        // Test with empty token
        TestUser result = JwtDecoder.decodeCustomClaimsSafe(token, jwtAlgo, TestUser.class);
        assertNull(result);
    }

    @Test
    void testDecodeCustomClaimsSafeWithBlankToken() {
        JwtAlgo jwtAlgo = Mockito.mock(JwtAlgo.class);
        String token = "   ";

        // Test with blank token
        TestUser result = JwtDecoder.decodeCustomClaimsSafe(token, jwtAlgo, TestUser.class);
        assertNull(result);
    }

    @Test
    void testConvertCustomClaimsWithMergeFunctionOverload() {
        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .build();

        try {
            var method = JwtDecoder.class.getDeclaredMethod("convertCustomClaims", Claims.class, Class.class);
            method.setAccessible(true);
            TestUser result = (TestUser) method.invoke(null, claims, TestUser.class);
            assertNotNull(result);
            assertEquals("test-user", result.getUsername());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testConvertCustomClaimsWithMapAndMerge() {
        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .add("age", 30)
                .build();

        try {
            var method = JwtDecoder.class.getDeclaredMethod("convertCustomClaims", Claims.class, Class.class);
            method.setAccessible(true);
            Map<String, Object> result = (Map<String, Object>) method.invoke(null, claims, Map.class);
            assertNotNull(result);
            assertEquals(2, result.size());
            assertEquals("test-user", result.get("username"));
            assertEquals(30, result.get("age"));
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testConvertCustomClaimsException() {
        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .build();

        // Test with a class that cannot be instantiated
        try {
            var method = JwtDecoder.class.getDeclaredMethod("convertCustomClaims", Claims.class, Class.class);
            method.setAccessible(true);
            method.invoke(null, claims, String.class);
        } catch (Exception e) {
            // The method should throw JwtDecodeException
            assertTrue(e.getCause() instanceof JwtDecoder.JwtDecodeException);
        }
    }

    @Test
    void testConvertCustomClaimsWithEmptyMapAndMapClass() {
        Claims claims = Jwts.claims()
                .subject("sub")
                .issuer("iss")
                .build();

        try {
            var method = JwtDecoder.class.getDeclaredMethod("convertCustomClaims", Claims.class, Class.class);
            method.setAccessible(true);
            Map<String, Object> result = (Map<String, Object>) method.invoke(null, claims, Map.class);
            assertNotNull(result);
            assertTrue(result.isEmpty());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testConvertCustomClaimsWithMapClass() {
        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .add("age", 30)
                .build();

        try {
            var method = JwtDecoder.class.getDeclaredMethod("convertCustomClaims", Claims.class, Class.class);
            method.setAccessible(true);
            Map<String, Object> result = (Map<String, Object>) method.invoke(null, claims, Map.class);
            assertNotNull(result);
            assertEquals(2, result.size());
            assertEquals("test-user", result.get("username"));
            assertEquals(30, result.get("age"));
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testConvertCustomClaimsWithEmptyMapAndNonMapClass() {
        Claims claims = Jwts.claims()
                .subject("sub")
                .issuer("iss")
                .build();

        try {
            var method = JwtDecoder.class.getDeclaredMethod("convertCustomClaims", Claims.class, Class.class);
            method.setAccessible(true);
            TestUser result = (TestUser) method.invoke(null, claims, TestUser.class);
            assertNotNull(result);
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testConvertCustomClaimsWithMergeFunction() {
        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .build();

        try {
            var method = JwtDecoder.class.getDeclaredMethod("convertCustomClaims", Claims.class, Class.class);
            method.setAccessible(true);
            TestUser result = (TestUser) method.invoke(null, claims, TestUser.class);
            assertNotNull(result);
            assertEquals("test-user", result.getUsername());
        } catch (Exception e) {
            fail(e);
        }
    }

    @Test
    void testConvertToFullObjectException() {
        Claims claims = Jwts.claims()
                .subject("sub")
                .add("username", "test-user")
                .build();

        // Test with a class that cannot be instantiated
        try {
            var method = JwtDecoder.class.getDeclaredMethod("convertToFullObject", Claims.class, Class.class);
            method.setAccessible(true);
            method.invoke(null, claims, String.class);
        } catch (Exception e) {
            // The method should throw JwtDecodeException
            assertTrue(e.getCause() instanceof JwtDecoder.JwtDecodeException);
        }
    }

    @Test
    void testCreateCleanFullClaimsMap() {
        Claims claims = Jwts.claims()
                .subject("sub")
                .issuer("iss")
                .issuedAt(new Date())
                .expiration(new Date())
                .add("jti", "token-id") // Standard claim that should be filtered
                .add("aud", "audience") // Standard claim that should be filtered
                .add("nbf", new Date()) // Standard claim that should be filtered
                .add("username", "test-user") // Custom claim that should be included
                .add("age", 30) // Custom claim that should be included
                .build();

        try {
            var method = JwtDecoder.class.getDeclaredMethod("createCleanFullClaimsMap", Claims.class);
            method.setAccessible(true);
            Map<String, Object> result = (Map<String, Object>) method.invoke(null, claims);
            assertNotNull(result);
            
            // Should contain the 4 standard claims
            assertTrue(result.containsKey("subject"));
            assertTrue(result.containsKey("issuer"));
            assertTrue(result.containsKey("issuedAt"));
            assertTrue(result.containsKey("expiration"));
            
            // Should not contain other standard claims
            assertFalse(result.containsKey("jti"));
            assertFalse(result.containsKey("aud"));
            assertFalse(result.containsKey("nbf"));
            
            // Should contain custom claims
            assertTrue(result.containsKey("username"));
            assertTrue(result.containsKey("age"));
            assertEquals("test-user", result.get("username"));
            assertEquals(30, result.get("age"));
        } catch (Exception e) {
            fail(e);
        }
    }

    // Helper class for testing
    static class TestUser {
        private String username;
        private int age;

        public String getUsername() {
            return username;
        }

        public void setUsername(String username) {
            this.username = username;
        }

        public int getAge() {
            return age;
        }

        public void setAge(int age) {
            this.age = age;
        }
    }
}