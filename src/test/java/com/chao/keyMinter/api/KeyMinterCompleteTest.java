package com.chao.keyMinter.api;

import com.chao.keyMinter.core.JwtFactory;
import com.chao.keyMinter.domain.model.*;
import com.chao.keyMinter.domain.service.JwtAlgo;
import io.jsonwebtoken.Claims;
import lombok.Data;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.Collections;
import java.util.Date;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@Slf4j
class KeyMinterCompleteTest {

    @Mock
    JwtFactory jwtFactory;

    @Mock
    JwtAlgo defaultAlgo;

    @Mock
    JwtAlgo newAlgo;

    @Mock
    JwtAlgo ecdsaAlgo;

    @Mock
    KeyVersion keyVersion;

    private KeyMinter key;

    private final static String TOKEN = "test.jwt.token";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(defaultAlgo.getKeyInfo()).thenReturn("kid-001");
        when(defaultAlgo.getAlgorithmInfo()).thenReturn("Default Algo Info");
        when(defaultAlgo.keyPairExists()).thenReturn(false);
        when(defaultAlgo.keyPairExists(any())).thenReturn(false);
        when(defaultAlgo.getActiveKeyId()).thenReturn("kid-001");
        when(defaultAlgo.getKeyPath()).thenReturn(Paths.get("/tmp/keys"));
        when(defaultAlgo.listAllKeys()).thenReturn(Collections.emptyList());
        when(defaultAlgo.listAllKeys(anyString())).thenReturn(Collections.emptyList());
        when(defaultAlgo.listKeys(any())).thenReturn(Collections.emptyList());
        when(defaultAlgo.listKeys(any(), anyString())).thenReturn(Collections.emptyList());
        when(defaultAlgo.getKeyVersions()).thenReturn(Collections.emptyList());
        when(defaultAlgo.getKeyVersions(any())).thenReturn(Collections.emptyList());
        when(defaultAlgo.getKeyVersionsByStatus(any())).thenReturn(Collections.emptyList());
        when(defaultAlgo.setActiveKey(anyString())).thenReturn(true);
        when(defaultAlgo.verifyToken(anyString())).thenReturn(false);
        when(defaultAlgo.isECD(any())).thenReturn(false);

        key = new KeyMinter(jwtFactory);
    }

    @Test
    void testSwitchToWithException() {
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenThrow(new RuntimeException("Test exception"));

        boolean result = key.switchTo(Algorithm.RSA256);
        assertFalse(result);
    }

    @Test
    void testSwitchToWithAutoloadDirectory() {
        when(jwtFactory.get(Algorithm.RSA256, "test-dir")).thenReturn(newAlgo);
        when(jwtFactory.autoLoad(Algorithm.RSA256, "test-dir")).thenReturn(newAlgo);

        boolean result = key.switchTo(Algorithm.RSA256, "test-dir", null, true);
        assertTrue(result);
        verify(jwtFactory).autoLoad(Algorithm.RSA256, "test-dir");
    }

    @Test
    void testSwitchToWithPathException() {
        Path path = Paths.get("custom/path");
        when(jwtFactory.get(Algorithm.ES256, path)).thenThrow(new RuntimeException("Test exception"));

        boolean result = key.switchTo(Algorithm.ES256, path, false);
        assertFalse(result);
    }

    @Test
    void testSwitchToWithPathAndAutoload() {
        Path path = Paths.get("custom/path");
        when(jwtFactory.get(Algorithm.ES256, path)).thenReturn(newAlgo);
        when(jwtFactory.autoLoad(Algorithm.ES256)).thenReturn(newAlgo);

        boolean result = key.switchTo(Algorithm.ES256, path, true);
        assertTrue(result);
        verify(jwtFactory).autoLoad(Algorithm.ES256);
    }

    @Test
    void testAutoLoadWithForce() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519, true)).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, true);
        assertSame(newAlgo, result);
    }

    @Test
    void testAutoLoadWithDirectory() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519, "test-dir")).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, "test-dir");
        assertSame(newAlgo, result);
    }

    @Test
    void testAutoLoadWithPath() {
        Path path = Paths.get("test/path");
        when(jwtFactory.autoLoad(Algorithm.Ed25519, path)).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, path);
        assertSame(newAlgo, result);
    }

    @Test
    void testAutoLoadWithKeyIdAndForce() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519, "test-dir", "key1", true)).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, "test-dir", "key1", true);
        assertSame(newAlgo, result);
    }

    @Test
    void testCreateKeyPairWithSameAlgorithm() {
        // Set current algorithm to RSA256
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        key.switchTo(Algorithm.RSA256);

        when(newAlgo.generateKeyPair(Algorithm.RSA256)).thenReturn(true);
        boolean result = key.createKeyPair(Algorithm.RSA256);
        assertTrue(result);
    }

    @Test
    void testGetCustomClaims() {
        try (MockedStatic<JwtDecoder> mockedDecoder = Mockito.mockStatic(JwtDecoder.class)) {
            JwtFullInfo<String> fullInfo = new JwtFullInfo<>();
            fullInfo.setCustomClaims("test");
            mockedDecoder.when(() -> JwtDecoder.decodeToFullInfo(TOKEN, String.class, defaultAlgo)).thenReturn(fullInfo);

            String result = key.getCustomClaims(TOKEN, String.class);
            assertEquals("test", result);
        }
    }

    @Test
    void testGetCustomClaimsSafe() {
        try (MockedStatic<JwtDecoder> mockedDecoder = Mockito.mockStatic(JwtDecoder.class)) {
            // Test with non-null result
            JwtFullInfo<String> fullInfo = new JwtFullInfo<>();
            fullInfo.setCustomClaims("test");
            mockedDecoder.when(() -> JwtDecoder.decodeToFullInfoSafe(TOKEN, String.class, defaultAlgo)).thenReturn(fullInfo);

            String result = key.getCustomClaimsSafe(TOKEN, String.class);
            assertEquals("test", result);

            // Test with null result
            mockedDecoder.when(() -> JwtDecoder.decodeToFullInfoSafe(TOKEN, String.class, defaultAlgo)).thenReturn(null);
            result = key.getCustomClaimsSafe(TOKEN, String.class);
            assertNull(result);
        }
    }

    @Test
    void testGetFullInfo() {
        try (MockedStatic<JwtDecoder> mockedDecoder = Mockito.mockStatic(JwtDecoder.class)) {
            JwtFullInfo<String> fullInfo = new JwtFullInfo<>();
            fullInfo.setCustomClaims("test");
            mockedDecoder.when(() -> JwtDecoder.decodeToFullInfo(TOKEN, String.class, defaultAlgo)).thenReturn(fullInfo);

            JwtFullInfo<String> result = key.getFullInfo(TOKEN, String.class);
            assertSame(fullInfo, result);
        }
    }

    @Test
    void testGetFullInfoSafe() {
        try (MockedStatic<JwtDecoder> mockedDecoder = Mockito.mockStatic(JwtDecoder.class)) {
            JwtFullInfo<String> fullInfo = new JwtFullInfo<>();
            fullInfo.setCustomClaims("test");
            mockedDecoder.when(() -> JwtDecoder.decodeToFullInfoSafe(TOKEN, String.class, defaultAlgo)).thenReturn(fullInfo);

            JwtFullInfo<String> result = key.getFullInfoSafe(TOKEN, String.class);
            assertSame(fullInfo, result);
        }
    }

    @Test
    void testVerifyWithAlgorithm() {
        when(newAlgo.verifyToken(TOKEN)).thenReturn(true);
        boolean result = key.verifyWithAlgorithm(TOKEN, newAlgo);
        assertTrue(result);

        assertThrows(NullPointerException.class, () -> key.verifyWithAlgorithm(TOKEN, null));
    }

    @Test
    void testGetECDCurveInfo() {
        // Test with non-ECD algorithm
        String result = key.getECDCurveInfo();
        assertNull(result);

        // Test with ECD algorithm
        when(jwtFactory.get(Algorithm.ES256, (String) null)).thenReturn(ecdsaAlgo);
        when(ecdsaAlgo.isECD(Algorithm.ES256)).thenReturn(true);
        when(ecdsaAlgo.getCurveInfo(Algorithm.ES256)).thenReturn("P-256");
        key.switchTo(Algorithm.ES256);

        result = key.getECDCurveInfo();
        assertEquals("P-256", result);
    }

    @Test
    void testVerify() {
        when(jwtFactory.autoLoad(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(defaultAlgo.verifyToken(TOKEN)).thenReturn(true);

        boolean result = key.verify(Algorithm.HMAC256, TOKEN);
        assertTrue(result);
    }

    @Test
    void testDecodeStandardInfo() {
        try (MockedStatic<JwtDecoder> mockedDecoder = Mockito.mockStatic(JwtDecoder.class)) {
            JwtStandardInfo stdInfo = JwtStandardInfo.builder().subject("sub").build();
            when(jwtFactory.autoLoad(Algorithm.HMAC256)).thenReturn(defaultAlgo);
            mockedDecoder.when(() -> JwtDecoder.decodeStandardInfo(TOKEN, defaultAlgo)).thenReturn(stdInfo);

            JwtStandardInfo result = key.decodeStandardInfo(Algorithm.HMAC256, TOKEN);
            assertSame(stdInfo, result);
        }
    }

    @Test
    void testDecodeCustomInfo() {
        try (MockedStatic<JwtDecoder> mockedDecoder = Mockito.mockStatic(JwtDecoder.class)) {
            when(jwtFactory.autoLoad(Algorithm.HMAC256)).thenReturn(defaultAlgo);
            mockedDecoder.when(() -> JwtDecoder.decodeCustomClaimsSafe(TOKEN, defaultAlgo, String.class)).thenReturn("test");

            String result = key.decodeCustomInfo(Algorithm.HMAC256, TOKEN, String.class);
            assertEquals("test", result);
        }
    }

    @Test
    void testIsDecodable() {
        try (MockedStatic<JwtDecoder> mockedDecoder = Mockito.mockStatic(JwtDecoder.class)) {
            when(jwtFactory.autoLoad(Algorithm.HMAC256)).thenReturn(defaultAlgo);
            mockedDecoder.when(() -> JwtDecoder.isTokenDecodable(TOKEN, defaultAlgo)).thenReturn(true);

            boolean result = key.isDecodable(Algorithm.HMAC256, TOKEN);
            assertTrue(result);
        }
    }

    @Test
    void testGetKeyInfo() {
        when(jwtFactory.autoLoad(Algorithm.HMAC256, null, "key1")).thenReturn(defaultAlgo);
        when(defaultAlgo.getKeyInfo()).thenReturn("Key info");

        String result = key.getKeyInfo(Algorithm.HMAC256, "key1");
        assertEquals("Key info", result);
    }

    @Test
    void testGetKeyVersionsWithKeyId() {
        when(jwtFactory.autoLoad(Algorithm.HMAC256, null, "key1")).thenReturn(defaultAlgo);
        when(defaultAlgo.getKeyVersions()).thenReturn(List.of("v1", "v2"));

        String result = key.getKeyVersions(Algorithm.HMAC256, "key1");
        assertTrue(result.contains("v1"));
        assertTrue(result.contains("v2"));
    }

    @Test
    void testGenerateTokenWithAlgorithmAndKeyId() {
        JwtProperties props = JwtProperties.builder().subject("sub").build();
        when(jwtFactory.autoLoad(Algorithm.HMAC256, null, "key1")).thenReturn(defaultAlgo);
        when(defaultAlgo.generateToken(props, Algorithm.HMAC256, "payload", String.class)).thenReturn("token");

        String result = key.generateToken(Algorithm.HMAC256, "key1", props, "payload", String.class);
        assertEquals("token", result);
    }

    @Test
    void testGetCurrentKey() {
        Object keyObj = new Object();
        when(defaultAlgo.getCurrentKey()).thenReturn(keyObj);

        Object result = key.getCurrentKey();
        assertSame(keyObj, result);
    }

    @Test
    void testGetActiveKeyVersion() {
        when(defaultAlgo.getActiveKeyVersion()).thenReturn(keyVersion);

        KeyVersion result = key.getActiveKeyVersion();
        assertSame(keyVersion, result);
    }

    @Test
    void testGetKeyVersionsByStatus() {
        when(defaultAlgo.getKeyVersionsByStatus(KeyStatus.ACTIVE)).thenReturn(List.of("v1"));

        List<String> result = key.getKeyVersionsByStatus(KeyStatus.ACTIVE);
        assertEquals(1, result.size());
        assertEquals("v1", result.get(0));
    }

    @Test
    void testGetCacheSize() {
        when(jwtFactory.getCacheSize()).thenReturn(5);

        int result = key.getCacheSize();
        assertEquals(5, result);
    }

    @Test
    void testGetKeyByVersion() {
        Object keyObj = new Object();
        when(defaultAlgo.getKeyByVersion("v1")).thenReturn(keyObj);

        Object result = key.getKeyByVersion("v1");
        assertSame(keyObj, result);
    }

    @Test
    void testCloseWithPreviousAlgo() {
        // Setup previous algorithm
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        key.switchTo(Algorithm.RSA256);

        key.close();
        verify(defaultAlgo).close();
        verify(newAlgo).close();
    }

    @Test
    void testCleanupExpiredGracefulAlgo() {
        // This test indirectly tests cleanupExpiredGracefulAlgo through scheduledCleanup
        key.scheduledCleanup();
        verify(jwtFactory).cleanupAllAlgos();
    }

    @Test
    void testSetActiveKeyFailure() {
        when(defaultAlgo.setActiveKey("invalid-key")).thenReturn(false);
        boolean result = key.setActiveKey("invalid-key");
        assertFalse(result);
    }

    @Test
    void testGenerateAllKeyPairsWithFailures() {
        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(jwtFactory.get(Algorithm.RSA256)).thenReturn(newAlgo);
        when(jwtFactory.get(Algorithm.ES256)).thenReturn(ecdsaAlgo);
        when(jwtFactory.get(Algorithm.Ed25519)).thenReturn(defaultAlgo);

        // Test HMAC failure
        when(defaultAlgo.generateAllKeyPairs()).thenReturn(false);
        when(newAlgo.generateAllKeyPairs()).thenReturn(true);
        when(ecdsaAlgo.generateAllKeyPairs()).thenReturn(true);

        boolean result = key.generateAllKeyPairs();
        assertFalse(result);

        // Test exception case
        when(defaultAlgo.generateAllKeyPairs()).thenThrow(new RuntimeException("Test exception"));
        result = key.generateAllKeyPairs();
        assertFalse(result);
    }

    @Test
    void testGetKeyVersionsWithNullAlgorithm() {
        key.getKeyVersions(null);
        verify(defaultAlgo).getKeyVersions(Algorithm.HMAC256);
    }

    @Test
    void testIsValidWithGraceful() {
        // Test with no backup algo
        boolean result = key.isValidWithGraceful(TOKEN);
        assertFalse(result);

        // Test with backup algo
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        key.switchTo(Algorithm.RSA256);
        when(defaultAlgo.verifyToken(TOKEN)).thenReturn(true);

        result = key.isValidWithGraceful(TOKEN);
        assertTrue(result);
    }

    @Data
    static class Demo {
        private Long id;
        private User user;
    }

    @Data
    static class User {
        private String name;
        private int age;
    }
}
