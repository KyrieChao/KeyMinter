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
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

@Slf4j
class KeyMinterTest {

    @Mock
    JwtFactory jwtFactory;

    @Mock
    JwtAlgo defaultAlgo;

    @Mock
    JwtAlgo newAlgo;

    @Mock  // 需要 mock Claims
    Claims claims;

    private KeyMinter key;

    private final static String TOKEN = "test.jwt.token";

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(defaultAlgo.getKeyInfo()).thenReturn("kid-001");

        // 关键：补充激活密钥需要的 Mock
        KeyVersion mockKv = new KeyVersion();
        mockKv.setKeyId("kid-001");
        mockKv.setStatus(KeyStatus.ACTIVE);

        key = new KeyMinter(jwtFactory);
        key.setActiveKey("kid-001");
    }

    @Test
    void testInitialization() {
        Mockito.verify(jwtFactory).get(Algorithm.HMAC256);
        assertEquals("kid-001", key.getJwtProperties());
    }

    @Test
    void testSwitchTo() {
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        when(newAlgo.getKeyInfo()).thenReturn("New Algo Info");

        boolean result = key.switchTo(Algorithm.RSA256);
        assertTrue(result);

        assertEquals("New Algo Info", key.getJwtProperties());
    }

    @Test
    void testSwitchToWithPath() {
        Path path = Paths.get("custom/path");
        when(jwtFactory.get(Algorithm.ES256, path)).thenReturn(newAlgo);
        when(newAlgo.getKeyInfo()).thenReturn("EC Algo Info");

        boolean result = key.switchTo(Algorithm.ES256, path, false);
        assertTrue(result);

        assertEquals("EC Algo Info", key.getJwtProperties());
    }

    @Test
    void testSwitchToWithKeyIdAndAutoload() {
        String keyId = "key-123";
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        // Autoload delegation
        when(jwtFactory.autoLoad(Algorithm.RSA256, null, keyId)).thenReturn(newAlgo);

        boolean result = key.switchTo(Algorithm.RSA256, keyId);
        assertTrue(result);

        Mockito.verify(jwtFactory).autoLoad(Algorithm.RSA256, null, keyId);
    }

    @Test
    void testGenerateToken() {
        JwtProperties props = new JwtProperties();
        props.setSubject("sub");
        props.setIssuer("iss");
        props.setExpiration(Instant.now().plusSeconds(3600));

        when(defaultAlgo.generateToken(any(), eq(Algorithm.HMAC256))).thenReturn("token");

        String token = key.generateToken(props);
        assertEquals("token", token);
        Mockito.verify(defaultAlgo).generateToken(any(), eq(Algorithm.HMAC256));
    }

    @Test
    void testGenerateTokenWithCustomClaims() {
        JwtProperties props = new JwtProperties();
        props.setSubject("sub");
        props.setIssuer("iss");
        props.setExpiration(java.time.Instant.now().plusSeconds(3600));
        Map<String, Object> claims = Collections.singletonMap("foo", "bar");

        when(defaultAlgo.generateToken(any(), eq(Algorithm.HMAC256), eq(claims), eq(Map.class))).thenReturn("token");

        String token = key.generateToken(props, claims, Map.class);
        assertEquals("token", token);
    }

    @Test
    void testVerifyToken() {
        when(defaultAlgo.verifyToken("valid-token")).thenReturn(true);
        when(defaultAlgo.verifyToken("invalid-token")).thenReturn(false);

        assertTrue(key.isValidToken("valid-token"));
        assertFalse(key.isValidToken("invalid-token"));
    }

    @Test
    void testGracefulVerify() {
        // Setup: Switch from default to new
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        key.switchTo(Algorithm.RSA256);

        // Current is newAlgo, Previous is defaultAlgo

        // Case 1: Token valid with current
        when(newAlgo.verifyToken("token1")).thenReturn(true);
        assertTrue(key.isValidToken("token1"));
        Mockito.verify(defaultAlgo, never()).verifyToken("token1");

        // Case 2: Token invalid with current, valid with previous
        when(newAlgo.verifyToken("token2")).thenReturn(false);
        when(defaultAlgo.verifyToken("token2")).thenReturn(true);
        assertTrue(key.isValidToken("token2"));

        // Test helper methods for specific verification
        assertTrue(key.isValidWithCurrent("token1"));
        assertFalse(key.isValidWithCurrent("token2"));
        assertTrue(key.isValidWithGraceful("token2"));

        // Case 3: Token invalid with both
        when(newAlgo.verifyToken("token3")).thenReturn(false);
        when(defaultAlgo.verifyToken("token3")).thenReturn(false);
        assertFalse(key.isValidToken("token3"));
    }

    @Test
    void testScheduledCleanup() {
        key.scheduledCleanup();
        Mockito.verify(jwtFactory).cleanupAllAlgos();
    }

    @Test
    void testAutoLoadDelegation() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519)).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519);
        assertSame(newAlgo, result);
        Mockito.verify(jwtFactory).autoLoad(Algorithm.Ed25519);
    }

    @Test
    void testAutoLoadDelegation2() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519, false)).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, false);
        assertSame(newAlgo, result);
        Mockito.verify(jwtFactory).autoLoad(Algorithm.Ed25519, false);
    }

    @Test
    void testAutoLoadDelegation3() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519, true)).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, true);
        assertSame(newAlgo, result);
        Mockito.verify(jwtFactory).autoLoad(Algorithm.Ed25519, true);
    }

    @Test
    void testAutoLoadDelegation4() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519, "")).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, "");
        assertSame(newAlgo, result);
        Mockito.verify(jwtFactory).autoLoad(Algorithm.Ed25519, "");
    }

    @Test
    void testAutoLoadDelegation5() {
        Path path = Paths.get("custom/path");
        when(jwtFactory.autoLoad(Algorithm.Ed25519, path)).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, path);
        assertSame(newAlgo, result);
        Mockito.verify(jwtFactory).autoLoad(Algorithm.Ed25519, path);
    }

    @Test
    void testAutoLoadDelegation6() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519, "", "")).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, "", "");
        assertSame(newAlgo, result);
        Mockito.verify(jwtFactory).autoLoad(Algorithm.Ed25519, "", "");
    }

    @Test
    void testAutoLoadDelegation7() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519, "", "", true)).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, "", "", true);
        assertSame(newAlgo, result);
        Mockito.verify(jwtFactory).autoLoad(Algorithm.Ed25519, "", "", true);
    }

    @Test
    void testAutoLoadDelegation8() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519, "", "", false)).thenReturn(newAlgo);
        JwtAlgo result = key.autoLoad(Algorithm.Ed25519, "", "", false);
        assertSame(newAlgo, result);
        Mockito.verify(jwtFactory).autoLoad(Algorithm.Ed25519, "", "", false);
    }

    @Test
    void testCreateHmacKey() {
        when(defaultAlgo.generateHmacKey(Algorithm.HMAC256, 64)).thenReturn(true);
        assertTrue(key.createHmacKey(Algorithm.HMAC256, 64));

        // Test null length defaults to 64
        key.createHmacKey(Algorithm.HMAC256, null);
        Mockito.verify(defaultAlgo, times(2)).generateHmacKey(Algorithm.HMAC256, 64);

        // Test invalid algo
        assertThrows(IllegalArgumentException.class, () -> key.createHmacKey(Algorithm.RSA256, 64));
    }

    @Test
    void testCreateKeyPair() {
        // Current algo is HMAC, asking for RSA (different)
        when(jwtFactory.get(Algorithm.RSA256)).thenReturn(newAlgo);
        when(newAlgo.generateKeyPair(Algorithm.RSA256)).thenReturn(true);

        assertTrue(key.createKeyPair(Algorithm.RSA256));

        // Test invalid algo (HMAC)
        assertThrows(IllegalArgumentException.class, () -> key.createKeyPair(Algorithm.HMAC256));
    }

    @Test
    void testDecodeMethods() {
        // Since KeyMinter uses static JwtDecoder, we should use try-with-resources for MockedStatic
        try (MockedStatic<JwtDecoder> mockedDecoder = Mockito.mockStatic(JwtDecoder.class)) {
            String token = "token";

            // getStandardInfo
            JwtStandardInfo stdInfo = JwtStandardInfo.builder().subject("sub").build();
            mockedDecoder.when(() -> JwtDecoder.decodeStandardInfo(token, defaultAlgo)).thenReturn(stdInfo);
            assertEquals(stdInfo, key.getStandardInfo(token));

            // decodeToObject
            mockedDecoder.when(() -> JwtDecoder.decodeToObject(token, String.class, defaultAlgo)).thenReturn("obj");
            assertEquals("obj", key.decodeToObject(token, String.class));

            // decodeToFullMap
            Map<String, Object> map = Collections.emptyMap();
            mockedDecoder.when(() -> JwtDecoder.decodeToFullMap(token, defaultAlgo)).thenReturn(map);
            assertEquals(map, key.decodeToFullMap(token));

            // decodeIssuedAt
            Date now = new Date();
            mockedDecoder.when(() -> JwtDecoder.decodeIssuedAt(token, defaultAlgo)).thenReturn(now);
            assertEquals(now, key.decodeIssuedAt(token));

            // decodeExpiration
            mockedDecoder.when(() -> JwtDecoder.decodeExpiration(token, defaultAlgo)).thenReturn(now);
            assertEquals(now, key.decodeExpiration(token));

            // isTokenDecodable
            mockedDecoder.when(() -> JwtDecoder.isTokenDecodable(token, defaultAlgo)).thenReturn(true);
            assertTrue(key.isTokenDecodable(token));
        }
    }

    @Test
    void testListKeys() {
        key.listAllKeys();
        Mockito.verify(defaultAlgo).listAllKeys();

        key.listAllKeys("dir");
        Mockito.verify(defaultAlgo).listAllKeys("dir");

        key.listKeys();
        Mockito.verify(defaultAlgo).listKeys(Algorithm.HMAC256);

        key.listKeys(Algorithm.RSA256, "dir");
        Mockito.verify(defaultAlgo).listKeys(Algorithm.RSA256, "dir");
    }

    @Test
    void testGetKeyVersions() {
        key.getKeyVersions();
        Mockito.verify(defaultAlgo).getKeyVersions();

        key.getKeyVersions(Algorithm.RSA256);
        Mockito.verify(defaultAlgo).getKeyVersions(Algorithm.RSA256);
    }

    @Test
    void testMetrics() {
        key.recordBlacklistHit();
        Map<String, Long> metrics = key.getMetrics();
        assertTrue(metrics.containsKey("gracefulUsage"));
        assertTrue(metrics.containsKey("blacklistHit"));
        assertEquals(1L, metrics.get("blacklistHit"));
        key.resetMetrics();
        assertEquals(0L, key.getMetrics().get("blacklistHit"));
    }

    @Test
    void testGenerateAllKeyPairs() {
        when(jwtFactory.get(any())).thenReturn(newAlgo);
        when(newAlgo.generateAllKeyPairs()).thenReturn(true);

        assertTrue(key.generateAllKeyPairs());
        // HMAC256 is called in constructor AND in generateAllKeyPairs
        Mockito.verify(jwtFactory, times(2)).get(Algorithm.HMAC256);
        Mockito.verify(jwtFactory).get(Algorithm.RSA256);
        Mockito.verify(jwtFactory).get(Algorithm.ES256);
        Mockito.verify(jwtFactory).get(Algorithm.Ed25519);
    }

    @Test
    void testWithKeyDirectory() {
        Path p = Paths.get("dir");
        key.withKeyDirectory(p);
        Mockito.verify(defaultAlgo).withKeyDirectory(p);

        key.withKeyDirectory("dir");
        Mockito.verify(defaultAlgo).withKeyDirectory("dir");
    }

    @Test
    void testSetActiveKey() {
        when(defaultAlgo.setActiveKey("k1")).thenReturn(true);
        assertTrue(key.setActiveKey("k1"));
        Mockito.verify(defaultAlgo).setActiveKey("k1");
    }

    @Test
    void testKeyPairExists() {
        when(defaultAlgo.keyPairExists()).thenReturn(true);
        assertTrue(key.keyPairExists());

        when(defaultAlgo.keyPairExists(Algorithm.RSA256)).thenReturn(false);
        assertFalse(key.keyPairExists(Algorithm.RSA256));
    }

    @Test
    void testGetActiveKeyId() {
        when(defaultAlgo.getActiveKeyId()).thenReturn("k1");
        assertEquals("k1", key.getActiveKeyId());
    }

    @Test
    void testClose() {
        key.close();
        Mockito.verify(defaultAlgo).close();
    }

    @Test
    void testClearCache() {
        key.clearCache();
        Mockito.verify(jwtFactory).clearCache();
    }

    @Test
    void testGetAlgorithmInfo() {
        when(defaultAlgo.getAlgorithmInfo()).thenReturn("info");
        assertEquals("info", key.getAlgorithmInfo());
    }

    @Test
    void testGetKeyPath() {
        Path p = Paths.get("p");
        when(defaultAlgo.getKeyPath()).thenReturn(p);
        assertEquals(p, key.getKeyPath());
    }

}



