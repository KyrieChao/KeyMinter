package com.chao.keyMinter.api;

import com.chao.keyMinter.core.JwtFactory;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.JwtStandardInfo;
import com.chao.keyMinter.domain.service.JwtAlgo;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;
import java.util.Date;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class KeyMinterTest {

    @Mock
    JwtFactory jwtFactory;

    @Mock
    JwtAlgo defaultAlgo;

    @Mock
    JwtAlgo newAlgo;

    private KeyMinter keyMinter;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(defaultAlgo.getKeyInfo()).thenReturn("Default Algo Info");

        keyMinter = new KeyMinter(jwtFactory);
    }

    @Test
    void testInitialization() {
        verify(jwtFactory).get(Algorithm.HMAC256);
        assertEquals("Default Algo Info", keyMinter.getJwtProperties());
    }

    @Test
    void testSwitchTo() {
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        when(newAlgo.getKeyInfo()).thenReturn("New Algo Info");

        boolean result = keyMinter.switchTo(Algorithm.RSA256);
        assertTrue(result);

        assertEquals("New Algo Info", keyMinter.getJwtProperties());
    }

    @Test
    void testSwitchToWithPath() {
        Path path = Paths.get("custom/path");
        when(jwtFactory.get(Algorithm.ES256, path)).thenReturn(newAlgo);
        when(newAlgo.getKeyInfo()).thenReturn("EC Algo Info");

        boolean result = keyMinter.switchTo(Algorithm.ES256, path, false);
        assertTrue(result);

        assertEquals("EC Algo Info", keyMinter.getJwtProperties());
    }
    
    @Test
    void testSwitchToWithKeyIdAndAutoload() {
        String keyId = "key-123";
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        // Autoload delegation
        when(jwtFactory.autoLoad(Algorithm.RSA256, null, keyId)).thenReturn(newAlgo);
        
        boolean result = keyMinter.switchTo(Algorithm.RSA256, keyId);
        assertTrue(result);
        
        verify(jwtFactory).autoLoad(Algorithm.RSA256, null, keyId);
    }

    @Test
    void testGenerateToken() {
        JwtProperties props = new JwtProperties();
        props.setSubject("sub");
        props.setIssuer("iss");
        props.setExpiration(java.time.Instant.now().plusSeconds(3600));

        when(defaultAlgo.generateToken(any(), eq(Algorithm.HMAC256))).thenReturn("token");

        String token = keyMinter.generateToken(props);
        assertEquals("token", token);
        verify(defaultAlgo).generateToken(any(), eq(Algorithm.HMAC256));
    }
    
    @Test
    void testGenerateTokenWithCustomClaims() {
        JwtProperties props = new JwtProperties();
        props.setSubject("sub");
        props.setIssuer("iss");
        props.setExpiration(java.time.Instant.now().plusSeconds(3600));
        Map<String, Object> claims = Collections.singletonMap("foo", "bar");

        when(defaultAlgo.generateToken(any(), eq(Algorithm.HMAC256), eq(claims), eq(Map.class))).thenReturn("token");

        String token = keyMinter.generateToken(props, claims, Map.class);
        assertEquals("token", token);
    }

    @Test
    void testVerifyToken() {
        when(defaultAlgo.verifyToken("valid-token")).thenReturn(true);
        when(defaultAlgo.verifyToken("invalid-token")).thenReturn(false);

        assertTrue(keyMinter.isValidToken("valid-token"));
        assertFalse(keyMinter.isValidToken("invalid-token"));
    }

    @Test
    void testGracefulVerify() {
        // Setup: Switch from default to new
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(newAlgo);
        keyMinter.switchTo(Algorithm.RSA256);

        // Current is newAlgo, Previous is defaultAlgo

        // Case 1: Token valid with current
        when(newAlgo.verifyToken("token1")).thenReturn(true);
        assertTrue(keyMinter.isValidToken("token1"));
        verify(defaultAlgo, never()).verifyToken("token1");

        // Case 2: Token invalid with current, valid with previous
        when(newAlgo.verifyToken("token2")).thenReturn(false);
        when(defaultAlgo.verifyToken("token2")).thenReturn(true);
        assertTrue(keyMinter.isValidToken("token2"));
        
        // Test helper methods for specific verification
        assertTrue(keyMinter.isValidWithCurrent("token1"));
        assertFalse(keyMinter.isValidWithCurrent("token2"));
        assertTrue(keyMinter.isValidWithGraceful("token2"));

        // Case 3: Token invalid with both
        when(newAlgo.verifyToken("token3")).thenReturn(false);
        when(defaultAlgo.verifyToken("token3")).thenReturn(false);
        assertFalse(keyMinter.isValidToken("token3"));
    }

    @Test
    void testScheduledCleanup() {
        keyMinter.scheduledCleanup();
        verify(jwtFactory).cleanupAllAlgos();
    }

    @Test
    void testAutoLoadDelegation() {
        when(jwtFactory.autoLoad(Algorithm.Ed25519)).thenReturn(newAlgo);
        JwtAlgo result = keyMinter.autoLoad(Algorithm.Ed25519);
        assertSame(newAlgo, result);
        verify(jwtFactory).autoLoad(Algorithm.Ed25519);
    }
    
    @Test
    void testCreateHmacKey() {
        when(defaultAlgo.generateHmacKey(Algorithm.HMAC256, 64)).thenReturn(true);
        assertTrue(keyMinter.createHmacKey(Algorithm.HMAC256, 64));
        
        // Test null length defaults to 64
        keyMinter.createHmacKey(Algorithm.HMAC256, null);
        verify(defaultAlgo, times(2)).generateHmacKey(Algorithm.HMAC256, 64);
        
        // Test invalid algo
        assertThrows(IllegalArgumentException.class, () -> keyMinter.createHmacKey(Algorithm.RSA256, 64));
    }
    
    @Test
    void testCreateKeyPair() {
        // Current algo is HMAC, asking for RSA (different)
        when(jwtFactory.get(Algorithm.RSA256)).thenReturn(newAlgo);
        when(newAlgo.generateKeyPair(Algorithm.RSA256)).thenReturn(true);
        
        assertTrue(keyMinter.createKeyPair(Algorithm.RSA256));
        
        // Test invalid algo (HMAC)
        assertThrows(IllegalArgumentException.class, () -> keyMinter.createKeyPair(Algorithm.HMAC256));
    }
    
    @Test
    void testDecodeMethods() {
        // Since KeyMinter uses static JwtDecoder, we should use try-with-resources for MockedStatic
        try (MockedStatic<JwtDecoder> mockedDecoder = Mockito.mockStatic(JwtDecoder.class)) {
            String token = "token";
            
            // getStandardInfo
            JwtStandardInfo stdInfo = JwtStandardInfo.builder().subject("sub").build();
            mockedDecoder.when(() -> JwtDecoder.decodeStandardInfo(token, defaultAlgo)).thenReturn(stdInfo);
            assertEquals(stdInfo, keyMinter.getStandardInfo(token));
            
            // decodeToObject
            mockedDecoder.when(() -> JwtDecoder.decodeToObject(token, String.class, defaultAlgo)).thenReturn("obj");
            assertEquals("obj", keyMinter.decodeToObject(token, String.class));
            
            // decodeToFullMap
            Map<String, Object> map = Collections.emptyMap();
            mockedDecoder.when(() -> JwtDecoder.decodeToFullMap(token, defaultAlgo)).thenReturn(map);
            assertEquals(map, keyMinter.decodeToFullMap(token));
            
            // decodeIssuedAt
            Date now = new Date();
            mockedDecoder.when(() -> JwtDecoder.decodeIssuedAt(token, defaultAlgo)).thenReturn(now);
            assertEquals(now, keyMinter.decodeIssuedAt(token));
            
            // decodeExpiration
            mockedDecoder.when(() -> JwtDecoder.decodeExpiration(token, defaultAlgo)).thenReturn(now);
            assertEquals(now, keyMinter.decodeExpiration(token));
            
            // isTokenDecodable
            mockedDecoder.when(() -> JwtDecoder.isTokenDecodable(token, defaultAlgo)).thenReturn(true);
            assertTrue(keyMinter.isTokenDecodable(token));
        }
    }
    
    @Test
    void testListKeys() {
        keyMinter.listAllKeys();
        verify(defaultAlgo).listAllKeys();
        
        keyMinter.listAllKeys("dir");
        verify(defaultAlgo).listAllKeys("dir");
        
        keyMinter.listKeys();
        verify(defaultAlgo).listKeys(Algorithm.HMAC256);
        
        keyMinter.listKeys(Algorithm.RSA256, "dir");
        verify(defaultAlgo).listKeys(Algorithm.RSA256, "dir");
    }
    
    @Test
    void testGetKeyVersions() {
        keyMinter.getKeyVersions();
        verify(defaultAlgo).getKeyVersions();
        
        keyMinter.getKeyVersions(Algorithm.RSA256);
        verify(defaultAlgo).getKeyVersions(Algorithm.RSA256);
    }
    
    @Test
    void testMetrics() {
        keyMinter.recordBlacklistHit();
        Map<String, Long> metrics = keyMinter.getMetrics();
        assertTrue(metrics.containsKey("gracefulUsage"));
        assertTrue(metrics.containsKey("blacklistHit"));
        assertEquals(1L, metrics.get("blacklistHit"));
        keyMinter.resetMetrics();
        assertEquals(0L, keyMinter.getMetrics().get("blacklistHit"));
    }
    
    @Test
    void testGenerateAllKeyPairs() {
        when(jwtFactory.get(any())).thenReturn(newAlgo);
        when(newAlgo.generateAllKeyPairs()).thenReturn(true);
        
        assertTrue(keyMinter.generateAllKeyPairs());
        // HMAC256 is called in constructor AND in generateAllKeyPairs
        verify(jwtFactory, times(2)).get(Algorithm.HMAC256);
        verify(jwtFactory).get(Algorithm.RSA256);
        verify(jwtFactory).get(Algorithm.ES256);
        verify(jwtFactory).get(Algorithm.Ed25519);
    }
    
    @Test
    void testWithKeyDirectory() {
        Path p = Paths.get("dir");
        keyMinter.withKeyDirectory(p);
        verify(defaultAlgo).withKeyDirectory(p);
        
        keyMinter.withKeyDirectory("dir");
        verify(defaultAlgo).withKeyDirectory("dir");
    }
    
    @Test
    void testSetActiveKey() {
        when(defaultAlgo.setActiveKey("k1")).thenReturn(true);
        assertTrue(keyMinter.setActiveKey("k1"));
        verify(defaultAlgo).setActiveKey("k1");
    }
    
    @Test
    void testKeyPairExists() {
        when(defaultAlgo.keyPairExists()).thenReturn(true);
        assertTrue(keyMinter.keyPairExists());
        
        when(defaultAlgo.keyPairExists(Algorithm.RSA256)).thenReturn(false);
        assertFalse(keyMinter.keyPairExists(Algorithm.RSA256));
    }
    
    @Test
    void testGetActiveKeyId() {
        when(defaultAlgo.getActiveKeyId()).thenReturn("k1");
        assertEquals("k1", keyMinter.getActiveKeyId());
    }
    
    @Test
    void testClose() {
        keyMinter.close();
        verify(defaultAlgo).close();
    }
    
    @Test
    void testClearCache() {
        keyMinter.clearCache();
        verify(jwtFactory).clearCache();
    }
    
    @Test
    void testGetAlgorithmInfo() {
        when(defaultAlgo.getAlgorithmInfo()).thenReturn("info");
        assertEquals("info", keyMinter.getAlgorithmInfo());
    }
    
    @Test
    void testGetKeyPath() {
        Path p = Paths.get("p");
        when(defaultAlgo.getKeyPath()).thenReturn(p);
        assertEquals(p, keyMinter.getKeyPath());
    }
}



