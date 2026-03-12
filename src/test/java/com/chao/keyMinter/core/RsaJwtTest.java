package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.port.out.KeyRepository;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class RsaJwtTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    @Mock
    KeyRepository keyRepository;

    private RsaJwt rsaJwt;
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        
        when(properties.getKeyValidityMillis()).thenReturn(3600000L); // 1 hour
        when(properties.getTransitionPeriodHours()).thenReturn(24);
        when(properties.isEnableRotation()).thenReturn(true);
        when(properties.getExpiredKeyRetentionMillis()).thenReturn(Duration.ofDays(30).toMillis());
        
        rsaJwt = new RsaJwt(properties, tempDir);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (rsaJwt != null) {
            rsaJwt.close();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void testInitializationCreatesDirectory() {
        Path keyPath = rsaJwt.getKeyPath();
        assertNotNull(keyPath);
        assertTrue(keyPath.endsWith("rsa-keys"));
    }

    @Test
    void testGenerateKey() {
        boolean success = rsaJwt.generateKeyPair(Algorithm.RSA256);
        assertTrue(success);
        
        List<String> keys = rsaJwt.getKeyVersions(Algorithm.RSA256);
        assertFalse(keys.isEmpty());
        String keyId = keys.get(0);
        
        rsaJwt.setActiveKey(keyId);
        
        String activeKeyId = rsaJwt.getActiveKeyId();
        assertEquals(keyId, activeKeyId);
        
        // Verify file existence
        Path versionDir = rsaJwt.getKeyPath().resolve(activeKeyId);
        assertTrue(Files.exists(versionDir));
        assertTrue(Files.exists(versionDir.resolve("private.key")));
        assertTrue(Files.exists(versionDir.resolve("public.key")));
        assertTrue(Files.exists(versionDir.resolve("algorithm.info")));
    }

    @Test
    void testGenerateAndVerifyToken() {
        rsaJwt.generateKeyPair(Algorithm.RSA256);
        List<String> keys = rsaJwt.getKeyVersions(Algorithm.RSA256);
        String keyId = keys.get(0);
        rsaJwt.setActiveKey(keyId);
        
        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("rsa-user");
        jwtProps.setIssuer("rsa-issuer");
        jwtProps.setExpiration(Instant.now().plus(Duration.ofMinutes(10)));
        
        String token = rsaJwt.generateToken(jwtProps, Collections.singletonMap("role", "user"), Algorithm.RSA256);
        assertNotNull(token);
        
        // Verify
        boolean valid = rsaJwt.verifyToken(token);
        assertTrue(valid);
        
        // Decode
        Claims claims = rsaJwt.decodePayload(token);
        assertEquals("rsa-user", claims.getSubject());
        assertEquals("rsa-issuer", claims.getIssuer());
    }

    @Test
    void testRotateKey() {
        rsaJwt.generateKeyPair(Algorithm.RSA256);
        List<String> keys1 = rsaJwt.getKeyVersions(Algorithm.RSA256);
        String key1 = keys1.get(0);
        rsaJwt.setActiveKey(key1);
        
        // Rotate
        String newKeyId = rsaJwt.generateKeyVersionId(Algorithm.RSA256);
        boolean success = rsaJwt.rotateKey(Algorithm.RSA256, newKeyId);
        assertTrue(success);
        
        rsaJwt.setActiveKey(newKeyId);
        assertEquals(newKeyId, rsaJwt.getActiveKeyId());
        
        assertTrue(rsaJwt.keyPairExists(Algorithm.RSA256));
    }
    
    @Test
    void testInvalidInputs() {
        assertThrows(NullPointerException.class, () -> rsaJwt.generateToken(null, Algorithm.RSA256));
        assertFalse(rsaJwt.verifyToken(null));
        assertFalse(rsaJwt.verifyToken(""));
    }
    
    @Test
    void testLoadExistingKeys() {
        // 1. Generate keys in one instance
        rsaJwt.generateKeyPair(Algorithm.RSA256);
        List<String> keys = rsaJwt.getKeyVersions(Algorithm.RSA256);
        String keyId = keys.get(0);
        rsaJwt.setActiveKey(keyId);
        
        rsaJwt.close();
        
        // 2. Create new instance
        RsaJwt newInstance = new RsaJwt(properties, tempDir);
        newInstance.loadExistingKeyVersions();
        
        // 3. Verify
        assertEquals(keyId, newInstance.getActiveKeyId());
        assertTrue(newInstance.keyPairExists(Algorithm.RSA256));
        
        // 4. Verify token generation works
        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("reload-rsa");
        jwtProps.setIssuer("rsa-issuer");
        jwtProps.setExpiration(Instant.now().plus(Duration.ofMinutes(10)));
        
        String token = newInstance.generateToken(jwtProps, null, Algorithm.RSA256);
        assertTrue(newInstance.verifyToken(token));
        newInstance.close();
    }
    
    @Test
    void testCorruptedKeyFile() throws Exception {
        // 1. Generate key
        rsaJwt.generateKeyPair(Algorithm.RSA256);
        List<String> keys = rsaJwt.getKeyVersions(Algorithm.RSA256);
        String keyId = keys.get(0);
        rsaJwt.setActiveKey(keyId);
        
        rsaJwt.close();
        
        // 2. Corrupt the private key file
        Path keyDir = tempDir.resolve("rsa-keys").resolve(keyId);
        Files.writeString(keyDir.resolve("private.key"), "corrupted-content");
        
        // 3. Reload
        RsaJwt newInstance = new RsaJwt(properties, tempDir);
        newInstance.loadExistingKeyVersions();
        
        // 4. Verify loaded but potentially broken on usage
        // Since the only key is corrupted, it should not be loaded/activated
        assertNull(newInstance.getActiveKeyId());
        
        // But signing should fail
        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("fail");
        jwtProps.setIssuer("iss");
        jwtProps.setExpiration(Instant.now().plusSeconds(60));
        
        assertThrows(IllegalStateException.class, () -> newInstance.generateToken(jwtProps, null, Algorithm.RSA256));
        newInstance.close();
    }
    
    @Test
    void testVerifyWithKeyVersion() {
        rsaJwt.generateKeyPair(Algorithm.RSA256);
        List<String> keys = rsaJwt.getKeyVersions(Algorithm.RSA256);
        String key1 = keys.get(0);
        rsaJwt.setActiveKey(key1);
        
        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("user");
        jwtProps.setIssuer("iss");
        jwtProps.setExpiration(Instant.now().plusSeconds(60));
        
        String token = rsaJwt.generateToken(jwtProps, null, Algorithm.RSA256);
        
        assertTrue(rsaJwt.verifyWithKeyVersion(key1, token));
        assertFalse(rsaJwt.verifyWithKeyVersion("non-existent", token));
    }
}



