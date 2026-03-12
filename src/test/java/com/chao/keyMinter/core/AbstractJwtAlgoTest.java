package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersion;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;
import java.time.Instant;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class AbstractJwtAlgoTest {

    @TempDir
    Path tempDir;

    private TestJwtAlgo jwtAlgo;
    private KeyMinterProperties properties;

    @BeforeEach
    void setUp() {
        properties = new KeyMinterProperties();
        properties.setKeyValidityDays(1);
        properties.setEnableRotation(true);
        jwtAlgo = new TestJwtAlgo(properties, tempDir);
    }

    @Test
    void testValidateJwtProperties_Valid() {
        // Arrange
        JwtProperties props = new JwtProperties();
        props.setSubject("sub");
        props.setIssuer("iss");
        props.setExpiration(Instant.now().plusSeconds(3600));

        // Act & Assert
        assertDoesNotThrow(() -> jwtAlgo.validateJwtProperties(props), "Valid properties should pass validation");
    }

    @Test
    void testValidateJwtProperties_Invalid() {
        // Arrange
        JwtProperties props = new JwtProperties();
        
        // Act & Assert - Null props
        assertThrows(NullPointerException.class, () -> jwtAlgo.validateJwtProperties(null), "Null properties should throw NPE");

        // Missing Subject
        props.setIssuer("iss");
        props.setExpiration(Instant.now().plusSeconds(3600));
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.validateJwtProperties(props), "Missing subject should throw IllegalArgumentException");

        // Missing Issuer
        props.setSubject("sub");
        props.setIssuer("");
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.validateJwtProperties(props), "Empty issuer should throw IllegalArgumentException");

        // Missing Expiration
        props.setIssuer("iss");
        props.setExpiration(null);
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.validateJwtProperties(props), "Null expiration should throw IllegalArgumentException");

        // Past Expiration
        props.setExpiration(Instant.now().minusSeconds(3600));
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.validateJwtProperties(props), "Past expiration should throw IllegalArgumentException");
    }

    @Test
    void testCheckActiveKeyCanSign_NoKey() {
        // Act & Assert
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> jwtAlgo.checkActiveKeyCanSign());
        assertEquals("No active key. Call setActiveKey or rotateKey first.", ex.getMessage());
    }

    @Test
    void testCheckActiveKeyCanSign_KeyNotFound() {
        // Arrange
        // Manually set activeKeyId without adding to map (simulating inconsistent state)
        jwtAlgo.setActiveKeyIdDirectly("non-existent-key");

        // Act & Assert
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> jwtAlgo.checkActiveKeyCanSign());
        assertTrue(ex.getMessage().contains("Active key version not found"));
    }

    @Test
    void testCheckActiveKeyCanSign_Expired() {
        // Arrange
        String keyId = "expired-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(keyId)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(10))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setActiveKeyIdDirectly(keyId);

        // Act & Assert
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> jwtAlgo.checkActiveKeyCanSign());
        assertTrue(ex.getMessage().contains("Active key has expired"));
    }

    @Test
    void testCheckActiveKeyCanSign_Revoked() {
        // Arrange
        String keyId = "revoked-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(keyId)
                .status(KeyStatus.REVOKED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setActiveKeyIdDirectly(keyId);

        // Act & Assert
        IllegalStateException ex = assertThrows(IllegalStateException.class, () -> jwtAlgo.checkActiveKeyCanSign());
        assertTrue(ex.getMessage().contains("Active key cannot be used for signing"));
    }

    @Test
    void testSetActiveKey_InvalidInput() {
        // Act & Assert
        assertFalse(jwtAlgo.setActiveKey(null), "Null keyId should return false");
        assertFalse(jwtAlgo.setActiveKey(""), "Empty keyId should return false");
        assertFalse(jwtAlgo.setActiveKey("non-existent"), "Non-existent keyId should return false");
    }

    @Test
    void testSetActiveKey_ExpiredOrRevoked() {
        // Arrange
        String expiredKey = "expired";
        KeyVersion expVersion = KeyVersion.builder()
                .keyId(expiredKey)
                .status(KeyStatus.EXPIRED) // Status is EXPIRED
                .expiresAt(Instant.now().minusSeconds(10)) // Actually expired
                .build();
        jwtAlgo.addKeyVersion(expVersion);

        String revokedKey = "revoked";
        KeyVersion revVersion = KeyVersion.builder()
                .keyId(revokedKey)
                .status(KeyStatus.REVOKED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(revVersion);

        // Act & Assert
        assertFalse(jwtAlgo.setActiveKey(expiredKey), "Setting expired key should fail");
        assertFalse(jwtAlgo.setActiveKey(revokedKey), "Setting revoked key should fail");
    }

    @Test
    void testConvertToClaimsMap() {
        // 1. Null
        assertNull(jwtAlgo.convertToClaimsMap(null));

        // 2. Map
        Map<String, Object> map = new HashMap<>();
        map.put("foo", "bar");
        assertEquals(map, jwtAlgo.convertToClaimsMap(map));

        // 3. String (JSON)
        String json = "{\"foo\":\"bar\"}";
        Map<String, Object> result = jwtAlgo.convertToClaimsMap(json);
        assertEquals("bar", result.get("foo"));

        // 4. Object (POJO)
        TestClaims claims = new TestClaims("bar");
        result = jwtAlgo.convertToClaimsMap(claims);
        assertEquals("bar", result.get("foo"));

        // 5. Invalid JSON String
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.convertToClaimsMap("{invalid-json}"));
    }
    
    @Test
    void testAutoLoadKey_PreferredNotFound() {
        // Arrange
        String preferred = "preferred-key";
        
        // Act
        jwtAlgo.autoLoadKey(preferred);
        
        // Assert
        assertNull(jwtAlgo.getActiveKeyId(), "Should not set active key if preferred key not found");
    }

    @Test
    void testAutoLoadKey_PreferredExpired() {
        // Arrange
        String preferred = "preferred-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(preferred)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(100))
                .build();
        jwtAlgo.addKeyVersion(version);
        
        // Act
        jwtAlgo.autoLoadKey(preferred);
        
        // Assert
        // Logic: if expired, logs warning and returns (does not activate)
        // Since we didn't set it active before, activeKeyId should be null
        // But wait, autoLoadKey checks: if (keyVersions.containsKey) { if expired { log; return; } setActiveKey... }
        // So it should NOT activate.
        assertNull(jwtAlgo.getActiveKeyId(), "Should not activate expired preferred key");
    }

    @Test
    void testCleanupExpiredKeys_InMemoery() {
        // Arrange
        String expiredKey = "expired-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(expiredKey)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().minusSeconds(100))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setActiveKeyIdDirectly(expiredKey);
        
        // Act
        jwtAlgo.cleanupExpiredKeys();
        
        // Assert
        assertEquals(KeyStatus.EXPIRED, version.getStatus());
    }

    @Test
    void testGetKeyInfo() {
        // Arrange
        String keyId = "test-key";
        KeyVersion version = KeyVersion.builder()
                .keyId(keyId)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setActiveKeyIdDirectly(keyId);
        
        // Act
        String info = jwtAlgo.getKeyInfo();
        
        // Assert
        assertNotNull(info);
        assertTrue(info.contains(keyId));
        assertTrue(info.contains("ACTIVE"));
    }

    @Test
    void testDefaultMethods() {
        // manageSecret
        assertFalse(jwtAlgo.manageSecret("secret"));
        
        // rotateKeyWithTransition - should throw because rotation is enabled but not implemented in test subclass?
        // Wait, base class throws UnsupportedOperationException if not enabled, or logs warn and returns false.
        // My properties have rotation enabled.
        // Base class:
        // if (!isKeyRotationEnabled()) throw ...
        // log.warn(...)
        // return false;
        assertFalse(jwtAlgo.rotateKeyWithTransition(Algorithm.HMAC256, "new-key", 24));
        
        // If rotation disabled
        properties.setEnableRotation(false);
        assertThrows(UnsupportedOperationException.class, () -> jwtAlgo.rotateKeyWithTransition(Algorithm.HMAC256, "new-key", 24));
    }
    
    @Test
    void testGetDirTimestamp() {
        // Valid
        Path p1 = tempDir.resolve("HMAC256-v20230101-120000-12345678");
        assertDoesNotThrow(() -> jwtAlgo.getDirTimestamp(p1));
        
        // Invalid
        Path p2 = tempDir.resolve("invalid-name");
        assertEquals(java.time.LocalDateTime.MIN, jwtAlgo.getDirTimestamp(p2));
    }

    // --- Helper Classes ---

    static class TestClaims {
        public String foo;
        public TestClaims() {}
        public TestClaims(String foo) { this.foo = foo; }
    }

    /**
     * Concrete implementation of AbstractJwtAlgo for testing.
     */
    static class TestJwtAlgo extends AbstractJwtAlgo {

        public TestJwtAlgo(KeyMinterProperties properties, Path tempDir) {
            super(properties);
            this.currentKeyPath = tempDir;
        }

        // Expose protected method for testing
        public void setActiveKeyIdDirectly(String keyId) {
            this.activeKeyId = keyId;
        }

        public void addKeyVersion(KeyVersion version) {
            this.keyVersions.put(version.getKeyId(), version);
        }

        @Override
        public String generateJwt(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
            return "dummy-token";
        }

        @Override
        public boolean verifyToken(String token) {
            return true;
        }

        @Override
        public boolean verifyWithKeyVersion(String keyVersionId, String token) {
            return true;
        }

        @Override
        public Claims decodePayload(String token) {
            return null;
        }

        @Override
        protected boolean hasKeyFilesInDirectory(String tag) {
            return false;
        }

        @Override
        protected void loadFirstKeyFromDirectory(String tag) {
            // No-op
        }

        @Override
        protected void loadKeyVersion(Path path) {
            // No-op
        }

        @Override
        protected boolean isKeyVersionDir(Path dir) {
            return false;
        }

        @Override
        protected Object getSignAlgorithm(Algorithm algorithm) {
            return null;
        }
    }
}



