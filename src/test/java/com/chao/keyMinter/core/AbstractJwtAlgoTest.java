package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersion;
import com.chao.keyMinter.domain.port.out.KeyRepository;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

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

    @Test
    void testGetKeyVersions_and_filters() {
        // Arrange
        KeyVersion h1 = KeyVersion.builder().keyId("h1").algorithm(Algorithm.HMAC256).status(KeyStatus.CREATED).build();
        KeyVersion r1 = KeyVersion.builder().keyId("r1").algorithm(Algorithm.RSA256).status(KeyStatus.REVOKED).build();
        jwtAlgo.addKeyVersion(h1);
        jwtAlgo.addKeyVersion(r1);

        // Act
        List<String> all = jwtAlgo.getKeyVersions();
        List<String> hmacOnly = jwtAlgo.getKeyVersions(Algorithm.HMAC256);
        List<String> nullAlgo = jwtAlgo.getKeyVersions((Algorithm) null);
        List<String> revoked = jwtAlgo.getKeyVersionsByStatus(KeyStatus.REVOKED);
        List<String> nullStatus = jwtAlgo.getKeyVersionsByStatus(null);

        // Assert
        assertTrue(all.containsAll(List.of("h1", "r1")));
        assertEquals(List.of("h1"), hmacOnly);
        assertEquals(Collections.emptyList(), nullAlgo);
        assertEquals(List.of("r1"), revoked);
        assertEquals(Collections.emptyList(), nullStatus);
    }

    @Test
    void testGetActiveKeyVersion_when_no_active_returns_null() {
        // Arrange
        jwtAlgo.setActiveKeyIdDirectly(null);

        // Act
        KeyVersion active = jwtAlgo.getActiveKeyVersion();

        // Assert
        assertNull(active);
    }

    @Test
    void testSetActiveKey_success_sets_transition_for_old_key_and_activates_new() {
        // Arrange
        properties.setTransitionPeriodHours(1);
        KeyVersion oldKey = KeyVersion.builder()
                .keyId("old")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.ACTIVE)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        KeyVersion newKey = KeyVersion.builder()
                .keyId("new")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(oldKey);
        jwtAlgo.addKeyVersion(newKey);
        jwtAlgo.setActiveKeyIdDirectly("old");

        // Act
        boolean ok = jwtAlgo.setActiveKey("new");

        // Assert
        assertTrue(ok);
        assertEquals("new", jwtAlgo.getActiveKeyId());
        assertEquals(KeyStatus.ACTIVE, jwtAlgo.getActiveKeyVersion().getStatus());
        assertEquals(KeyStatus.TRANSITIONING, oldKey.getStatus());
        assertNotNull(oldKey.getTransitionEndsAt());
    }

    @Test
    void testSetActiveKey_when_loadKeyPair_throws_returns_false() {
        // Arrange
        KeyVersion version = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(version);
        jwtAlgo.setLoadKeyPairFailure(true);

        // Act
        boolean ok = jwtAlgo.setActiveKey("k1");

        // Assert
        assertFalse(ok);
    }

    @Test
    void testCanKeyVerify_transitioning_key_past_transition_end_is_deactivated() {
        // Arrange
        KeyVersion version = KeyVersion.builder()
                .keyId("t1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.TRANSITIONING)
                .expiresAt(Instant.now().plusSeconds(3600))
                .transitionEndsAt(Instant.now().minusSeconds(5))
                .build();
        jwtAlgo.addKeyVersion(version);

        // Act
        boolean canVerify = jwtAlgo.canKeyVerify("t1");

        // Assert
        assertFalse(canVerify);
        assertEquals(KeyStatus.INACTIVE, version.getStatus());
    }

    @Test
    void testValidateDirectoryPath_rejects_non_normalized_and_symlink() {
        // Arrange
        Path nonNormalized = Path.of("a", "..", "b");

        // Act & Assert
        assertThrows(SecurityException.class, () -> jwtAlgo.validateDirectoryPath(nonNormalized));

        Path normalized = Path.of("b");
        try (org.mockito.MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.isSymbolicLink(normalized)).thenReturn(true);
            assertThrows(SecurityException.class, () -> jwtAlgo.validateDirectoryPath(normalized));
        }
    }

    @Test
    void testFindKeyDir_returns_latest_matching_dir_and_handles_interrupt_and_io_error() throws Exception {
        // Arrange
        Path dir = Files.createDirectories(tempDir.resolve("scan"));
        jwtAlgo.setCurrentKeyPath(dir);

        Files.createDirectories(dir.resolve("hmac-v20240101-120000-a"));
        Files.createDirectories(dir.resolve("hmac-v20240102-120000-b"));

        // Act
        Optional<Path> latest = jwtAlgo.callFindKeyDir("HMAC", null);

        // Assert
        assertTrue(latest.isPresent());
        assertEquals("hmac-v20240102-120000-b", latest.get().getFileName().toString());

        // Arrange (Interrupted sleep path)
        jwtAlgo.setCurrentKeyPath(dir.resolve("empty"));
        Files.createDirectories(jwtAlgo.getCurrentKeyPath());
        Thread.currentThread().interrupt();

        // Act
        Optional<Path> interruptedResult = jwtAlgo.callFindKeyDir("HMAC", null);

        // Assert
        assertTrue(interruptedResult.isEmpty());
        Thread.interrupted();

        // Arrange (I/O error path)
        jwtAlgo.setCurrentKeyPath(dir.resolve("ioerr"));
        Files.createDirectories(jwtAlgo.getCurrentKeyPath());
        try (org.mockito.MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(jwtAlgo.getCurrentKeyPath())).thenReturn(true);
            files.when(() -> Files.list(jwtAlgo.getCurrentKeyPath())).thenThrow(new java.io.IOException("boom"));

            // Act
            Optional<Path> ioError = jwtAlgo.callFindKeyDir("HMAC", null);

            // Assert
            assertTrue(ioError.isEmpty());
        }
    }

    @Test
    void testUpdateKeyStatusFile_when_repo_missing_or_ioexception_does_not_throw() throws Exception {
        // Arrange
        jwtAlgo.setKeyRepository(null);

        // Act & Assert
        assertDoesNotThrow(() -> jwtAlgo.callUpdateKeyStatusFile("k1", KeyStatus.ACTIVE));

        KeyRepository repo = Mockito.mock(KeyRepository.class);
        Mockito.doThrow(new java.io.IOException("io")).when(repo).saveMetadata(Mockito.eq("k1"), Mockito.eq("status.info"), Mockito.anyString());
        jwtAlgo.setKeyRepository(repo);

        assertDoesNotThrow(() -> jwtAlgo.callUpdateKeyStatusFile("k1", KeyStatus.ACTIVE));
    }

    @Test
    void testMarkKeyActive_covers_missing_version_and_repo_paths() throws Exception {
        // Arrange
        jwtAlgo.setKeyRepository(null);

        // Act & Assert (missing version)
        assertDoesNotThrow(() -> jwtAlgo.callMarkKeyActive("missing"));

        // Arrange (repo null path with existing version)
        KeyVersion v = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(v);
        assertDoesNotThrow(() -> jwtAlgo.callMarkKeyActive("k1"));

        // Arrange (repo present but throws IOException)
        KeyRepository repo = Mockito.mock(KeyRepository.class);
        Mockito.doThrow(new java.io.IOException("io")).when(repo).saveMetadata(Mockito.eq("k1"), Mockito.eq("status.info"), Mockito.anyString());
        jwtAlgo.setKeyRepository(repo);
        assertDoesNotThrow(() -> jwtAlgo.callMarkKeyActive("k1"));
    }

    @Test
    void testAutoLoadFirstKey_when_no_key_files_sets_active_null() {
        // Arrange
        jwtAlgo.setActiveKeyIdDirectly("will-clear");

        // Act
        jwtAlgo.autoLoadFirstKey(Algorithm.HMAC256, null, false);

        // Assert
        assertNull(jwtAlgo.getActiveKeyId());
    }

    @Test
    void testAutoLoadKey_when_present_and_not_expired_activates() {
        // Arrange
        KeyVersion version = KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(3600))
                .build();
        jwtAlgo.addKeyVersion(version);

        // Act
        jwtAlgo.autoLoadKey("k1");

        // Assert
        assertEquals("k1", jwtAlgo.getActiveKeyId());
    }

    @Test
    void testAutoLoadKey_when_current_key_path_null_is_handled() {
        // Arrange
        jwtAlgo.setCurrentKeyPath(null);

        // Act
        jwtAlgo.autoLoadKey("k1");

        // Assert
        assertNull(jwtAlgo.getActiveKeyId());
    }

    @Test
    void testListAllKeys_scans_directories_and_handles_invalid_inputs_and_exceptions() throws Exception {
        // Arrange
        Path baseDir = Files.createDirectories(tempDir.resolve("base"));
        Path typeDir = Files.createDirectories(baseDir.resolve("unknown-keys"));
        Path v1 = Files.createDirectories(typeDir.resolve("unknown-v20240101-120000-a"));

        Files.writeString(v1.resolve("status.info"), "NOT_A_STATUS");
        Files.writeString(v1.resolve("expiration.info"), "NOT_AN_INSTANT");

        // Act
        List<KeyVersion> empty1 = jwtAlgo.listAllKeys((String) null);
        List<KeyVersion> empty2 = jwtAlgo.listAllKeys("");
        List<KeyVersion> empty3 = jwtAlgo.listAllKeys(tempDir.resolve("missing").toString());
        List<KeyVersion> keys = jwtAlgo.listAllKeys(baseDir.toString());

        // Assert
        assertEquals(Collections.emptyList(), empty1);
        assertEquals(Collections.emptyList(), empty2);
        assertEquals(Collections.emptyList(), empty3);
        assertEquals(1, keys.size());
        assertEquals("unknown-v20240101-120000-a", keys.get(0).getKeyId());
        assertEquals(Algorithm.HMAC256, keys.get(0).getAlgorithm());
        assertEquals(KeyStatus.CREATED, keys.get(0).getStatus());
        assertNull(keys.get(0).getExpiresAt());

        // Arrange (I/O exception path)
        try (org.mockito.MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            Path anyPath = Path.of("io-base");
            files.when(() -> Files.exists(anyPath)).thenReturn(true);
            files.when(() -> Files.isDirectory(anyPath)).thenReturn(true);
            files.when(() -> Files.list(anyPath)).thenThrow(new java.io.IOException("boom"));

            // Act
            List<KeyVersion> ioKeys = jwtAlgo.listAllKeys(anyPath.toString());

            // Assert
            assertEquals(Collections.emptyList(), ioKeys);
        }
    }

    @Test
    void testGetDirTimestamp_reads_created_time_from_version_json() throws Exception {
        // Arrange
        Path dir = Files.createDirectories(tempDir.resolve("any-v20240101-120000-a"));
        Files.writeString(dir.resolve("version.json"), "{\"createdTime\":\"2024-01-01T10:15:30\"}");

        // Act
        LocalDateTime ts = jwtAlgo.getDirTimestamp(dir);

        // Assert
        assertEquals(LocalDateTime.parse("2024-01-01T10:15:30"), ts);
    }

    @Test
    void testConvertToClaimsMap_object_conversion_failure_throws() {
        // Arrange
        class Node {
            public Node next;
        }
        Node n = new Node();
        n.next = n;

        // Act & Assert
        assertThrows(IllegalArgumentException.class, () -> jwtAlgo.convertToClaimsMap(n));
    }

    @Test
    void testToDate_null_throws_and_non_null_converts() {
        // Arrange
        Instant now = Instant.now();

        // Act & Assert
        assertThrows(NullPointerException.class, () -> AbstractJwtAlgo.toDate(null));
        assertEquals(now.toEpochMilli(), AbstractJwtAlgo.toDate(now).toInstant().toEpochMilli());
    }

    @Test
    void testListAllKeys_uses_parent_dot_when_current_key_path_has_no_parent(@TempDir Path workDir) throws Exception {
        // Arrange
        String oldUserDir = System.getProperty("user.dir");
        System.setProperty("user.dir", workDir.toString());
        try {
            Path base = Files.createDirectories(workDir.resolve("base"));
            Path relativeKeyPath = Path.of("hmac-keys");
            Files.createDirectories(workDir.resolve(relativeKeyPath));
            jwtAlgo.setCurrentKeyPath(relativeKeyPath);

            // Act
            List<KeyVersion> result = jwtAlgo.listAllKeys();

            // Assert
            assertNotNull(result);
        } finally {
            System.setProperty("user.dir", oldUserDir);
        }
    }

    @Test
    void testClose_is_idempotent() {
        // Arrange & Act
        jwtAlgo.close();
        jwtAlgo.close();

        // Assert
        assertTrue(true);
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
        private volatile boolean failLoadKeyPair;

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

        public void setLoadKeyPairFailure(boolean fail) {
            this.failLoadKeyPair = fail;
        }

        public void setCurrentKeyPath(Path path) {
            this.currentKeyPath = path;
        }

        public void setKeyRepository(KeyRepository repo) {
            this.keyRepository = repo;
        }

        public Optional<Path> callFindKeyDir(String tag, java.util.function.Predicate<Path> extraFilter) {
            return super.findKeyDir(tag, extraFilter);
        }

        public void callUpdateKeyStatusFile(String keyId, KeyStatus status) {
            super.updateKeyStatusFile(keyId, status);
        }

        public void callMarkKeyActive(String keyId) {
            super.markKeyActive(keyId);
        }

        @Override
        protected void loadKeyPair(String keyId) {
            if (failLoadKeyPair) {
                throw new RuntimeException("load failed");
            }
            super.loadKeyPair(keyId);
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
        public boolean generateKeyPair(Algorithm algorithm) {
            return false;
        }

        @Override
        public boolean generateHmacKey(Algorithm algorithm, Integer length) {
            return false;
        }

        @Override
        public boolean generateAllKeyPairs() {
            return false;
        }

        @Override
        public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
            return false;
        }

        @Override
        public boolean rotateHmacKey(Algorithm algorithm, String newKeyIdentifier, Integer length) {
            return false;
        }

        @Override
        public List<KeyVersion> listKeys(Algorithm algorithm) {
            return List.of();
        }

        @Override
        public void loadExistingKeyVersions() {
        }

        @Override
        public Object getCurrentKey() {
            return null;
        }

        @Override
        public Object getKeyByVersion(String keyId) {
            return null;
        }

        @Override
        public String getCurveInfo(Algorithm algorithm) {
            return "";
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



