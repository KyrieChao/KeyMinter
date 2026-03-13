package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersionData;
import com.chao.keyMinter.domain.port.out.KeyRepository;
import com.chao.keyMinter.domain.port.out.SecretDirProvider;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.mockito.MockedStatic;

import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

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
    void lombok_getters_should_be_callable() {
        assertNotNull(rsaJwt.getVersionKeyPairs());
        assertNull(rsaJwt.getKeyPair());
    }

    @Test
    void constructors_should_use_default_base_dir_and_append_rsa_keys() {
        Path original = SecretDirProvider.getDefaultBaseDir();
        SecretDirProvider.setDefaultBaseDir(tempDir);
        try {
            RsaJwt defaultCtor = new RsaJwt();
            RsaJwt pathCtor = new RsaJwt(tempDir);

            assertTrue(defaultCtor.getKeyPath().endsWith("rsa-keys"));
            assertEquals(tempDir.normalize().resolve("rsa-keys"), pathCtor.getKeyPath());

            defaultCtor.close();
            pathCtor.close();
        } finally {
            SecretDirProvider.setDefaultBaseDir(original);
        }
    }

    @Test
    void constructor_should_accept_null_directory_and_default_to_rsa_dir() {
        // Arrange
        when(properties.isEnableRotation()).thenReturn(false);

        // Act
        RsaJwt jwt = new RsaJwt(properties, (Path) null);

        // Assert
        assertNotNull(jwt.getKeyPath());
        assertTrue(jwt.getKeyPath().endsWith("rsa-keys"));
        jwt.close();
    }

    @Test
    void autoLoadFirstKey_should_exercise_directory_scan_overrides_when_not_found() {
        // Arrange
        rsaJwt.keyRepository = null;
        rsaJwt.currentKeyPath = tempDir.resolve("missing-rsa");

        // Act
        rsaJwt.autoLoadFirstKey(Algorithm.RSA256, null, false);

        // Assert
        assertNull(rsaJwt.getActiveKeyId());
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

    @Test
    void loadExistingKeyVersions_should_swallow_files_list_ioexception() throws Exception {
        // Arrange
        Path rsaDir = tempDir.resolve("rsa-keys");
        Files.createDirectories(rsaDir);
        rsaJwt.keyRepository = null;
        rsaJwt.currentKeyPath = rsaDir;

        try (MockedStatic<Files> files = mockStatic(Files.class)) {
            files.when(() -> Files.exists(rsaDir)).thenReturn(true);
            files.when(() -> Files.isDirectory(rsaDir)).thenReturn(true);
            files.when(() -> Files.list(rsaDir)).thenThrow(new java.io.IOException("boom"));

            // Act & Assert
            assertDoesNotThrow(rsaJwt::loadExistingKeyVersions);
        }
    }

    @Test
    void loadExistingKeyVersions_repo_should_cover_expired_missing_invalid_and_active_paths() throws Exception {
        // Arrange
        KeyRepository repo = mock(KeyRepository.class);
        when(repo.listKeys(null)).thenReturn(List.of("expired", "missing", "bad", "active", "created"));

        when(repo.loadMetadata(eq("expired"), anyString())).thenReturn(Optional.empty());
        when(repo.loadMetadata(eq("expired"), eq("expiration.info"))).thenReturn(Optional.of(Instant.now().minusSeconds(1).toString()));

        when(repo.loadMetadata(eq("missing"), anyString())).thenReturn(Optional.empty());
        when(repo.loadKey(eq("missing"), eq("private.key"))).thenReturn(Optional.empty());
        when(repo.loadKey(eq("missing"), eq("public.key"))).thenReturn(Optional.of(new byte[]{1}));

        when(repo.loadMetadata(eq("bad"), anyString())).thenReturn(Optional.empty());
        when(repo.loadKey(eq("bad"), eq("private.key"))).thenReturn(Optional.of("bad".getBytes()));
        when(repo.loadKey(eq("bad"), eq("public.key"))).thenReturn(Optional.of("bad".getBytes()));

        java.security.KeyPair kp = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        when(repo.loadMetadata(eq("active"), eq("status.info"))).thenReturn(Optional.of("ACTIVE"));
        when(repo.loadMetadata(eq("active"), eq("algorithm.info"))).thenReturn(Optional.of("RSA256"));
        when(repo.loadMetadata(eq("active"), eq("expiration.info"))).thenReturn(Optional.of(Instant.now().plusSeconds(60).toString()));
        when(repo.loadKey(eq("active"), eq("private.key"))).thenReturn(Optional.of(kp.getPrivate().getEncoded()));
        when(repo.loadKey(eq("active"), eq("public.key"))).thenReturn(Optional.of(kp.getPublic().getEncoded()));

        java.security.KeyPair kp2 = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        when(repo.loadMetadata(eq("created"), eq("status.info"))).thenReturn(Optional.of("CREATED"));
        when(repo.loadMetadata(eq("created"), eq("expiration.info"))).thenReturn(Optional.of(Instant.now().plusSeconds(60).toString()));
        when(repo.loadKey(eq("created"), eq("private.key"))).thenReturn(Optional.of(kp2.getPrivate().getEncoded()));
        when(repo.loadKey(eq("created"), eq("public.key"))).thenReturn(Optional.of(kp2.getPublic().getEncoded()));

        RsaJwt withRepo = new RsaJwt(properties, repo);

        // Act
        withRepo.loadExistingKeyVersions();

        // Assert
        assertEquals("active", withRepo.getActiveKeyId());
        assertNotNull(withRepo.getCurrentKey());
        assertTrue(withRepo.getKeyVersions().containsAll(List.of("active", "created")));
        withRepo.close();
    }

    @Test
    void isKeyVersionDir_should_cover_all_detection_clauses() throws Exception {
        // Arrange
        Path rsaDir = tempDir.resolve("rsa-keys");
        Files.createDirectories(rsaDir);

        Path p1 = Files.createDirectories(rsaDir.resolve("x"));
        Files.writeString(p1.resolve("algorithm.info"), "RSA256");

        Path p2 = Files.createDirectories(rsaDir.resolve("rsa-v20240101-000000-a"));

        Path p3 = Files.createDirectories(rsaDir.resolve("p3"));
        Files.write(p3.resolve("private.key"), new byte[]{1});
        Files.write(p3.resolve("public.key"), new byte[]{1});

        // Act & Assert
        assertFalse(rsaJwt.isKeyVersionDir(null));
        assertTrue(rsaJwt.isKeyVersionDir(p1));
        assertTrue(rsaJwt.isKeyVersionDir(p2));
        assertTrue(rsaJwt.isKeyVersionDir(p3));
    }

    @Test
    void rotateKey_should_use_default_transition_when_properties_null() {
        // Arrange
        RsaJwt jwt = new RsaJwt(null, tempDir);

        // Act
        boolean ok = jwt.rotateKey(Algorithm.RSA256, "k");

        // Assert
        assertFalse(ok);
        jwt.close();
    }

    @Test
    void rotateKeyWithTransition_should_cover_keyRotationAtomic_true_false_and_ioexception() throws Exception {
        // Arrange
        when(properties.isEnableRotation()).thenReturn(true);
        RsaJwt jwt = new RsaJwt(properties, tempDir);
        jwt.keyRepository = null;
        jwt.currentKeyPath = Files.createDirectories(tempDir.resolve("rsa-keys"));

        try (MockedStatic<KeyRotation> rotation = mockStatic(KeyRotation.class)) {
            rotation.when(() -> KeyRotation.rotateKeyAtomic(anyString(), any(), any(), any(), any())).thenReturn(true);
            assertTrue(jwt.rotateKeyWithTransition(Algorithm.RSA256, "k1", 1));

            rotation.when(() -> KeyRotation.rotateKeyAtomic(anyString(), any(), any(), any(), any())).thenReturn(false);
            assertFalse(jwt.rotateKeyWithTransition(Algorithm.RSA256, "k2", 1));

            rotation.when(() -> KeyRotation.rotateKeyAtomic(anyString(), any(), any(), any(), any()))
                    .thenThrow(new java.io.IOException("io"));
            assertThrows(java.io.UncheckedIOException.class, () -> jwt.rotateKeyWithTransition(Algorithm.RSA256, "k3", 1));
        } finally {
            jwt.close();
        }
    }

    @Test
    void loadKeyPair_should_load_from_disk_then_reuse_cached_entry() throws Exception {
        // Arrange
        String keyId = "RSA256-v20240101-000000-" + UUID.randomUUID().toString().substring(0, 8);
        Path rsaDir = Files.createDirectories(tempDir.resolve("rsa-keys"));
        Path v = Files.createDirectories(rsaDir.resolve(keyId));

        java.security.KeyPair kp = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        Files.write(v.resolve("private.key"), kp.getPrivate().getEncoded());
        Files.write(v.resolve("public.key"), kp.getPublic().getEncoded());
        Files.writeString(v.resolve("algorithm.info"), "RSA256");
        Files.writeString(v.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());
        Files.writeString(v.resolve("status.info"), "CREATED");

        rsaJwt.keyRepository = null;
        rsaJwt.currentKeyPath = rsaDir;
        rsaJwt.keyVersions.put(keyId, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId).algorithm(Algorithm.RSA256).status(KeyStatus.CREATED).expiresAt(Instant.now().plusSeconds(60)).build());

        // Act
        rsaJwt.loadKeyPair(keyId);
        Object loaded = rsaJwt.getKeyByVersion(keyId);
        rsaJwt.loadKeyPair(keyId);

        // Assert
        assertEquals(keyId, rsaJwt.getActiveKeyId());
        assertNotNull(rsaJwt.getCurrentKey());
        assertNotNull(loaded);
    }

    @Test
    void generateJwt_verifyToken_and_decodePayload_should_cover_success_and_security_exception() throws Exception {
        // Arrange
        java.security.KeyPair kp = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        setPrivateField(rsaJwt, "keyPair", kp);
        JwtProperties props = new JwtProperties();
        props.setSubject("s");
        props.setIssuer("i");
        props.setExpiration(Instant.now().plusSeconds(60));

        // Act
        String token = rsaJwt.generateJwt(props, Map.of("a", 1), Algorithm.RSA256);

        // Assert
        assertTrue(rsaJwt.verifyToken(token));
        Claims claims = rsaJwt.decodePayload(token);
        assertEquals("s", claims.getSubject());

        // Act & Assert (bad signature with another key)
        java.security.KeyPair other = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        setPrivateField(rsaJwt, "keyPair", other);
        assertThrows(SecurityException.class, () -> rsaJwt.decodePayload(token));
    }

    @Test
    void generateJwt_should_throw_when_no_active_keyPair() {
        // Arrange
        setPrivateField(rsaJwt, "keyPair", null);
        JwtProperties props = new JwtProperties();
        props.setSubject("s");
        props.setIssuer("i");
        props.setExpiration(Instant.now().plusSeconds(60));

        // Act & Assert
        assertThrows(IllegalStateException.class, () -> rsaJwt.generateJwt(props, Map.of(), Algorithm.RSA256));
    }

    @Test
    void generateAllKeyPairs_should_return_false_when_any_rotation_fails_and_true_when_all_ok() {
        // Arrange
        RsaJwt spy = spy(rsaJwt);
        doReturn(true).when(spy).rotateKey(any(), anyString());

        // Act
        assertTrue(spy.generateAllKeyPairs());

        // Arrange
        doReturn(true).when(spy).rotateKey(any(), anyString());
        doReturn(false).when(spy).rotateKey(eq(Algorithm.RSA384), anyString());

        // Act
        assertFalse(spy.generateAllKeyPairs());
    }

    @Test
    void loadKeyVersion_should_cover_exception_catch_when_keyId_unavailable() {
        // Arrange
        Path root = Path.of("C:\\");

        // Act & Assert
        assertDoesNotThrow(() -> rsaJwt.loadKeyVersion(root));
    }

    @Test
    void loadKeyVersion_should_cover_invalid_metadata_and_default_fallbacks_with_key_files() throws Exception {
        // Arrange
        Path rsaDir = tempDir.resolve("rsa-keys");
        Path v = Files.createDirectories(rsaDir.resolve("RSA256-v20240101-000003-dddd"));
        java.security.KeyPair kp = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);

        Files.write(v.resolve("private.key"), kp.getPrivate().getEncoded());
        Files.write(v.resolve("public.key"), kp.getPublic().getEncoded());
        Files.writeString(v.resolve("status.info"), "NOT_A_STATUS");
        Files.writeString(v.resolve("algorithm.info"), "NOT_AN_ALG");
        Files.writeString(v.resolve("expiration.info"), "NOT_AN_INSTANT");
        Files.writeString(v.resolve("transition.info"), "NOT_AN_INSTANT");

        // Act
        rsaJwt.loadKeyVersion(v);

        // Assert
        assertTrue(rsaJwt.getKeyVersions().contains("RSA256-v20240101-000003-dddd"));
    }

    @Test
    void close_should_cleanup_internal_state() {
        // Arrange
        rsaJwt.keyVersions.put("x", com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId("x").algorithm(Algorithm.RSA256).status(KeyStatus.CREATED).expiresAt(Instant.now().plusSeconds(60)).build());

        // Act
        rsaJwt.close();

        // Assert
        assertTrue(rsaJwt.getKeyVersions().isEmpty());
        assertNull(rsaJwt.getActiveKeyId());
    }

    @Test
    void autoLoadFirstKey_should_set_active_when_matching_key_dir_exists() throws Exception {
        // Arrange
        String keyId1 = "RSA256-v20240101-000000-aaaa";
        String keyId2 = "RSA256-v20240102-000000-bbbb";

        Path rsaDir = Files.createDirectories(tempDir.resolve("rsa-keys"));
        Path d1 = Files.createDirectories(rsaDir.resolve(keyId1));
        Path d2 = Files.createDirectories(rsaDir.resolve(keyId2));

        java.security.KeyPair kp1 = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        java.security.KeyPair kp2 = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        Files.write(d1.resolve("private.key"), kp1.getPrivate().getEncoded());
        Files.write(d1.resolve("public.key"), kp1.getPublic().getEncoded());
        Files.write(d2.resolve("private.key"), kp2.getPrivate().getEncoded());
        Files.write(d2.resolve("public.key"), kp2.getPublic().getEncoded());

        rsaJwt.keyRepository = null;
        rsaJwt.currentKeyPath = rsaDir;
        rsaJwt.keyVersions.put(keyId1, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId1).algorithm(Algorithm.RSA256).status(KeyStatus.CREATED).expiresAt(Instant.now().plusSeconds(60)).build());
        rsaJwt.keyVersions.put(keyId2, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId2).algorithm(Algorithm.RSA256).status(KeyStatus.CREATED).expiresAt(Instant.now().plusSeconds(60)).build());

        // Act
        rsaJwt.autoLoadFirstKey(Algorithm.RSA256, null, false);

        // Assert
        assertEquals(keyId2, rsaJwt.getActiveKeyId());
        assertNotNull(rsaJwt.getCurrentKey());
    }

    @Test
    void rotateKeyWithTransition_should_execute_real_atomic_rotation_to_cover_lambdas() {
        // Arrange
        when(properties.isEnableRotation()).thenReturn(true);
        RsaJwt jwt = new RsaJwt(properties, tempDir);
        jwt.keyRepository = null;

        // Act
        boolean ok = jwt.rotateKeyWithTransition(Algorithm.RSA256, "RSA256-v20240103-000000-cccc", 1);

        // Assert
        assertTrue(ok);
        jwt.close();
    }

    @Test
    void verifyToken_should_cover_parse_failure_with_active_key() throws Exception {
        // Arrange
        java.security.KeyPair kp = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        setPrivateField(rsaJwt, "keyPair", kp);

        // Act & Assert
        assertFalse(rsaJwt.verifyToken("not-a-jwt"));
    }

    @Test
    void verifyWithKeyVersion_should_cover_repo_load_success() throws Exception {
        // Arrange
        KeyRepository repo = mock(KeyRepository.class);
        when(repo.listKeys(null)).thenReturn(List.of());

        java.security.KeyPair kp = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        when(repo.loadMetadata(eq("k1"), eq("status.info"))).thenReturn(Optional.of("ACTIVE"));
        when(repo.loadMetadata(eq("k1"), eq("algorithm.info"))).thenReturn(Optional.of("RSA256"));
        when(repo.loadMetadata(eq("k1"), eq("expiration.info"))).thenReturn(Optional.of(Instant.now().plusSeconds(60).toString()));
        when(repo.loadKey(eq("k1"), eq("private.key"))).thenReturn(Optional.of(kp.getPrivate().getEncoded()));
        when(repo.loadKey(eq("k1"), eq("public.key"))).thenReturn(Optional.of(kp.getPublic().getEncoded()));

        RsaJwt jwt = new RsaJwt(properties, repo);
        jwt.keyVersions.put("k1", com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId("k1").algorithm(Algorithm.RSA256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());

        JwtProperties props = new JwtProperties();
        props.setSubject("s");
        props.setIssuer("i");
        props.setExpiration(Instant.now().plusSeconds(60));
        setPrivateField(jwt, "keyPair", kp);
        String token = jwt.generateJwt(props, Map.of(), Algorithm.RSA256);

        // Act
        boolean ok = jwt.verifyWithKeyVersion("k1", token);

        // Assert
        assertTrue(ok);
        jwt.close();
    }

    @Test
    void verifyWithKeyVersion_should_cover_disk_load_success_missing_key_and_parse_failure() throws Exception {
        // Arrange (disk load success)
        String keyId = "RSA256-v20240104-000000-dddd";
        Path rsaDir = Files.createDirectories(tempDir.resolve("rsa-keys"));
        Path v = Files.createDirectories(rsaDir.resolve(keyId));
        java.security.KeyPair kp = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        Files.write(v.resolve("private.key"), kp.getPrivate().getEncoded());
        Files.write(v.resolve("public.key"), kp.getPublic().getEncoded());

        rsaJwt.keyRepository = null;
        rsaJwt.currentKeyPath = rsaDir;
        rsaJwt.keyVersions.put(keyId, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId).algorithm(Algorithm.RSA256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());

        JwtProperties props = new JwtProperties();
        props.setSubject("s");
        props.setIssuer("i");
        props.setExpiration(Instant.now().plusSeconds(60));
        setPrivateField(rsaJwt, "keyPair", kp);
        String token = rsaJwt.generateJwt(props, Map.of(), Algorithm.RSA256);

        // Act & Assert (disk load)
        assertTrue(rsaJwt.verifyWithKeyVersion(keyId, token));

        // Arrange (missing keyPair)
        String missingId = "missing-k";
        rsaJwt.keyVersions.put(missingId, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(missingId).algorithm(Algorithm.RSA256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());

        // Act & Assert (warn branch)
        assertFalse(rsaJwt.verifyWithKeyVersion(missingId, token));

        // Act & Assert (parse failure with existing keyPair)
        assertFalse(rsaJwt.verifyWithKeyVersion(keyId, "not-a-jwt"));
    }

    @Test
    void loadKeyVersion_should_return_when_null() {
        // Act & Assert
        assertDoesNotThrow(() -> rsaJwt.loadKeyVersion(null));
    }

    @Test
    void loadKeyVersion_should_parse_transition_end_when_present() throws Exception {
        // Arrange
        Path rsaDir = tempDir.resolve("rsa-keys");
        Path v = Files.createDirectories(rsaDir.resolve("RSA256-v20240105-000000-eeee"));
        java.security.KeyPair kp = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        Files.write(v.resolve("private.key"), kp.getPrivate().getEncoded());
        Files.write(v.resolve("public.key"), kp.getPublic().getEncoded());
        Files.writeString(v.resolve("transition.info"), Instant.now().plusSeconds(60).toString());

        // Act
        rsaJwt.loadKeyVersion(v);

        // Assert
        assertNotNull(rsaJwt.keyVersions.get("RSA256-v20240105-000000-eeee").getTransitionEndsAt());
    }

    @Test
    void private_loadKeyPairFromDir_and_loadKeyPairFromPaths_should_cover_null_and_exception() throws Exception {
        // Arrange
        assertNull(invokeLoadKeyPairFromDir(rsaJwt, null));
        assertNull(invokeLoadKeyPairFromPaths(rsaJwt, null, null));

        Path rsaDir = tempDir.resolve("rsa-keys");
        Path v = Files.createDirectories(rsaDir.resolve("bad"));
        Path priv = v.resolve("private.key");
        Path pub = v.resolve("public.key");
        Files.write(priv, "bad".getBytes());
        Files.write(pub, "bad".getBytes());

        // Act
        assertNull(invokeLoadKeyPairFromPaths(rsaJwt, priv, pub));
    }

    @Test
    void loadExistingKeyVersions_should_cover_legacy_not_found_and_legacy_exception_paths() throws Exception {
        // Arrange (legacy not found)
        Path rsaDir = Files.createDirectories(tempDir.resolve("rsa-keys"));
        rsaJwt.keyRepository = null;
        rsaJwt.currentKeyPath = rsaDir;
        rsaJwt.keyVersions.clear();

        // Act
        rsaJwt.loadExistingKeyVersions();

        // Assert
        assertNull(rsaJwt.getActiveKeyId());

        // Arrange (legacy exception: currentKeyPath null)
        Method m = RsaJwt.class.getDeclaredMethod("loadLegacyKeyPair");
        m.setAccessible(true);
        rsaJwt.currentKeyPath = null;

        // Act & Assert
        assertDoesNotThrow(() -> m.invoke(rsaJwt));
    }

    @Test
    void getRsaSignAlgorithm_should_cover_rsa384_and_rsa512_cases() throws Exception {
        Method m = RsaJwt.class.getDeclaredMethod("getRsaSignAlgorithm", Algorithm.class);
        m.setAccessible(true);
        assertNotNull(m.invoke(rsaJwt, Algorithm.RSA384));
        assertNotNull(m.invoke(rsaJwt, Algorithm.RSA512));
    }

    @Test
    void rotateKeyWithTransition_should_return_false_when_rotation_disabled() {
        when(properties.isEnableRotation()).thenReturn(false);
        RsaJwt noRotation = new RsaJwt(properties, tempDir);

        boolean ok = noRotation.rotateKeyWithTransition(Algorithm.RSA256, "k1", 1);

        assertFalse(ok);
        noRotation.close();
    }

    @Test
    void rotateKeyWithTransition_should_support_repository_success_and_failure() throws Exception {
        KeyRepository repo = mock(KeyRepository.class);
        when(properties.isEnableRotation()).thenReturn(true);
        RsaJwt withRepo = new RsaJwt(properties, repo);

        boolean ok = withRepo.rotateKeyWithTransition(Algorithm.RSA256, "repo-key", 1);

        assertTrue(ok);
        verify(repo).saveKeyVersion(any(KeyVersionData.class));

        doThrow(new java.io.IOException("io")).when(repo).saveKeyVersion(any(KeyVersionData.class));
        boolean fail = withRepo.rotateKeyWithTransition(Algorithm.RSA256, "repo-key-2", 1);

        assertFalse(fail);
        withRepo.close();
    }

    @Test
    void loadExistingKeyVersions_should_cover_repo_error_and_filesystem_scan_and_legacy() throws Exception {
        KeyRepository repo = mock(KeyRepository.class);
        when(repo.listKeys(null)).thenThrow(new java.io.IOException("boom"));
        RsaJwt withRepo = new RsaJwt(properties, repo);
        assertDoesNotThrow(withRepo::loadExistingKeyVersions);

        Path rsaDir = tempDir.resolve("rsa-keys");
        Files.createDirectories(rsaDir);

        RsaJwt fs = new RsaJwt(properties, tempDir);
        fs.keyRepository = null;

        java.security.KeyPair legacyPair = invokeGenerateRsaKeyPair(fs, Algorithm.RSA256);
        Files.write(rsaDir.resolve("private.key"), legacyPair.getPrivate().getEncoded());
        Files.write(rsaDir.resolve("public.key"), legacyPair.getPublic().getEncoded());

        fs.loadExistingKeyVersions();

        assertNotNull(fs.getActiveKeyId());
        assertNotNull(fs.getCurrentKey());

        fs.close();
        withRepo.close();
    }

    @Test
    void loadExistingKeyVersions_should_return_when_currentKeyPath_null_and_repo_null() {
        rsaJwt.keyRepository = null;
        rsaJwt.currentKeyPath = null;
        assertDoesNotThrow(rsaJwt::loadExistingKeyVersions);
    }

    @Test
    void private_helpers_should_cover_key_sizes_and_update_failures() throws Exception {
        java.security.KeyPair rsa256 = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        assertNotNull(rsa256.getPrivate());

        Path tmp = Files.createDirectories(tempDir.resolve("tmp-save"));
        assertDoesNotThrow(() -> invokeSaveKeyPairToDirectory(rsaJwt, rsa256, tmp, Algorithm.RSA256, "kid"));
        assertTrue(Files.exists(tmp.resolve("private.key")));
        assertTrue(Files.exists(tmp.resolve("public.key")));
        assertTrue(Files.exists(tmp.resolve("algorithm.info")));
        assertTrue(Files.exists(tmp.resolve("expiration.info")));
        assertTrue(Files.exists(tmp.resolve("status.info")));

        assertDoesNotThrow(() -> invokeUpdateKeyVersionWithTransition(rsaJwt, "k1", Algorithm.RSA256, rsa256, 0));
        assertTrue(rsaJwt.getKeyVersions().contains("k1"));

        assertThrows(RuntimeException.class, () -> invokeUpdateKeyVersionWithTransition(rsaJwt, null, Algorithm.RSA256, rsa256, 1));
    }

    @Test
    void generateRsaKeyPair_should_choose_key_sizes_for_rsa384_and_rsa512() throws Exception {
        java.security.KeyPair dummy = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        java.security.KeyPairGenerator generator = mock(java.security.KeyPairGenerator.class);
        when(generator.generateKeyPair()).thenReturn(dummy);

        try (MockedStatic<java.security.KeyPairGenerator> mocked = mockStatic(java.security.KeyPairGenerator.class)) {
            mocked.when(() -> java.security.KeyPairGenerator.getInstance("RSA")).thenReturn(generator);

            invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA384);
            verify(generator).initialize(3072);

            clearInvocations(generator);
            invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA512);
            verify(generator).initialize(4096);
        }
    }

    @Test
    void loadKeyPair_should_throw_when_missing_on_disk_and_cover_verify_fail_paths() {
        String keyId = "missing";
        rsaJwt.keyRepository = null;
        rsaJwt.currentKeyPath = tempDir.resolve("rsa-keys");
        rsaJwt.keyVersions.put(keyId, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId)
                .algorithm(Algorithm.RSA256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(60))
                .build());

        assertThrows(IllegalArgumentException.class, () -> rsaJwt.loadKeyPair(keyId));
        assertFalse(rsaJwt.verifyToken("not-a-jwt"));
        assertFalse(rsaJwt.verifyToken(" "));
        assertFalse(rsaJwt.verifyWithKeyVersion(" ", "t"));
    }

    @Test
    void decodePayload_should_cover_blank_and_no_key() {
        assertThrows(IllegalArgumentException.class, () -> rsaJwt.decodePayload(""));

        setPrivateField(rsaJwt, "keyPair", null);
        assertThrows(SecurityException.class, () -> rsaJwt.decodePayload("a.b.c"));
    }

    @Test
    void getSignAlgorithm_should_throw_and_info_should_be_non_null() {
        assertThrows(UnsupportedOperationException.class, () -> rsaJwt.getSignAlgorithm(Algorithm.RSA256));
        assertNotNull(rsaJwt.getKeyInfo());
        assertNotNull(rsaJwt.getAlgorithmInfo());
    }

    @Test
    void verifyWithKeyVersion_should_cover_repo_loading_and_parse_failure() throws Exception {
        KeyRepository repo = mock(KeyRepository.class);
        RsaJwt withRepo = new RsaJwt(properties, repo);
        withRepo.keyVersions.put("k1", com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId("k1")
                .algorithm(Algorithm.RSA256)
                .status(KeyStatus.CREATED)
                .expiresAt(Instant.now().plusSeconds(60))
                .build());

        when(repo.loadMetadata(eq("k1"), anyString())).thenReturn(java.util.Optional.of(KeyStatus.CREATED.name()));
        when(repo.loadKey(eq("k1"), eq("private.key"))).thenReturn(java.util.Optional.of("bad".getBytes()));
        when(repo.loadKey(eq("k1"), eq("public.key"))).thenReturn(java.util.Optional.of("bad".getBytes()));

        boolean ok = withRepo.verifyWithKeyVersion("k1", "not-a-jwt");

        assertFalse(ok);
        withRepo.close();
    }

    @Test
    void loadKeyVersion_should_cover_expired_skip_null_keypair_and_active_assignment() throws Exception {
        Path rsaDir = tempDir.resolve("rsa-keys");
        Path v1 = Files.createDirectories(rsaDir.resolve("RSA256-v20240101-000000-aaaa"));

        Files.writeString(v1.resolve("status.info"), "ACTIVE");
        Files.writeString(v1.resolve("expiration.info"), Instant.now().minusSeconds(1).toString());

        rsaJwt.loadKeyVersion(v1);

        Path v2 = Files.createDirectories(rsaDir.resolve("RSA256-v20240101-000001-bbbb"));
        Files.writeString(v2.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());

        rsaJwt.loadKeyVersion(v2);

        Path v3 = Files.createDirectories(rsaDir.resolve("RSA256-v20240101-000002-cccc"));
        java.security.KeyPair kp = invokeGenerateRsaKeyPair(rsaJwt, Algorithm.RSA256);
        Files.write(v3.resolve("private.key"), kp.getPrivate().getEncoded());
        Files.write(v3.resolve("public.key"), kp.getPublic().getEncoded());
        Files.writeString(v3.resolve("status.info"), "ACTIVE");
        Files.writeString(v3.resolve("algorithm.info"), "RSA256");
        Files.writeString(v3.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());

        rsaJwt.loadKeyVersion(v3);
        assertEquals(v3.getFileName().toString(), rsaJwt.getActiveKeyId());
        assertNotNull(rsaJwt.getCurrentKey());
    }

    @Test
    void loadKeyVersion_should_swallow_invalid_metadata_and_paths() throws Exception {
        Path rsaDir = tempDir.resolve("rsa-keys");
        Path v1 = Files.createDirectories(rsaDir.resolve("v"));

        Files.writeString(v1.resolve("algorithm.info"), "NOT_AN_ALG");
        Files.writeString(v1.resolve("status.info"), "NOT_A_STATUS");
        Files.writeString(v1.resolve("expiration.info"), "NOT_AN_INSTANT");
        Files.writeString(v1.resolve("transition.info"), "NOT_AN_INSTANT");

        rsaJwt.loadKeyVersion(v1);
        assertTrue(true);
    }

    @Test
    void getRsaSignAlgorithm_should_throw_for_non_rsa() throws Exception {
        Method m = RsaJwt.class.getDeclaredMethod("getRsaSignAlgorithm", Algorithm.class);
        m.setAccessible(true);

        assertThrows(java.lang.reflect.InvocationTargetException.class, () -> m.invoke(rsaJwt, Algorithm.HMAC256));
    }

    private static java.security.KeyPair invokeGenerateRsaKeyPair(RsaJwt target, Algorithm algorithm) throws Exception {
        Method m = RsaJwt.class.getDeclaredMethod("generateRsaKeyPair", Algorithm.class);
        m.setAccessible(true);
        return (java.security.KeyPair) m.invoke(target, algorithm);
    }

    private static void invokeSaveKeyPairToDirectory(RsaJwt target, java.security.KeyPair keyPair, Path tempDir, Algorithm algorithm, String keyId) throws Exception {
        Method m = RsaJwt.class.getDeclaredMethod("saveKeyPairToDirectory", java.security.KeyPair.class, Path.class, Algorithm.class, String.class);
        m.setAccessible(true);
        m.invoke(target, keyPair, tempDir, algorithm, keyId);
    }

    private static void invokeUpdateKeyVersionWithTransition(RsaJwt target, String keyId, Algorithm algorithm, java.security.KeyPair keyPair, int transitionHours) throws Exception {
        Method m = RsaJwt.class.getDeclaredMethod("updateKeyVersionWithTransition", String.class, Algorithm.class, java.security.KeyPair.class, int.class);
        m.setAccessible(true);
        try {
            m.invoke(target, keyId, algorithm, keyPair, transitionHours);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static java.security.KeyPair invokeLoadKeyPairFromDir(RsaJwt target, Path versionDir) throws Exception {
        Method m = RsaJwt.class.getDeclaredMethod("loadKeyPairFromDir", Path.class);
        m.setAccessible(true);
        return (java.security.KeyPair) m.invoke(target, versionDir);
    }

    private static java.security.KeyPair invokeLoadKeyPairFromPaths(RsaJwt target, Path privateKeyPath, Path publicKeyPath) throws Exception {
        Method m = RsaJwt.class.getDeclaredMethod("loadKeyPairFromPaths", Path.class, Path.class);
        m.setAccessible(true);
        return (java.security.KeyPair) m.invoke(target, privateKeyPath, publicKeyPath);
    }

    private static void setPrivateField(Object target, String fieldName, Object value) {
        try {
            java.lang.reflect.Field f = target.getClass().getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}



