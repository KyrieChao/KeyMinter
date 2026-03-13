package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.port.out.KeyRepository;
import com.chao.keyMinter.internal.SecureByteArray;
import io.jsonwebtoken.Claims;
import io.jsonwebtoken.Jwts;
import io.jsonwebtoken.security.Keys;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import javax.crypto.SecretKey;
import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class HmacJwtTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    private HmacJwt hmacJwt;
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);

        when(properties.getKeyValidityMillis()).thenReturn(3600000L);
        when(properties.getTransitionPeriodHours()).thenReturn(24);
        when(properties.getTransitionPeriodMillis()).thenReturn(Duration.ofHours(24).toMillis());
        when(properties.isEnableRotation()).thenReturn(true);
        when(properties.getExpiredKeyRetentionMillis()).thenReturn(Duration.ofDays(30).toMillis());

        hmacJwt = new HmacJwt(properties, tempDir);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (hmacJwt != null) {
            hmacJwt.close();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void constructors_should_normalize_paths_and_use_default_base_dir() {
        Path base = tempDir.resolve("base");
        com.chao.keyMinter.domain.port.out.SecretDirProvider.setDefaultBaseDir(base);

        HmacJwt d0 = new HmacJwt();
        assertNotNull(d0.getKeyPath());
        assertTrue(d0.getKeyPath().endsWith("hmac-keys"));
        d0.close();

        HmacJwt d1 = new HmacJwt(base);
        assertEquals(base.normalize().resolve("hmac-keys"), d1.getKeyPath());
        d1.close();

        HmacJwt d2 = new HmacJwt(properties, (Path) null);
        assertNotNull(d2.getKeyPath());
        assertTrue(d2.getKeyPath().endsWith("hmac-keys"));
        d2.close();

        HmacJwt d3 = new HmacJwt(properties, base.resolve("x"));
        assertEquals(base.resolve("x").normalize().resolve("hmac-keys"), d3.getKeyPath());
        d3.close();
    }

    @Test
    void lombok_getters_should_be_callable() {
        assertNotNull(hmacJwt.getVersionSecrets());
        assertNull(hmacJwt.getCurrentSecret());
    }

    @Test
    void generateKeyPair_and_generateHmacKey_should_create_version_dir_and_files() throws Exception {
        assertTrue(hmacJwt.generateKeyPair(Algorithm.HMAC256));
        assertTrue(hmacJwt.generateHmacKey(Algorithm.HMAC256, 64));

        List<String> keys = hmacJwt.getKeyVersions(Algorithm.HMAC256);
        assertFalse(keys.isEmpty());

        String keyId = keys.get(0);
        hmacJwt.setActiveKey(keyId);

        assertEquals(keyId, hmacJwt.getActiveKeyId());
        assertNotNull(hmacJwt.getCurrentSecret());
        assertNotNull(hmacJwt.getCurrentKey());
        assertNotNull(hmacJwt.getKeyByVersion(keyId));

        Path versionDir = hmacJwt.getKeyPath().resolve(keyId);
        assertTrue(Files.exists(versionDir));
        assertTrue(Files.exists(versionDir.resolve("secret.key")));
        assertTrue(Files.exists(versionDir.resolve("algorithm.info")));
        assertTrue(Files.exists(versionDir.resolve("expiration.info")));
        assertTrue(Files.exists(versionDir.resolve("status.info")));
    }

    @Test
    void generateToken_verifyToken_decodePayload_should_cover_success_and_failures() {
        hmacJwt.generateHmacKey(Algorithm.HMAC256, 64);
        String keyId = hmacJwt.getKeyVersions(Algorithm.HMAC256).get(0);
        hmacJwt.setActiveKey(keyId);

        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("test-user");
        jwtProps.setIssuer("test-issuer");
        jwtProps.setExpiration(Instant.now().plusSeconds(60));

        String token = hmacJwt.generateToken(jwtProps, Map.of("role", "admin"), Algorithm.HMAC256);
        assertTrue(hmacJwt.verifyToken(token));

        Claims claims = hmacJwt.decodePayload(token);
        assertEquals("test-user", claims.getSubject());
        assertEquals("test-issuer", claims.getIssuer());
        assertEquals("admin", claims.get("role"));

        assertFalse(hmacJwt.verifyToken("not-a-jwt"));
        assertThrows(SecurityException.class, () -> hmacJwt.decodePayload("not-a-jwt"));

        setField(hmacJwt, "currentSecret", null);
        assertThrows(IllegalStateException.class, () -> hmacJwt.generateJwt(jwtProps, Map.of(), Algorithm.HMAC256));
    }

    @Test
    void rotateHmacKeyWithTransition_should_cover_repository_success_and_failure_and_min_length() throws Exception {
        KeyRepository repo = mock(KeyRepository.class);
        when(properties.isEnableRotation()).thenReturn(true);

        HmacJwt jwt = new HmacJwt(properties, repo);
        assertTrue(jwt.rotateHmacKeyWithTransition(Algorithm.HMAC256, "k1", 1, 1));
        verify(repo).saveKeyVersion(any());
        assertTrue(jwt.getKeyVersions().contains("k1"));

        doThrow(new IOException("io")).when(repo).saveKeyVersion(any());
        assertFalse(jwt.rotateHmacKeyWithTransition(Algorithm.HMAC256, "k2", 64, 1));

        jwt.close();
    }

    @Test
    void rotateHmacKeyWithTransition_should_cover_filesystem_success_and_ioexception() throws Exception {
        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("fs"));
        jwt.keyRepository = null;

        assertTrue(jwt.rotateHmacKeyWithTransition(Algorithm.HMAC256, "k1", null, 1));
        assertTrue(jwt.rotateHmacKeyWithTransition(Algorithm.HMAC256, "k1b", 64, 1));

        try (MockedStatic<KeyRotation> mocked = mockStatic(KeyRotation.class)) {
            mocked.when(() -> KeyRotation.rotateKeyAtomic(anyString(), any(), any(), any(), any())).thenThrow(new IOException("io"));
            assertThrows(UncheckedIOException.class, () -> jwt.rotateHmacKeyWithTransition(Algorithm.HMAC256, "k2", null, 1));
        }

        jwt.close();
    }

    @Test
    void rotateHmacKeyWithTransition_should_return_false_when_rotation_disabled() {
        when(properties.isEnableRotation()).thenReturn(false);
        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("disabled"));
        assertFalse(jwt.rotateHmacKeyWithTransition(Algorithm.HMAC256, "k", 64, 1));
        jwt.close();
    }

    @Test
    void verifyWithKeyVersion_should_cover_repo_load_disk_load_missing_and_parse_failures() throws Exception {
        assertFalse(hmacJwt.verifyWithKeyVersion(null, "t"));
        assertFalse(hmacJwt.verifyWithKeyVersion("k", null));

        hmacJwt.keyVersions.put("revoked", com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId("revoked").algorithm(Algorithm.HMAC256).status(KeyStatus.REVOKED).expiresAt(Instant.now().plusSeconds(60)).build());
        assertFalse(hmacJwt.verifyWithKeyVersion("revoked", "t"));

        byte[] raw = new byte[64];
        new java.security.SecureRandom().nextBytes(raw);
        SecretKey key = Keys.hmacShaKeyFor(raw);
        String token = Jwts.builder()
                .subject("s")
                .issuer("i")
                .expiration(java.util.Date.from(Instant.now().plusSeconds(60)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();

        KeyRepository repo = mock(KeyRepository.class);
        HmacJwt withRepo = new HmacJwt(properties, repo);
        withRepo.keyVersions.put("k1", com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId("k1").algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());
        when(repo.loadMetadata(eq("k1"), eq("status.info"))).thenReturn(Optional.of("ACTIVE"));
        when(repo.loadMetadata(eq("k1"), eq("expiration.info"))).thenReturn(Optional.of(Instant.now().plusSeconds(60).toString()));
        when(repo.loadMetadata(eq("k1"), eq("algorithm.info"))).thenReturn(Optional.of("HMAC256"));
        when(repo.loadKey(eq("k1"), eq("secret.key"))).thenReturn(Optional.of(raw.clone()));
        assertTrue(withRepo.verifyWithKeyVersion("k1", token));
        assertFalse(withRepo.verifyWithKeyVersion("k1", "not-a-jwt"));

        HmacJwt noRepo = new HmacJwt(properties, tempDir.resolve("disk"));
        noRepo.keyRepository = null;
        String keyId = "hmac-v20240101-000000-" + UUID.randomUUID().toString().substring(0, 8);
        Path v = Files.createDirectories(noRepo.getKeyPath().resolve(keyId));
        Files.write(v.resolve("secret.key"), raw);
        noRepo.keyVersions.put(keyId, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId).algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());
        assertTrue(noRepo.verifyWithKeyVersion(keyId, token));

        assertFalse(noRepo.verifyWithKeyVersion("missing", token));

        withRepo.close();
        noRepo.close();
    }

    @Test
    void verifyWithKeyVersion_should_warn_when_version_exists_but_secret_missing() throws Exception {
        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("missing-secret"));
        jwt.keyRepository = null;
        Files.createDirectories(jwt.getKeyPath());
        jwt.keyVersions.put("noSecret", com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId("noSecret").algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());

        assertFalse(jwt.verifyWithKeyVersion("noSecret", "a.b.c"));
        jwt.close();
    }

    @Test
    void verifyToken_should_cover_kid_path_fallback_path_and_header_parse_failure() {
        assertFalse(hmacJwt.verifyToken(null));
        assertFalse(hmacJwt.verifyToken(""));

        hmacJwt.generateHmacKey(Algorithm.HMAC256, 64);
        String keyId = hmacJwt.getKeyVersions(Algorithm.HMAC256).get(0);
        hmacJwt.setActiveKey(keyId);

        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("u");
        jwtProps.setIssuer("iss");
        jwtProps.setExpiration(Instant.now().plusSeconds(60));

        String tokenWithKid = hmacJwt.generateToken(jwtProps, null, Algorithm.HMAC256);
        assertTrue(hmacJwt.verifyToken(tokenWithKid));

        assertFalse(hmacJwt.verifyToken("not-a-jwt"));

        hmacJwt.activeKeyId = null;
        String tokenNoKid = hmacJwt.generateJwt(jwtProps, Map.of(), Algorithm.HMAC256);
        assertTrue(hmacJwt.verifyToken(tokenNoKid));

        setField(hmacJwt, "currentSecret", null);
        assertFalse(hmacJwt.verifyToken(tokenNoKid));

        assertFalse(hmacJwt.verifyToken("###.###.###"));
    }

    @Test
    void autoLoadFirstKey_should_cover_preferred_key_short_circuit() {
        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("autoload"));
        jwt.keyRepository = null;
        jwt.autoLoadFirstKey(Algorithm.HMAC256, "missing", false);
        jwt.close();
    }

    @Test
    void autoLoadFirstKey_should_cover_findKeyDir_absent_and_present() throws Exception {
        HmacJwt empty = new HmacJwt(properties, tempDir.resolve("autoload-empty"));
        empty.keyRepository = null;
        Files.createDirectories(empty.getKeyPath());
        empty.autoLoadFirstKey(Algorithm.HMAC256, null, false);
        empty.close();

        Path base = tempDir.resolve("autoload-present").resolve("hmac-keys");
        Files.createDirectories(base);
        byte[] raw = new byte[64];
        new java.security.SecureRandom().nextBytes(raw);
        String keyId = "HMAC256-v20240101-000000-aaaa";
        Path v = Files.createDirectories(base.resolve(keyId));
        Files.write(v.resolve("secret.key"), raw);
        Files.writeString(v.resolve("status.info"), "CREATED");
        Files.writeString(v.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());

        HmacJwt present = new HmacJwt(properties, tempDir.resolve("autoload-present"));
        present.keyRepository = null;
        present.loadExistingKeyVersions();
        present.autoLoadFirstKey(Algorithm.HMAC256, null, true);
        present.close();
    }

    @Test
    void decodePayload_should_cover_blank_no_key_and_success() {
        assertThrows(IllegalArgumentException.class, () -> hmacJwt.decodePayload(""));

        setField(hmacJwt, "currentSecret", null);
        assertThrows(SecurityException.class, () -> hmacJwt.decodePayload("a.b.c"));

        hmacJwt.generateHmacKey(Algorithm.HMAC256, 64);
        String keyId = hmacJwt.getKeyVersions(Algorithm.HMAC256).get(0);
        hmacJwt.setActiveKey(keyId);

        JwtProperties jwtProps = new JwtProperties();
        jwtProps.setSubject("u");
        jwtProps.setIssuer("iss");
        jwtProps.setExpiration(Instant.now().plusSeconds(60));

        String token = hmacJwt.generateToken(jwtProps, null, Algorithm.HMAC256);
        assertEquals("u", hmacJwt.decodePayload(token).getSubject());
    }

    @Test
    void loadExistingKeyVersions_should_cover_repository_list_exception_and_filesystem_guards_and_list_exception() throws Exception {
        KeyRepository repo = mock(KeyRepository.class);
        when(repo.listKeys(null)).thenThrow(new IOException("io"));
        HmacJwt repoJwt = new HmacJwt(properties, repo);
        assertDoesNotThrow(repoJwt::loadExistingKeyVersions);
        repoJwt.close();

        HmacJwt fs = new HmacJwt(properties, tempDir.resolve("guard"));
        fs.keyRepository = null;
        fs.currentKeyPath = tempDir.resolve("guard").resolve("missing");
        assertDoesNotThrow(fs::loadExistingKeyVersions);

        fs.currentKeyPath = null;
        assertDoesNotThrow(fs::loadExistingKeyVersions);

        Path notDir = tempDir.resolve("guard-file");
        Files.writeString(notDir, "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        fs.currentKeyPath = notDir;
        assertDoesNotThrow(fs::loadExistingKeyVersions);

        Path ok = Files.createDirectories(tempDir.resolve("guard2").resolve("hmac-keys"));
        fs.currentKeyPath = ok;
        try (MockedStatic<Files> files = mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.list(eq(ok))).thenThrow(new IOException("io"));
            assertDoesNotThrow(fs::loadExistingKeyVersions);
        }
        fs.close();
    }

    @Test
    void loadExistingKeyVersions_should_cover_repo_and_filesystem_and_legacy_migration() throws Exception {
        KeyRepository repo = mock(KeyRepository.class);
        when(repo.listKeys(null)).thenReturn(List.of("expired", "missing", "bad", "active", "created"));

        when(repo.loadMetadata(eq("expired"), anyString())).thenReturn(Optional.empty());
        when(repo.loadMetadata(eq("expired"), eq("expiration.info"))).thenReturn(Optional.of(Instant.now().minusSeconds(1).toString()));
        when(repo.loadKey(eq("expired"), eq("secret.key"))).thenReturn(Optional.of(new byte[64]));

        when(repo.loadMetadata(eq("missing"), anyString())).thenReturn(Optional.empty());
        when(repo.loadKey(eq("missing"), eq("secret.key"))).thenReturn(Optional.empty());

        when(repo.loadMetadata(eq("bad"), eq("status.info"))).thenReturn(Optional.of("NOT_A_STATUS"));
        when(repo.loadKey(eq("bad"), eq("secret.key"))).thenReturn(Optional.of(new byte[0]));

        byte[] raw = new byte[64];
        new java.security.SecureRandom().nextBytes(raw);
        when(repo.loadMetadata(eq("active"), eq("status.info"))).thenReturn(Optional.of("ACTIVE"));
        when(repo.loadMetadata(eq("active"), eq("algorithm.info"))).thenReturn(Optional.of("HMAC256"));
        when(repo.loadMetadata(eq("active"), eq("expiration.info"))).thenReturn(Optional.of(Instant.now().plusSeconds(60).toString()));
        when(repo.loadKey(eq("active"), eq("secret.key"))).thenReturn(Optional.of(raw.clone()));

        when(repo.loadMetadata(eq("created"), eq("status.info"))).thenReturn(Optional.of("CREATED"));
        when(repo.loadMetadata(eq("created"), eq("algorithm.info"))).thenReturn(Optional.of("HMAC256"));
        when(repo.loadMetadata(eq("created"), eq("expiration.info"))).thenReturn(Optional.of(Instant.now().plusSeconds(60).toString()));
        when(repo.loadKey(eq("created"), eq("secret.key"))).thenReturn(Optional.of(raw.clone()));

        HmacJwt repoJwt = new HmacJwt(properties, repo);
        repoJwt.loadExistingKeyVersions();
        assertEquals("active", repoJwt.getActiveKeyId());
        assertNotNull(repoJwt.getCurrentKey());
        repoJwt.close();

        HmacJwt fsJwt = new HmacJwt(properties, tempDir.resolve("fs-load"));
        fsJwt.keyRepository = null;

        Path base = fsJwt.getKeyPath();
        Files.createDirectories(base);
        Files.write(base.resolve("a.key"), raw);
        Files.write(base.resolve("empty.key"), new byte[0]);
        Files.write(base.resolve(".hidden.key"), raw);

        Path expiredDir = Files.createDirectories(base.resolve("hmac-v20240101-000000-expired"));
        Files.write(expiredDir.resolve("secret.key"), raw);
        Files.writeString(expiredDir.resolve("expiration.info"), Instant.now().minusSeconds(1).toString());
        Files.writeString(expiredDir.resolve("status.info"), "ACTIVE");
        Files.writeString(expiredDir.resolve("algorithm.info"), "HMAC256");

        Path badDir = Files.createDirectories(base.resolve("hmac-v20240101-000001-bad"));
        Files.write(badDir.resolve("secret.key"), new byte[0]);
        Files.writeString(badDir.resolve("status.info"), "NOT_A_STATUS");
        Files.writeString(badDir.resolve("algorithm.info"), "NOT_AN_ALG");
        Files.writeString(badDir.resolve("expiration.info"), "NOT_AN_INSTANT");
        Files.writeString(badDir.resolve("transition.info"), "NOT_AN_INSTANT");

        Path activeDir = Files.createDirectories(base.resolve("hmac-v20240101-000002-active"));
        Files.write(activeDir.resolve("secret.key"), raw);
        Files.writeString(activeDir.resolve("status.info"), "ACTIVE");
        Files.writeString(activeDir.resolve("algorithm.info"), "HMAC256");
        Files.writeString(activeDir.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());
        Files.writeString(activeDir.resolve("transition.info"), Instant.now().plusSeconds(60).toString());

        fsJwt.loadExistingKeyVersions();
        assertNotNull(fsJwt.getActiveKeyId());
        assertTrue(fsJwt.keyPairExists(Algorithm.HMAC256));
        fsJwt.close();
    }

    @Test
    void loadExistingKeyVersions_should_call_loadLegacyKeys_when_no_version_dirs_present() throws Exception {
        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("legacyload"));
        jwt.keyRepository = null;

        Files.createDirectories(jwt.getKeyPath().resolve("not-a-key-dir"));

        byte[] raw = new byte[64];
        new java.security.SecureRandom().nextBytes(raw);
        Files.write(jwt.getKeyPath().resolve("legacy.key"), raw);

        jwt.loadExistingKeyVersions();
        assertNotNull(jwt.getActiveKeyId());
        jwt.close();
    }

    @Test
    void loadLegacyKeys_should_cover_return_scan_catch_and_migrate() throws Exception {
        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("legacy"));
        jwt.keyRepository = null;

        Path originalKeyPath = jwt.getKeyPath();
        jwt.currentKeyPath = null;
        invokeLoadLegacyKeys(jwt);
        jwt.currentKeyPath = originalKeyPath;

        jwt.currentKeyPath = tempDir.resolve("legacy").resolve("missing");
        invokeLoadLegacyKeys(jwt);
        jwt.currentKeyPath = originalKeyPath;

        Files.createDirectories(jwt.getKeyPath());
        byte[] raw = new byte[64];
        new java.security.SecureRandom().nextBytes(raw);
        Files.write(jwt.getKeyPath().resolve("a.key"), raw);
        Files.write(jwt.getKeyPath().resolve("empty.key"), new byte[0]);
        Files.write(jwt.getKeyPath().resolve(".hidden.key"), raw);
        invokeLoadLegacyKeys(jwt);
        assertNotNull(jwt.getActiveKeyId());

        try (MockedStatic<Files> files = mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.list(eq(jwt.getKeyPath()))).thenThrow(new IOException("io"));
            invokeLoadLegacyKeys(jwt);
        }

        Path bad = jwt.getKeyPath().resolve("bad.key");
        Files.write(bad, raw);
        try (MockedStatic<Files> files = mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.readAllBytes(eq(bad))).thenThrow(new IOException("io"));
            invokeLoadLegacyKeys(jwt);
        }

        jwt.close();
    }

    @Test
    void loadKeyVersion_should_cover_exception_catch_for_root_path() {
        assertDoesNotThrow(() -> hmacJwt.loadKeyVersion(Path.of("C:\\")));
    }

    @Test
    void private_getKeyLengthForAlgorithm_should_cover_all_cases() throws Exception {
        assertEquals(64, (int) invokeGetKeyLengthForAlgorithm(hmacJwt, Algorithm.HMAC256));
        assertEquals(96, (int) invokeGetKeyLengthForAlgorithm(hmacJwt, Algorithm.HMAC384));
        assertEquals(128, (int) invokeGetKeyLengthForAlgorithm(hmacJwt, Algorithm.HMAC512));
        assertEquals(64, (int) invokeGetKeyLengthForAlgorithm(hmacJwt, Algorithm.RSA256));
    }

    @Test
    void private_loadSecureSecretFromDir_should_cover_null_missing_and_read_failure() throws Exception {
        assertNull(invokeLoadSecureSecretFromDir(hmacJwt, null));

        Path dir = Files.createDirectories(tempDir.resolve("sec").resolve("hmac-keys").resolve("v1"));
        assertNull(invokeLoadSecureSecretFromDir(hmacJwt, dir));

        Path secretFile = dir.resolve("secret.key");
        Files.write(secretFile, new byte[]{1, 2, 3});
        try (MockedStatic<Files> files = mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.readAllBytes(eq(secretFile))).thenThrow(new IOException("io"));
            assertNull(invokeLoadSecureSecretFromDir(hmacJwt, dir));
        }
    }

    @Test
    void private_getAlgorithmFromDir_should_cover_invalid_and_missing() throws Exception {
        Path dir1 = Files.createDirectories(tempDir.resolve("alg").resolve("hmac-keys").resolve("v1"));
        Files.write(dir1.resolve("secret.key"), SecureByteArray.random(64).getBytes());
        Files.writeString(dir1.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());
        Files.writeString(dir1.resolve("algorithm.info"), "NOT_AN_ALG");
        hmacJwt.loadKeyVersion(dir1);

        Path dir2 = Files.createDirectories(tempDir.resolve("alg").resolve("hmac-keys").resolve("v2"));
        Files.write(dir2.resolve("secret.key"), SecureByteArray.random(64).getBytes());
        Files.writeString(dir2.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());
        hmacJwt.loadKeyVersion(dir2);
    }

    @Test
    void updateKeyVersionWithTransition_should_cover_transition_hours_nonpositive() throws Exception {
        SecureByteArray secret = SecureByteArray.random(64);
        invokeUpdateKeyVersionWithTransition(hmacJwt, "t0", Algorithm.HMAC256, secret, 0);
        assertTrue(hmacJwt.getKeyVersions().contains("t0"));
        secret.wipe();
    }

    @Test
    void rotateKey_should_delegate_to_rotateHmacKey() {
        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("rotateKey"));
        assertTrue(jwt.rotateKey(Algorithm.HMAC256, "rk"));
        jwt.close();
    }

    @Test
    void isKeyVersionDir_should_cover_all_detection_clauses() throws Exception {
        assertFalse(hmacJwt.isKeyVersionDir(null));

        Path base = hmacJwt.getKeyPath();
        Files.createDirectories(base);

        Path p1 = Files.createDirectories(base.resolve("x"));
        Files.write(p1.resolve("secret.key"), new byte[]{1});
        assertTrue(hmacJwt.isKeyVersionDir(p1));

        Path p2 = Files.createDirectories(base.resolve("y"));
        Files.writeString(p2.resolve("algorithm.info"), "HMAC256");
        assertTrue(hmacJwt.isKeyVersionDir(p2));

        Path p3 = Files.createDirectories(base.resolve("hmac-v20240101-000000-a"));
        assertTrue(hmacJwt.isKeyVersionDir(p3));

        Path p4 = Files.createDirectories(base.resolve("z"));
        assertFalse(hmacJwt.isKeyVersionDir(p4));

        Path p5 = Files.createDirectories(base.resolve("hmac"));
        assertFalse(hmacJwt.isKeyVersionDir(p5));

        Path p6 = Files.createDirectories(base.resolve("x-v"));
        assertFalse(hmacJwt.isKeyVersionDir(p6));
    }

    @Test
    void loadKeyVersion_should_cover_null_secret_empty_and_missing_expiration() throws Exception {
        assertDoesNotThrow(() -> hmacJwt.loadKeyVersion(null));

        Path base = Files.createDirectories(tempDir.resolve("loadKeyVersion").resolve("hmac-keys"));

        Path noSecret = Files.createDirectories(base.resolve("HMAC256-v20240101-000000-nosecret"));
        Files.writeString(noSecret.resolve("algorithm.info"), "HMAC256");
        hmacJwt.loadKeyVersion(noSecret);

        Path emptySecret = Files.createDirectories(base.resolve("HMAC256-v20240101-000001-empty"));
        Files.write(emptySecret.resolve("secret.key"), new byte[0]);
        Files.writeString(emptySecret.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());
        hmacJwt.loadKeyVersion(emptySecret);

        Path noExp = Files.createDirectories(base.resolve("HMAC256-v20240101-000002-noexp"));
        Files.write(noExp.resolve("secret.key"), SecureByteArray.random(64).getBytes());
        Files.writeString(noExp.resolve("algorithm.info"), "HMAC256");
        hmacJwt.loadKeyVersion(noExp);
    }

    @Test
    void constructors_should_cover_active_key_present_and_repo_rotation_disabled_branch() throws Exception {
        byte[] raw = new byte[64];
        new java.security.SecureRandom().nextBytes(raw);
        Path base = Files.createDirectories(tempDir.resolve("ctor-active").resolve("hmac-keys").resolve("HMAC256-v20240101-000000-active"));
        Files.write(base.resolve("secret.key"), raw);
        Files.writeString(base.resolve("status.info"), "ACTIVE");
        Files.writeString(base.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());
        Files.writeString(base.resolve("algorithm.info"), "HMAC256");

        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("ctor-active"));
        assertNotNull(jwt.getActiveKeyId());
        jwt.close();

        KeyRepository repo = mock(KeyRepository.class);
        when(properties.isEnableRotation()).thenReturn(false);
        HmacJwt repoJwt = new HmacJwt(properties, repo);
        repoJwt.close();
    }

    @Test
    void verifyWithKeyVersion_should_cover_cached_wiped_and_null_path_cases() throws Exception {
        byte[] raw = new byte[64];
        new java.security.SecureRandom().nextBytes(raw);
        SecretKey key = Keys.hmacShaKeyFor(raw);
        String token = Jwts.builder()
                .subject("s")
                .issuer("i")
                .expiration(java.util.Date.from(Instant.now().plusSeconds(60)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();

        HmacJwt cached = new HmacJwt(properties, tempDir.resolve("cached"));
        cached.keyRepository = null;
        cached.keyVersions.put("k", com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId("k").algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());
        cached.getVersionSecrets().put("k", SecureByteArray.fromBytes(raw));
        assertTrue(cached.verifyWithKeyVersion("k", token));
        cached.close();

        HmacJwt wiped = new HmacJwt(properties, tempDir.resolve("wiped"));
        wiped.keyRepository = null;
        String keyId = "HMAC256-v20240101-000000-wiped";
        Path v = Files.createDirectories(wiped.getKeyPath().resolve(keyId));
        Files.write(v.resolve("secret.key"), raw);
        wiped.keyVersions.put(keyId, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId).algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());
        SecureByteArray s = SecureByteArray.fromBytes(raw);
        s.wipe();
        wiped.getVersionSecrets().put(keyId, s);
        assertTrue(wiped.verifyWithKeyVersion(keyId, token));

        wiped.currentKeyPath = null;
        wiped.keyVersions.put("nopath", com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId("nopath").algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());
        assertFalse(wiped.verifyWithKeyVersion("nopath", token));

        wiped.close();
    }

    @Test
    void verifyWithKeyVersion_should_cover_empty_secret_loaded_from_disk_and_wiped_secret_no_reload() throws Exception {
        byte[] raw = new byte[64];
        new java.security.SecureRandom().nextBytes(raw);
        SecretKey key = Keys.hmacShaKeyFor(raw);
        String token = Jwts.builder()
                .subject("s")
                .issuer("i")
                .expiration(java.util.Date.from(Instant.now().plusSeconds(60)))
                .signWith(key, Jwts.SIG.HS256)
                .compact();

        HmacJwt empty = new HmacJwt(properties, tempDir.resolve("v-empty"));
        empty.keyRepository = null;
        String keyId = "HMAC256-v20240101-000000-empty";
        Path v = Files.createDirectories(empty.getKeyPath().resolve(keyId));
        Files.write(v.resolve("secret.key"), new byte[0]);
        empty.keyVersions.put(keyId, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId).algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());
        assertFalse(empty.verifyWithKeyVersion(keyId, token));
        empty.close();

        HmacJwt wiped = new HmacJwt(properties, tempDir.resolve("v-wiped-noreload"));
        wiped.keyRepository = null;
        wiped.currentKeyPath = null;
        wiped.keyVersions.put("k", com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId("k").algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());
        SecureByteArray s = SecureByteArray.fromBytes(raw);
        s.wipe();
        wiped.getVersionSecrets().put("k", s);
        assertFalse(wiped.verifyWithKeyVersion("k", token));
        wiped.close();
    }

    @Test
    void current_secret_is_wiped_should_be_treated_as_unavailable() {
        SecureByteArray s = SecureByteArray.random(64);
        s.wipe();
        setField(hmacJwt, "currentSecret", s);
        assertFalse(hmacJwt.verifyToken("a.b.c"));
        assertThrows(SecurityException.class, () -> hmacJwt.decodePayload("a.b.c"));
        assertThrows(IllegalStateException.class, () -> hmacJwt.generateJwt(new JwtProperties(), Map.of(), Algorithm.HMAC256));
    }

    @Test
    void getKeyInfo_should_cover_active_key_and_rotation_disabled_branches() {
        assertNotNull(hmacJwt.getKeyInfo());

        hmacJwt.generateHmacKey(Algorithm.HMAC256, 64);
        String keyId = hmacJwt.getKeyVersions(Algorithm.HMAC256).get(0);
        hmacJwt.setActiveKey(keyId);
        assertTrue(hmacJwt.getKeyInfo().contains(keyId));

        when(properties.isEnableRotation()).thenReturn(false);
        HmacJwt disabled = new HmacJwt(properties, tempDir.resolve("info"));
        assertTrue(disabled.getKeyInfo().contains("disabled"));
        disabled.close();
    }

    @Test
    void loadKeyPair_should_cover_reload_when_wiped_and_missing_secret() throws Exception {
        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("kp"));
        jwt.keyRepository = null;

        byte[] raw = new byte[64];
        new java.security.SecureRandom().nextBytes(raw);

        String keyId = "hmac-v20240101-000000-" + UUID.randomUUID().toString().substring(0, 8);
        Path v = Files.createDirectories(jwt.getKeyPath().resolve(keyId));
        Files.write(v.resolve("secret.key"), raw);
        Files.writeString(v.resolve("status.info"), "ACTIVE");
        Files.writeString(v.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());

        jwt.keyVersions.put(keyId, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId).algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());

        SecureByteArray s = SecureByteArray.fromBytes(raw);
        s.wipe();
        jwt.getVersionSecrets().put(keyId, s);

        jwt.setActiveKey(keyId);
        assertEquals(keyId, jwt.getActiveKeyId());
        assertNotNull(jwt.getCurrentKey());

        assertThrows(IllegalArgumentException.class, () -> jwt.loadKeyPair("missing"));
        jwt.close();
    }

    @Test
    void loadKeyPair_should_throw_when_secret_is_empty() throws Exception {
        HmacJwt jwt = new HmacJwt(properties, tempDir.resolve("kp-empty"));
        jwt.keyRepository = null;

        String keyId = "HMAC256-v20240101-000000-empty";
        Path v = Files.createDirectories(jwt.getKeyPath().resolve(keyId));
        Files.write(v.resolve("secret.key"), new byte[0]);
        Files.writeString(v.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());
        jwt.keyVersions.put(keyId, com.chao.keyMinter.domain.model.KeyVersion.builder()
                .keyId(keyId).algorithm(Algorithm.HMAC256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60)).build());

        assertThrows(IllegalArgumentException.class, () -> jwt.loadKeyPair(keyId));
        jwt.close();
    }

    @Test
    void getSignAlgorithm_should_cover_default_branch() {
        assertThrows(IllegalArgumentException.class, () -> hmacJwt.generateJwt(new JwtProperties(), Map.of(), Algorithm.RSA256));
        assertThrows(IllegalStateException.class, () -> invokeGetSignAlgorithm(hmacJwt, Algorithm.RSA256));
        assertNotNull(invokeGetSignAlgorithm(hmacJwt, Algorithm.HMAC256));
        assertNotNull(invokeGetSignAlgorithm(hmacJwt, Algorithm.HMAC384));
        assertNotNull(invokeGetSignAlgorithm(hmacJwt, Algorithm.HMAC512));
    }

    @Test
    void autoLoadFirstKey_should_cover_force_and_no_dir_paths() {
        class NoFilesHmacJwt extends HmacJwt {
            NoFilesHmacJwt(KeyMinterProperties properties, Path secretDir) {
                super(properties, secretDir);
            }

            @Override
            protected boolean hasKeyFilesInDirectory(String tag) {
                return false;
            }
        }

        NoFilesHmacJwt jwt = new NoFilesHmacJwt(properties, tempDir.resolve("nofiles"));
        jwt.keyRepository = null;
        jwt.autoLoadFirstKey(Algorithm.HMAC256, null, false);
        assertNull(jwt.getActiveKeyId());
        assertNull(jwt.getCurrentSecret());

        jwt.autoLoadFirstKey(null, null, false);
        jwt.autoLoadFirstKey(Algorithm.HMAC256, null, true);
        jwt.close();
    }

    @Test
    void private_helpers_should_cover_exception_paths() throws Exception {
        SecureByteArray secret = SecureByteArray.random(64);
        Path out = Files.createDirectories(tempDir.resolve("out"));
        invokeSaveSecretToDirectory(hmacJwt, secret, out, Algorithm.HMAC256, "k");

        try (MockedStatic<Files> files = mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.write(any(Path.class), any(byte[].class), any(java.nio.file.OpenOption[].class))).thenThrow(new IOException("io"));
            assertThrows(UncheckedIOException.class, () -> invokeSaveSecretToDirectory(hmacJwt, secret, out, Algorithm.HMAC256, "k2"));
        }

        assertThrows(RuntimeException.class, () -> invokeUpdateKeyVersionWithTransition(hmacJwt, "k", Algorithm.HMAC256, null, 1));

        Path target = out.resolve("atomic.key");
        invokeWriteSecretToFileAtomically(hmacJwt, target, secret);

        try (MockedStatic<Files> files = mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.deleteIfExists(any(Path.class))).thenThrow(new IOException("io"));
            invokeWriteSecretToFileAtomically(hmacJwt, out.resolve("atomic2.key"), secret);
        }

        try (MockedStatic<Files> files = mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.write(any(Path.class), any(byte[].class), any(java.nio.file.OpenOption[].class))).thenThrow(new IOException("io"));
            assertThrows(UncheckedIOException.class, () -> invokeWriteSecretToFileAtomically(hmacJwt, out.resolve("atomic3.key"), secret));
        }

        secret.wipe();
    }

    @Test
    void generateAllKeyPairs_should_cover_success_and_failure() {
        HmacJwt spy = spy(hmacJwt);
        doReturn(true).when(spy).rotateHmacKey(any(), anyString(), any());
        assertTrue(spy.generateAllKeyPairs());

        doReturn(true).when(spy).rotateHmacKey(any(), anyString(), any());
        doReturn(false).when(spy).rotateHmacKey(eq(Algorithm.HMAC384), anyString(), any());
        assertFalse(spy.generateAllKeyPairs());
    }

    @Test
    void getKeyInfo_getAlgorithmInfo_and_close_should_cover_cleanup() {
        assertNotNull(hmacJwt.getKeyInfo());
        assertNotNull(hmacJwt.getAlgorithmInfo());
        hmacJwt.generateHmacKey(Algorithm.HMAC256, 64);
        String keyId = hmacJwt.getKeyVersions(Algorithm.HMAC256).get(0);
        hmacJwt.setActiveKey(keyId);

        Object current = hmacJwt.getCurrentKey();
        assertNotNull(current);

        hmacJwt.close();
        assertNull(hmacJwt.getActiveKeyId());
        assertTrue(hmacJwt.getKeyVersions().isEmpty());
    }

    private static void setField(Object target, String name, Object value) {
        try {
            Field f = null;
            Class<?> c = target.getClass();
            while (c != null && c != Object.class) {
                try {
                    f = c.getDeclaredField(name);
                    break;
                } catch (NoSuchFieldException ignored) {
                    c = c.getSuperclass();
                }
            }
            if (f == null) {
                throw new NoSuchFieldException(name);
            }
            f.setAccessible(true);
            f.set(target, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static Object invokeGetSignAlgorithm(HmacJwt jwt, Algorithm algorithm) {
        try {
            Method m = HmacJwt.class.getDeclaredMethod("getSignAlgorithm", Algorithm.class);
            m.setAccessible(true);
            return m.invoke(jwt, algorithm);
        } catch (Exception e) {
            if (e instanceof java.lang.reflect.InvocationTargetException ite && ite.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw new RuntimeException(e);
        }
    }

    private static void invokeSaveSecretToDirectory(HmacJwt jwt, SecureByteArray secret, Path dir, Algorithm alg, String keyId) throws Exception {
        Method m = HmacJwt.class.getDeclaredMethod("saveSecretToDirectory", SecureByteArray.class, Path.class, Algorithm.class, String.class);
        m.setAccessible(true);
        try {
            m.invoke(jwt, secret, dir, alg, keyId);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeUpdateKeyVersionWithTransition(HmacJwt jwt, String keyId, Algorithm alg, SecureByteArray secret, int hours) throws Exception {
        Method m = HmacJwt.class.getDeclaredMethod("updateKeyVersionWithTransition", String.class, Algorithm.class, SecureByteArray.class, int.class);
        m.setAccessible(true);
        try {
            m.invoke(jwt, keyId, alg, secret, hours);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeWriteSecretToFileAtomically(HmacJwt jwt, Path target, SecureByteArray secret) throws Exception {
        Method m = HmacJwt.class.getDeclaredMethod("writeSecretToFileAtomically", Path.class, SecureByteArray.class);
        m.setAccessible(true);
        try {
            m.invoke(jwt, target, secret);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeLoadLegacyKeys(HmacJwt jwt) throws Exception {
        Method m = HmacJwt.class.getDeclaredMethod("loadLegacyKeys");
        m.setAccessible(true);
        m.invoke(jwt);
    }

    private static Object invokeGetKeyLengthForAlgorithm(HmacJwt jwt, Algorithm algorithm) throws Exception {
        Method m = HmacJwt.class.getDeclaredMethod("getKeyLengthForAlgorithm", Algorithm.class);
        m.setAccessible(true);
        return m.invoke(jwt, algorithm);
    }

    private static SecureByteArray invokeLoadSecureSecretFromDir(HmacJwt jwt, Path versionDir) throws Exception {
        Method m = HmacJwt.class.getDeclaredMethod("loadSecureSecretFromDir", Path.class);
        m.setAccessible(true);
        return (SecureByteArray) m.invoke(jwt, versionDir);
    }
}

