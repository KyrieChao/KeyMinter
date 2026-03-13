package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersion;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.MockitoAnnotations;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class EcdsaJwtExtendedTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    private EcdsaJwt ecdsaJwt;
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        KeyRotation.setLockProvider(null); // Ensure clean state
        mocks = MockitoAnnotations.openMocks(this);
        when(properties.getKeyValidityMillis()).thenReturn(3600000L);
        when(properties.getTransitionPeriodHours()).thenReturn(24);
        when(properties.isEnableRotation()).thenReturn(true);
        
        ecdsaJwt = new EcdsaJwt(properties, tempDir);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (ecdsaJwt != null) {
            ecdsaJwt.close();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void testLegacyKeyMigration() throws Exception {
        // 1. Generate keys
        EcdsaJwt temp = null;
        try {
            temp = new EcdsaJwt(properties, tempDir);
            temp.generateKeyPair(Algorithm.ES256);
            List<String> keys = temp.getKeyVersions(Algorithm.ES256);
            String keyId = keys.get(0);
            
            Path ecDir = tempDir.resolve("ec-keys"); // This is where EcdsaJwt looks
            Path keyDir = ecDir.resolve(keyId);
            
            byte[] privateBytes = Files.readAllBytes(keyDir.resolve("private.key"));
            byte[] publicBytes = Files.readAllBytes(keyDir.resolve("public.key"));
            
            // Write legacy files directly in ec-keys directory
            Files.write(ecDir.resolve("legacy-es256-private.key"), privateBytes);
            Files.write(ecDir.resolve("legacy-es256-public.key"), publicBytes);
        } finally {
            if (temp != null) temp.close();
        }
        
        // 2. Initialize
        ecdsaJwt = new EcdsaJwt(properties, tempDir);
        
        // 3. Force migration via reflection
        java.lang.reflect.Field repoField = AbstractJwtAlgo.class.getDeclaredField("keyRepository");
        repoField.setAccessible(true);
        repoField.set(ecdsaJwt, null);
        
        java.lang.reflect.Method loadLegacyMethod = EcdsaJwt.class.getDeclaredMethod("loadLegacyKeyPairs");
        loadLegacyMethod.setAccessible(true);
        loadLegacyMethod.invoke(ecdsaJwt);
        
        // 4. Verify
        Path ecDir = tempDir.resolve("ec-keys");
        boolean migrated = Files.list(ecDir)
                .anyMatch(p -> Files.isDirectory(p) && p.getFileName().toString().contains("legacy"));
        
        assertTrue(migrated, "Should have migrated legacy keys");
        assertTrue(ecdsaJwt.keyPairExists(Algorithm.ES256));
    }
    
    @Test
    void testGetCurveInfo() {
        // No active key initially
        String info = ecdsaJwt.getCurveInfo(Algorithm.ES256);
        assertTrue(info.contains("No active key"));
        
        // Generate and activate
        ecdsaJwt.generateKeyPair(Algorithm.ES256);
        List<String> keys = ecdsaJwt.getKeyVersions(Algorithm.ES256);
        ecdsaJwt.setActiveKey(keys.get(0));
        
        info = ecdsaJwt.getCurveInfo(Algorithm.ES256);
        assertTrue(info.contains("Curve: secp256r1"));
        assertTrue(info.contains("Key Size: 256"));
    }
    
    @Test
    void testInvalidAlgorithm() {
        assertThrows(IllegalArgumentException.class, () -> ecdsaJwt.getCurveInfo(Algorithm.RSA256));
        assertThrows(IllegalArgumentException.class, () -> ecdsaJwt.generateKeyPair(Algorithm.RSA256));
    }
    
    @Test
    void testGenerateJwtWithoutActiveKey() {
        JwtProperties props = new JwtProperties("sub", "iss", Instant.now());
        assertThrows(IllegalStateException.class, () -> ecdsaJwt.generateJwt(props, null, Algorithm.ES256));
    }
    
    @Test
    void testVerifyTokenWithoutActiveKey() {
        assertFalse(ecdsaJwt.verifyToken("some.token.here"));
    }
    
    @Test
    void testConstructors() {
        EcdsaJwt defaultJwt = null;
        try {
            defaultJwt = new EcdsaJwt();
            assertNotNull(defaultJwt);
        } catch (Exception e) {
            // ignore
        } finally {
            if (defaultJwt != null) defaultJwt.close();
        }
        
        EcdsaJwt pathJwt = null;
        try {
            pathJwt = new EcdsaJwt(tempDir);
            assertNotNull(pathJwt);
        } finally {
            if (pathJwt != null) pathJwt.close();
        }
    }
    
    @Test
    void testGenerateAllKeyPairs() {
        assertTrue(ecdsaJwt.generateAllKeyPairs());
        assertTrue(ecdsaJwt.getKeyVersions(Algorithm.ES256).size() > 0);
        assertTrue(ecdsaJwt.getKeyVersions(Algorithm.ES384).size() > 0);
        assertTrue(ecdsaJwt.getKeyVersions(Algorithm.ES512).size() > 0);
    }
    
    @Test
    void testGetKeyInfo() {
        String info = ecdsaJwt.getKeyInfo();
        assertTrue(info.contains("ECDSA Keys"));
    }
    
    @Test
    void testAlgorithmInfo() {
        String info = ecdsaJwt.getAlgorithmInfo();
        assertTrue(info.contains("ES256"));
    }

    @Test
    void initializeKeyPath_should_cover_null_and_ec_keys_suffix_and_active_key_present_constructor() throws Exception {
        EcdsaJwt a = new EcdsaJwt(properties, (Path) null);
        assertTrue(a.getKeyPath().endsWith("ec-keys"));
        a.close();

        Path ec = Files.createDirectories(tempDir.resolve("ec-keys"));
        EcdsaJwt b = new EcdsaJwt(properties, ec);
        assertEquals(ec.normalize(), b.getKeyPath());
        b.close();

        EcdsaJwt gen = new EcdsaJwt(properties, tempDir.resolve("ctor-active"));
        assertTrue(gen.generateKeyPair(Algorithm.ES256));
        String keyId = gen.getKeyVersions(Algorithm.ES256).get(0);
        gen.setActiveKey(keyId);
        gen.close();

        EcdsaJwt loaded = new EcdsaJwt(properties, tempDir.resolve("ctor-active"));
        assertNotNull(loaded.getActiveKeyId());
        loaded.close();
    }

    @Test
    void rotateKeyWithTransition_should_cover_disabled_and_ioexception_and_transition_hours_nonpositive() throws Exception {
        when(properties.isEnableRotation()).thenReturn(false);
        EcdsaJwt disabled = new EcdsaJwt(properties, tempDir.resolve("disabled"));
        assertFalse(disabled.rotateKeyWithTransition(Algorithm.ES256, "k", 1));
        disabled.close();

        when(properties.isEnableRotation()).thenReturn(true);
        try (MockedStatic<KeyRotation> mocked = Mockito.mockStatic(KeyRotation.class)) {
            mocked.when(() -> KeyRotation.rotateKeyAtomic(anyString(), any(), any(), any(), any())).thenThrow(new IOException("io"));
            assertThrows(UncheckedIOException.class, () -> ecdsaJwt.rotateKeyWithTransition(Algorithm.ES256, "k2", 1));
        }

        assertTrue(ecdsaJwt.rotateKeyWithTransition(Algorithm.ES256, ecdsaJwt.generateKeyVersionId(Algorithm.ES256), 0));
    }

    @Test
    void loadExistingKeyVersions_should_cover_guards_and_list_exception() throws Exception {
        ecdsaJwt.currentKeyPath = null;
        assertDoesNotThrow(ecdsaJwt::loadExistingKeyVersions);

        ecdsaJwt.currentKeyPath = tempDir.resolve("missing-ec-keys");
        assertDoesNotThrow(ecdsaJwt::loadExistingKeyVersions);

        Path file = tempDir.resolve("not-dir");
        Files.writeString(file, "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        ecdsaJwt.currentKeyPath = file;
        assertDoesNotThrow(ecdsaJwt::loadExistingKeyVersions);

        Path dir = Files.createDirectories(tempDir.resolve("ec-keys"));
        ecdsaJwt.currentKeyPath = dir;
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.list(eq(dir))).thenThrow(new IOException("io"));
            assertDoesNotThrow(ecdsaJwt::loadExistingKeyVersions);
        }
    }

    @Test
    void isKeyVersionDir_should_cover_all_detection_clauses() throws Exception {
        assertFalse(ecdsaJwt.isKeyVersionDir(null));

        Path base = Files.createDirectories(tempDir.resolve("isKeyVersionDir").resolve("ec-keys"));

        Path d1 = Files.createDirectories(base.resolve("x"));
        Files.write(d1.resolve("private.key"), new byte[]{1});
        Files.write(d1.resolve("public.key"), new byte[]{2});
        assertTrue(ecdsaJwt.isKeyVersionDir(d1));

        Path d1a = Files.createDirectories(base.resolve("x-private-only"));
        Files.write(d1a.resolve("private.key"), new byte[]{1});
        assertFalse(ecdsaJwt.isKeyVersionDir(d1a));

        Path d1b = Files.createDirectories(base.resolve("x-public-only"));
        Files.write(d1b.resolve("public.key"), new byte[]{1});
        assertFalse(ecdsaJwt.isKeyVersionDir(d1b));

        Path d2 = Files.createDirectories(base.resolve("y"));
        Files.writeString(d2.resolve("algorithm.info"), "ES256");
        assertTrue(ecdsaJwt.isKeyVersionDir(d2));

        Path d3 = Files.createDirectories(base.resolve("es256-v20240101-000000-a"));
        assertTrue(ecdsaJwt.isKeyVersionDir(d3));

        Path d3a = Files.createDirectories(base.resolve("es256"));
        assertFalse(ecdsaJwt.isKeyVersionDir(d3a));

        Path d3b = Files.createDirectories(base.resolve("x-v"));
        assertFalse(ecdsaJwt.isKeyVersionDir(d3b));

        Path d4 = Files.createDirectories(base.resolve("z"));
        assertFalse(ecdsaJwt.isKeyVersionDir(d4));
    }

    @Test
    void loadKeyPair_should_cover_cache_hit_reload_and_missing() {
        assertTrue(ecdsaJwt.generateKeyPair(Algorithm.ES256));
        String keyId = ecdsaJwt.getKeyVersions(Algorithm.ES256).get(0);

        assertDoesNotThrow(() -> ecdsaJwt.loadKeyPair(keyId));
        assertDoesNotThrow(() -> ecdsaJwt.loadKeyPair(keyId));

        ecdsaJwt.getVersionKeyPairs().remove(keyId);
        assertDoesNotThrow(() -> ecdsaJwt.loadKeyPair(keyId));

        assertThrows(IllegalArgumentException.class, () -> ecdsaJwt.loadKeyPair("missing"));
    }

    @Test
    void verifyWithKeyVersion_verifyToken_decodePayload_should_cover_cache_miss_parse_fail_and_status_blocks() {
        assertTrue(ecdsaJwt.generateKeyPair(Algorithm.ES256));
        String keyId = ecdsaJwt.getKeyVersions(Algorithm.ES256).get(0);
        ecdsaJwt.setActiveKey(keyId);

        JwtProperties props = new JwtProperties("s", "i", Instant.now().plusSeconds(60));
        String token = ecdsaJwt.generateToken(props, Map.of(), Algorithm.ES256);

        ecdsaJwt.getVersionKeyPairs().remove(keyId);
        assertTrue(ecdsaJwt.verifyWithKeyVersion(keyId, token));
        assertFalse(ecdsaJwt.verifyWithKeyVersion(keyId, "not-a-jwt"));
        assertFalse(ecdsaJwt.verifyWithKeyVersion("missing", token));
        assertFalse(ecdsaJwt.verifyWithKeyVersion("", token));
        assertFalse(ecdsaJwt.verifyWithKeyVersion(keyId, ""));

        ecdsaJwt.keyVersions.get(keyId).setStatus(KeyStatus.REVOKED);
        assertFalse(ecdsaJwt.verifyWithKeyVersion(keyId, token));

        assertTrue(ecdsaJwt.verifyToken(token));
        assertFalse(ecdsaJwt.verifyToken("not-a-jwt"));

        ecdsaJwt.getVersionKeyPairs().remove(keyId);
        assertFalse(ecdsaJwt.verifyToken(token));

        assertThrows(IllegalArgumentException.class, () -> ecdsaJwt.decodePayload(""));
        ecdsaJwt.activeKeyId = null;
        assertThrows(SecurityException.class, () -> ecdsaJwt.decodePayload(token));
    }

    @Test
    void decodePayload_should_cover_active_key_not_loaded_and_jwt_exception_wrapping() {
        assertTrue(ecdsaJwt.generateKeyPair(Algorithm.ES256));
        String keyId = ecdsaJwt.getKeyVersions(Algorithm.ES256).get(0);
        ecdsaJwt.setActiveKey(keyId);

        JwtProperties props = new JwtProperties("s", "i", Instant.now().plusSeconds(60));
        String token = ecdsaJwt.generateToken(props, Map.of(), Algorithm.ES256);

        ecdsaJwt.getVersionKeyPairs().remove(keyId);
        assertThrows(SecurityException.class, () -> ecdsaJwt.decodePayload(token));

        ecdsaJwt.loadKeyPair(keyId);
        String tampered = token.substring(0, token.length() - 2) + "aa";
        assertThrows(SecurityException.class, () -> ecdsaJwt.decodePayload(tampered));
    }

    @Test
    void generateJwt_should_cover_active_missing_keypair_and_es384_es512() {
        JwtProperties props = new JwtProperties("s", "i", Instant.now().plusSeconds(60));

        assertThrows(IllegalStateException.class, () -> ecdsaJwt.generateJwt(props, Map.of(), Algorithm.ES256));

        assertTrue(ecdsaJwt.generateKeyPair(Algorithm.ES384));
        String k384 = ecdsaJwt.getKeyVersions(Algorithm.ES384).get(0);
        ecdsaJwt.setActiveKey(k384);
        assertNotNull(ecdsaJwt.generateToken(props, Map.of(), Algorithm.ES384));

        assertTrue(ecdsaJwt.generateKeyPair(Algorithm.ES512));
        String k512 = ecdsaJwt.getKeyVersions(Algorithm.ES512).get(0);
        ecdsaJwt.setActiveKey(k512);
        assertNotNull(ecdsaJwt.generateToken(props, Map.of(), Algorithm.ES512));

        ecdsaJwt.getVersionKeyPairs().remove(k512);
        assertThrows(IllegalStateException.class, () -> ecdsaJwt.generateJwt(props, Map.of(), Algorithm.ES512));
    }

    @Test
    void getCurveInfo_should_cover_not_available_branch_and_key_info_branches() throws Exception {
        assertTrue(ecdsaJwt.getCurveInfo(Algorithm.ES256).contains("No active key"));

        KeyPairGenerator rsa = KeyPairGenerator.getInstance("RSA");
        rsa.initialize(2048);
        KeyPair rsaKeyPair = rsa.generateKeyPair();
        ecdsaJwt.activeKeyId = "rsa";
        ecdsaJwt.getVersionKeyPairs().put("rsa", rsaKeyPair);
        assertTrue(ecdsaJwt.getCurveInfo(Algorithm.ES256).contains("not available"));

        ecdsaJwt.activeKeyId = "missing";
        ecdsaJwt.getVersionKeyPairs().remove("missing");
        assertTrue(ecdsaJwt.getCurveInfo(Algorithm.ES256).contains("not available"));

        ecdsaJwt.activeKeyId = "rsa";
        assertTrue(ecdsaJwt.getKeyInfo().contains("Active: rsa"));

        when(properties.isEnableRotation()).thenReturn(false);
        EcdsaJwt disabled = new EcdsaJwt(properties, tempDir.resolve("info"));
        assertTrue(disabled.getKeyInfo().contains("disabled"));
        disabled.close();
    }

    @Test
    void loadKeyVersion_should_cover_expired_skip_null_keypair_invalid_metadata_and_active_branch() throws Exception {
        Path base = Files.createDirectories(tempDir.resolve("loadKeyVersion").resolve("ec-keys"));
        EcdsaJwt jwt = new EcdsaJwt(properties, tempDir.resolve("loadKeyVersion"));

        assertDoesNotThrow(() -> jwt.loadKeyVersion(null));

        KeyPair ecKeyPair = generateEc("secp256r1");

        Path expiredDir = Files.createDirectories(base.resolve("es256-v20240101-000000-expired"));
        Files.write(expiredDir.resolve("private.key"), ecKeyPair.getPrivate().getEncoded());
        Files.write(expiredDir.resolve("public.key"), ecKeyPair.getPublic().getEncoded());
        Files.writeString(expiredDir.resolve("expiration.info"), Instant.now().minusSeconds(10).toString());
        Files.writeString(expiredDir.resolve("status.info"), "ACTIVE");
        jwt.loadKeyVersion(expiredDir);
        assertFalse(jwt.getKeyVersions().contains(expiredDir.getFileName().toString()));

        Path noKeyPairDir = Files.createDirectories(base.resolve("es256-v20240101-000001-nokp"));
        Files.writeString(noKeyPairDir.resolve("algorithm.info"), "ES256");
        jwt.loadKeyVersion(noKeyPairDir);

        Path good = Files.createDirectories(base.resolve("es256-v20240101-000002-good"));
        Files.write(good.resolve("private.key"), ecKeyPair.getPrivate().getEncoded());
        Files.write(good.resolve("public.key"), ecKeyPair.getPublic().getEncoded());
        Files.writeString(good.resolve("status.info"), "ACTIVE");
        Files.writeString(good.resolve("algorithm.info"), "BAD");
        Files.writeString(good.resolve("expiration.info"), "BAD");
        Files.writeString(good.resolve("transition.info"), "BAD");
        jwt.loadKeyVersion(good);
        assertEquals(good.getFileName().toString(), jwt.getActiveKeyId());
        jwt.close();
    }

    @Test
    void legacy_migration_and_private_helpers_should_cover_filename_algorithms_and_load_failures() throws Exception {
        EcdsaJwt jwt = new EcdsaJwt(properties, tempDir.resolve("legacy2"));
        jwt.keyRepository = null;

        assertEquals(Algorithm.ES384, invokeDetermineAlgorithm(jwt, "abc-es384"));
        assertEquals(Algorithm.ES512, invokeDetermineAlgorithm(jwt, "abc-es512"));
        assertEquals(Algorithm.ES256, invokeDetermineAlgorithm(jwt, "abc"));

        assertNull(invokeLoadKeyPairFromPaths(jwt, null, null));
        assertNull(invokeLoadKeyPairFromPaths(jwt, tempDir.resolve("x"), null));
        assertNull(invokeLoadKeyPairFromPaths(jwt, null, tempDir.resolve("y")));
        assertNull(invokeLoadKeyPairFromPaths(jwt, tempDir.resolve("missing-private.key"), tempDir.resolve("missing-public.key")));

        Path dir = Files.createDirectories(jwt.getKeyPath());
        Path priv = dir.resolve("bad-private.key");
        Path pub = dir.resolve("bad-public.key");
        Files.write(priv, new byte[]{1, 2, 3});
        Files.write(pub, new byte[]{1, 2, 3});
        assertNull(invokeLoadKeyPairFromPaths(jwt, priv, pub));

        Path missingPublic = dir.resolve("legacy-es384-private.key");
        Files.write(missingPublic, generateEc("secp384r1").getPrivate().getEncoded());
        invokeMigrateLegacy(jwt, missingPublic);

        Path pubOk = dir.resolve("legacy-es384-public.key");
        Files.write(pubOk, generateEc("secp384r1").getPublic().getEncoded());
        invokeMigrateLegacy(jwt, missingPublic);
        assertTrue(jwt.keyPairExists(Algorithm.ES384));

        Path failPriv = dir.resolve("legacy-es512-private.key");
        Path failPub = dir.resolve("legacy-es512-public.key");
        Files.write(failPriv, new byte[]{9});
        Files.write(failPub, new byte[]{9});
        invokeMigrateLegacy(jwt, failPriv);

        Path expectedPublic = dir.resolve("legacy-es512-public.key");
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.exists(eq(expectedPublic))).thenThrow(new RuntimeException("boom"));
            invokeMigrateLegacy(jwt, failPriv);
        }

        assertThrows(IllegalStateException.class, () -> invokeGetEcdsaSignAlgorithm(jwt, Algorithm.RSA256));
        assertThrows(IllegalArgumentException.class, () -> invokeGetAlgorithmConfig(jwt, Algorithm.RSA256));
        assertThrows(UnsupportedOperationException.class, () -> jwt.getSignAlgorithm(Algorithm.ES256));

        jwt.close();
    }

    @Test
    void verifyWithKeyVersion_should_cover_key_version_present_but_keypair_missing() throws Exception {
        EcdsaJwt jwt = new EcdsaJwt(properties, tempDir.resolve("vk-missing"));
        jwt.keyRepository = null;
        Files.createDirectories(jwt.getKeyPath());

        jwt.keyVersions.put("k", KeyVersion.builder()
                .keyId("k").algorithm(Algorithm.ES256).status(KeyStatus.ACTIVE).expiresAt(Instant.now().plusSeconds(60))
                .keyPath(jwt.getKeyPath().resolve("k").toString()).build());

        assertFalse(jwt.verifyWithKeyVersion("k", "a.b.c"));
        jwt.close();
    }

    @Test
    void autoLoadFirstKey_should_cover_predicate_false_and_null_tag_formatting() throws Exception {
        EcdsaJwt jwt = new EcdsaJwt(properties, tempDir.resolve("autoload-partial"));
        jwt.keyRepository = null;
        Files.createDirectories(jwt.getKeyPath());

        String partial1 = "ES256-v20240101-000000-nopriv";
        Path d1 = Files.createDirectories(jwt.getKeyPath().resolve(partial1));
        Files.write(d1.resolve("public.key"), generateEc("secp256r1").getPublic().getEncoded());

        String partial2 = "ES256-v20240101-000001-nopub";
        Path d2 = Files.createDirectories(jwt.getKeyPath().resolve(partial2));
        Files.write(d2.resolve("private.key"), generateEc("secp256r1").getPrivate().getEncoded());

        jwt.autoLoadFirstKey(Algorithm.ES256, null, false);
        assertNull(jwt.getActiveKeyId());

        jwt.autoLoadFirstKey(null, null, true);
        jwt.close();
    }

    @Test
    void loadKeyPairFromPaths_should_cover_exists_or_branches_and_read_failure_before_private_bytes() throws Exception {
        EcdsaJwt jwt = new EcdsaJwt(properties, tempDir.resolve("loadpaths"));
        Path dir = Files.createDirectories(jwt.getKeyPath());

        Path priv = dir.resolve("p.key");
        Files.write(priv, new byte[]{1, 2, 3});
        assertNull(invokeLoadKeyPairFromPaths(jwt, priv, dir.resolve("missing.key")));

        Path pub = dir.resolve("pub.key");
        Files.write(pub, new byte[]{1, 2, 3});
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.readAllBytes(eq(priv))).thenThrow(new IOException("io"));
            assertNull(invokeLoadKeyPairFromPaths(jwt, priv, pub));
        }

        jwt.close();
    }

    @Test
    void private_updateKeyVersionWithTransition_should_cover_exception_branch() {
        assertThrows(RuntimeException.class, () -> invokeUpdateKeyVersionWithTransition(ecdsaJwt, "k", Algorithm.ES256, null, 1));
    }

    @Test
    void getCurrentKey_and_getKeyByVersion_should_cover_branches() {
        assertNull(ecdsaJwt.getCurrentKey());
        assertNull(ecdsaJwt.getKeyByVersion("missing"));

        assertTrue(ecdsaJwt.generateKeyPair(Algorithm.ES256));
        String keyId = ecdsaJwt.getKeyVersions(Algorithm.ES256).get(0);
        ecdsaJwt.setActiveKey(keyId);

        assertNotNull(ecdsaJwt.getCurrentKey());
        assertNotNull(ecdsaJwt.getKeyByVersion(keyId));

        ecdsaJwt.activeKeyId = null;
        assertNull(ecdsaJwt.getCurrentKey());
    }

    @Test
    void autoLoadFirstKey_should_cover_hasKeyFiles_and_loadFirstKey_paths() {
        EcdsaJwt empty = new EcdsaJwt(properties, tempDir.resolve("autoload-empty"));
        empty.keyRepository = null;
        empty.autoLoadFirstKey(Algorithm.ES256, null, false);
        assertNull(empty.getActiveKeyId());
        empty.autoLoadFirstKey(Algorithm.ES256, null, true);
        empty.close();

        EcdsaJwt gen = new EcdsaJwt(properties, tempDir.resolve("autoload-present"));
        assertTrue(gen.generateKeyPair(Algorithm.ES256));
        String keyId = gen.getKeyVersions(Algorithm.ES256).get(0);
        gen.setActiveKey(keyId);
        gen.close();

        EcdsaJwt present = new EcdsaJwt(properties, tempDir.resolve("autoload-present"));
        present.keyRepository = null;
        present.autoLoadFirstKey(Algorithm.ES256, null, false);
        assertNotNull(present.getActiveKeyId());
        present.close();
    }

    @Test
    void loadKeyVersion_should_cover_catch_invalid_status_and_transition_success_and_null_dir_helper() throws Exception {
        EcdsaJwt jwt = new EcdsaJwt(properties, tempDir.resolve("loadKeyVersion2"));
        Path base = Files.createDirectories(jwt.getKeyPath());

        KeyPair ec = generateEc("secp256r1");
        Path d = Files.createDirectories(base.resolve("ES256-v20240101-000000-x"));
        Files.write(d.resolve("private.key"), ec.getPrivate().getEncoded());
        Files.write(d.resolve("public.key"), ec.getPublic().getEncoded());
        Files.writeString(d.resolve("status.info"), "BAD");
        Files.writeString(d.resolve("expiration.info"), Instant.now().plusSeconds(60).toString());
        Files.writeString(d.resolve("transition.info"), Instant.now().plusSeconds(60).toString());
        jwt.loadKeyVersion(d);
        KeyVersion v = jwt.keyVersions.get(d.getFileName().toString());
        assertNotNull(v);
        assertNotNull(v.getTransitionEndsAt());

        assertDoesNotThrow(() -> jwt.loadKeyVersion(Path.of("C:\\")));

        assertNull(invokeLoadKeyPairFromDir(jwt, null));
        jwt.close();
    }

    @Test
    void loadLegacyKeyPairs_should_cover_return_and_list_exception() throws Exception {
        EcdsaJwt jwt = new EcdsaJwt(properties, tempDir.resolve("legacy-scan"));
        jwt.keyRepository = null;

        jwt.currentKeyPath = null;
        invokeLoadLegacyKeyPairs(jwt);

        jwt.currentKeyPath = tempDir.resolve("legacy-scan").resolve("missing");
        invokeLoadLegacyKeyPairs(jwt);

        Path dir = Files.createDirectories(tempDir.resolve("legacy-scan").resolve("ec-keys"));
        jwt.currentKeyPath = dir;
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.list(eq(dir))).thenThrow(new IOException("io"));
            invokeLoadLegacyKeyPairs(jwt);
        }

        jwt.close();
    }

    @Test
    void loadFirstKeyFromDirectory_should_cover_tag_formatting_when_missing() {
        assertDoesNotThrow(() -> ecdsaJwt.loadFirstKeyFromDirectory("ES256"));
        assertNull(ecdsaJwt.getActiveKeyId());
    }

    private static KeyPair generateEc(String curve) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
        g.initialize(new java.security.spec.ECGenParameterSpec(curve));
        return g.generateKeyPair();
    }

    private static Algorithm invokeDetermineAlgorithm(EcdsaJwt jwt, String baseName) throws Exception {
        Method m = EcdsaJwt.class.getDeclaredMethod("determineAlgorithmFromFilename", String.class);
        m.setAccessible(true);
        return (Algorithm) m.invoke(jwt, baseName);
    }

    private static KeyPair invokeLoadKeyPairFromPaths(EcdsaJwt jwt, Path privateKeyPath, Path publicKeyPath) throws Exception {
        Method m = EcdsaJwt.class.getDeclaredMethod("loadKeyPairFromPaths", Path.class, Path.class);
        m.setAccessible(true);
        return (KeyPair) m.invoke(jwt, privateKeyPath, publicKeyPath);
    }

    private static void invokeMigrateLegacy(EcdsaJwt jwt, Path legacyPrivateKey) throws Exception {
        Method m = EcdsaJwt.class.getDeclaredMethod("migrateLegacyKeyPair", Path.class);
        m.setAccessible(true);
        m.invoke(jwt, legacyPrivateKey);
    }

    private static void invokeLoadLegacyKeyPairs(EcdsaJwt jwt) throws Exception {
        Method m = EcdsaJwt.class.getDeclaredMethod("loadLegacyKeyPairs");
        m.setAccessible(true);
        m.invoke(jwt);
    }

    private static void invokeUpdateKeyVersionWithTransition(EcdsaJwt jwt, String keyId, Algorithm algorithm, KeyPair keyPair, int transitionHours) throws Exception {
        Method m = EcdsaJwt.class.getDeclaredMethod("updateKeyVersionWithTransition", String.class, Algorithm.class, KeyPair.class, int.class);
        m.setAccessible(true);
        try {
            m.invoke(jwt, keyId, algorithm, keyPair, transitionHours);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static KeyPair invokeLoadKeyPairFromDir(EcdsaJwt jwt, Path dir) throws Exception {
        Method m = EcdsaJwt.class.getDeclaredMethod("loadKeyPairFromDir", Path.class);
        m.setAccessible(true);
        return (KeyPair) m.invoke(jwt, dir);
    }

    private static Object invokeGetEcdsaSignAlgorithm(EcdsaJwt jwt, Algorithm algorithm) {
        try {
            Method m = EcdsaJwt.class.getDeclaredMethod("getEcdsaSignAlgorithm", Algorithm.class);
            m.setAccessible(true);
            return m.invoke(jwt, algorithm);
        } catch (Exception e) {
            if (e instanceof java.lang.reflect.InvocationTargetException ite && ite.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw new RuntimeException(e);
        }
    }

    private static Object invokeGetAlgorithmConfig(EcdsaJwt jwt, Algorithm algorithm) {
        try {
            Method m = EcdsaJwt.class.getDeclaredMethod("getAlgorithmConfig", Algorithm.class);
            m.setAccessible(true);
            return m.invoke(jwt, algorithm);
        } catch (Exception e) {
            if (e instanceof java.lang.reflect.InvocationTargetException ite && ite.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw new RuntimeException(e);
        }
    }
}


