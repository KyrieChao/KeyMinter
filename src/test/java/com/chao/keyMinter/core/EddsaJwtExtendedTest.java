package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersion;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.jwk.Curve;
import com.nimbusds.jose.jwk.OctetKeyPair;
import com.nimbusds.jose.util.Base64URL;
import com.nimbusds.jwt.SignedJWT;
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
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.Provider;
import java.security.Security;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.List;
import java.util.Map;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class EddsaJwtExtendedTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    private EddsaJwt eddsaJwt;
    private AutoCloseable mocks;

    @BeforeEach
    void setUp() {
        KeyRotation.setLockProvider(null); // Ensure clean state
        mocks = MockitoAnnotations.openMocks(this);
        when(properties.getKeyValidityMillis()).thenReturn(3600000L);
        when(properties.getTransitionPeriodHours()).thenReturn(24);
        when(properties.isEnableRotation()).thenReturn(true);
        
        eddsaJwt = new EddsaJwt(properties, tempDir);
    }

    @AfterEach
    void tearDown() throws Exception {
        if (eddsaJwt != null) {
            eddsaJwt.close();
        }
        if (mocks != null) {
            mocks.close();
        }
    }

    @Test
    void testEd448Signing() {
        eddsaJwt.generateKeyPair(Algorithm.Ed448);
        List<String> keys = eddsaJwt.getKeyVersions(Algorithm.Ed448);
        String keyId = keys.get(0);
        eddsaJwt.setActiveKey(keyId);
        
        JwtProperties jwtProps = new JwtProperties("sub", "iss", Instant.now().plusSeconds(60));
        String token = eddsaJwt.generateJwt(jwtProps, null, Algorithm.Ed448);
        
        assertNotNull(token);
        assertTrue(eddsaJwt.verifyToken(token));
    }
    
    @Test
    void testGetCurveInfo() {
        eddsaJwt.generateKeyPair(Algorithm.Ed25519);
        List<String> keys = eddsaJwt.getKeyVersions(Algorithm.Ed25519);
        eddsaJwt.setActiveKey(keys.get(0));
        
        String info = eddsaJwt.getCurveInfo(Algorithm.Ed25519);
        assertTrue(info.contains("Ed25519"));
        
        // Ed448
        eddsaJwt.generateKeyPair(Algorithm.Ed448);
        List<String> keys448 = eddsaJwt.getKeyVersions(Algorithm.Ed448);
        eddsaJwt.setActiveKey(keys448.get(0));
        
        String info448 = eddsaJwt.getCurveInfo(Algorithm.Ed448);
        assertTrue(info448.contains("Ed448"));
    }
    
    @Test
    void testConstructors() throws Exception {
        EddsaJwt defaultJwt = new EddsaJwt();
        assertNotNull(defaultJwt);
        defaultJwt.close();

        EddsaJwt pathJwt = new EddsaJwt(tempDir);
        assertNotNull(pathJwt);
        pathJwt.close();

        EddsaJwt nullDirJwt = new EddsaJwt(properties, (Path) null);
        assertNotNull(nullDirJwt.getKeyPath());
        assertTrue(nullDirJwt.getKeyPath().endsWith("eddsa-keys"));
        nullDirJwt.close();

        Path base = Files.createDirectories(tempDir.resolve("eddsa-keys"));
        EddsaJwt exact = new EddsaJwt(properties, base);
        assertEquals(base.normalize(), exact.getKeyPath());
        exact.close();
    }
    
    @Test
    void testGenerateAllKeyPairs() {
        assertTrue(eddsaJwt.generateAllKeyPairs());
        assertTrue(eddsaJwt.getKeyVersions(Algorithm.Ed25519).size() > 0);
        assertTrue(eddsaJwt.getKeyVersions(Algorithm.Ed448).size() > 0);
    }
    
    @Test
    void testGetKeyInfo() {
        String info = eddsaJwt.getKeyInfo();
        assertTrue(info.contains("EdDSA Keys"));
    }
    
    @Test
    void testAlgorithmInfo() {
        String info = eddsaJwt.getAlgorithmInfo();
        assertTrue(info.contains("Ed25519"));
    }

    @Test
    void registerBouncyCastle_should_throw_on_security_failure() throws Exception {
        try (MockedStatic<Security> sec = Mockito.mockStatic(Security.class, Mockito.CALLS_REAL_METHODS)) {
            sec.when(() -> Security.getProvider(eq("BC"))).thenReturn(null);
            sec.when(() -> Security.addProvider(any(Provider.class))).thenThrow(new RuntimeException("boom"));
            assertThrows(RuntimeException.class, EddsaJwtExtendedTest::invokeRegisterBouncyCastle);
        }
    }

    @Test
    void registerBouncyCastle_should_noop_when_provider_present() throws Exception {
        try (MockedStatic<Security> sec = Mockito.mockStatic(Security.class, Mockito.CALLS_REAL_METHODS)) {
            sec.when(() -> Security.getProvider(eq("BC"))).thenReturn(mock(Provider.class));
            invokeRegisterBouncyCastle();
            sec.verify(() -> Security.addProvider(any(Provider.class)), never());
        }
    }

    @Test
    void ensureBouncyCastle_should_cover_second_call_noop() throws Exception {
        assertDoesNotThrow(EddsaJwtExtendedTest::invokeEnsureBouncyCastle);
        assertDoesNotThrow(EddsaJwtExtendedTest::invokeEnsureBouncyCastle);
    }

    @Test
    void ensureBouncyCastle_should_cover_double_check_false_branch_with_concurrency() throws Exception {
        setStaticField(EddsaJwt.class, "bcRegistered", false);
        try (MockedStatic<Security> sec = Mockito.mockStatic(Security.class, Mockito.CALLS_REAL_METHODS)) {
            sec.when(() -> Security.getProvider(eq("BC"))).thenReturn(mock(Provider.class));
            Runnable task = () -> {
                try {
                    invokeEnsureBouncyCastle();
                } catch (Exception e) {
                    throw new RuntimeException(e);
                }
            };
            Thread t1 = new Thread(task);
            Thread t2 = new Thread(task);
            t1.start();
            t2.start();
            t1.join();
            t2.join();
        }
    }

    @Test
    void hasKeyFilesInDirectory_and_loadFirstKeyFromDirectory_should_cover_branches() {
        assertFalse(eddsaJwt.hasKeyFilesInDirectory("Ed25519"));

        assertDoesNotThrow(() -> eddsaJwt.loadFirstKeyFromDirectory(null));
        assertDoesNotThrow(() -> eddsaJwt.loadFirstKeyFromDirectory("Ed25519"));

        eddsaJwt.generateKeyPair(Algorithm.Ed25519);
        assertTrue(eddsaJwt.hasKeyFilesInDirectory("Ed25519"));

        eddsaJwt.activeKeyId = null;
        eddsaJwt.loadFirstKeyFromDirectory("Ed25519");
        assertNotNull(eddsaJwt.getActiveKeyId());
    }

    @Test
    void loadExistingKeyVersions_should_cover_guards_and_list_exception_and_legacy() throws Exception {
        eddsaJwt.currentKeyPath = null;
        assertDoesNotThrow(eddsaJwt::loadExistingKeyVersions);

        eddsaJwt.currentKeyPath = tempDir.resolve("missing");
        assertDoesNotThrow(eddsaJwt::loadExistingKeyVersions);

        Path file = tempDir.resolve("not-dir");
        Files.writeString(file, "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        eddsaJwt.currentKeyPath = file;
        assertDoesNotThrow(eddsaJwt::loadExistingKeyVersions);

        Path dir = Files.createDirectories(tempDir.resolve("scan").resolve("eddsa-keys"));
        eddsaJwt.currentKeyPath = dir;
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.list(eq(dir))).thenThrow(new IOException("io"));
            assertDoesNotThrow(eddsaJwt::loadExistingKeyVersions);
        }

        EddsaJwt legacy = new EddsaJwt(properties, tempDir.resolve("legacy"));
        Path legacyDir = legacy.getKeyPath();
        Files.createDirectories(legacyDir);
        OctetKeyPair okp = generateEd25519Key("legacy");
        Files.writeString(legacyDir.resolve("legacy.private.key"), okp.toJSONString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        legacy.loadExistingKeyVersions();
        assertNotNull(legacy.getActiveKeyId());
        legacy.close();
    }

    @Test
    void constructors_should_cover_active_key_already_present() {
        EddsaJwt gen = new EddsaJwt(properties, tempDir.resolve("ctor-active"));
        assertTrue(gen.generateKeyPair(Algorithm.Ed25519));
        String keyId = gen.getKeyVersions(Algorithm.Ed25519).get(0);
        gen.setActiveKey(keyId);
        gen.close();

        EddsaJwt loaded = new EddsaJwt(properties, tempDir.resolve("ctor-active"));
        assertNotNull(loaded.getActiveKeyId());
        loaded.close();
    }

    @Test
    void isKeyVersionDir_should_cover_all_detection_clauses() throws Exception {
        assertFalse(eddsaJwt.isKeyVersionDir(null));

        Path base = Files.createDirectories(tempDir.resolve("isKey").resolve("eddsa-keys"));
        Path d1 = Files.createDirectories(base.resolve("ed-v1"));
        assertTrue(eddsaJwt.isKeyVersionDir(d1));

        Path d1a = Files.createDirectories(base.resolve("ed1"));
        assertFalse(eddsaJwt.isKeyVersionDir(d1a));

        Path d1b = Files.createDirectories(base.resolve("x-v"));
        assertFalse(eddsaJwt.isKeyVersionDir(d1b));

        Path d2 = Files.createDirectories(base.resolve("x"));
        Files.writeString(d2.resolve("key.jwk"), "{}", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        assertTrue(eddsaJwt.isKeyVersionDir(d2));

        Path d3 = Files.createDirectories(base.resolve("y"));
        Files.writeString(d3.resolve("algorithm.info"), "Ed25519", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        assertTrue(eddsaJwt.isKeyVersionDir(d3));

        Path d4 = Files.createDirectories(base.resolve("z"));
        assertFalse(eddsaJwt.isKeyVersionDir(d4));
    }

    @Test
    void rotateKeyWithTransition_should_cover_disabled_and_ioexception_and_transition_hours_branches() throws Exception {
        when(properties.isEnableRotation()).thenReturn(false);
        EddsaJwt disabled = new EddsaJwt(properties, tempDir.resolve("disabled"));
        assertFalse(disabled.rotateKeyWithTransition(Algorithm.Ed25519, "k", 1));
        disabled.close();

        when(properties.isEnableRotation()).thenReturn(true);
        try (MockedStatic<KeyRotation> mocked = Mockito.mockStatic(KeyRotation.class)) {
            mocked.when(() -> KeyRotation.rotateKeyAtomic(anyString(), any(), any(), any(), any())).thenThrow(new IOException("io"));
            assertThrows(UncheckedIOException.class, () -> eddsaJwt.rotateKeyWithTransition(Algorithm.Ed25519, "k2", 1));
        }

        assertTrue(eddsaJwt.rotateKeyWithTransition(Algorithm.Ed25519, eddsaJwt.generateKeyVersionId(Algorithm.Ed25519), 0));
    }

    @Test
    void updateKeyVersionWithTransition_should_throw_when_key_pair_null() {
        assertThrows(RuntimeException.class, () -> invokeUpdateKeyVersionWithTransition(eddsaJwt, "k", Algorithm.Ed25519, null, 1));
    }

    @Test
    void loadKeyPair_should_cover_hit_reload_and_missing() {
        assertTrue(eddsaJwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = eddsaJwt.getKeyVersions(Algorithm.Ed25519).get(0);

        assertDoesNotThrow(() -> eddsaJwt.loadKeyPair(keyId));
        assertDoesNotThrow(() -> eddsaJwt.loadKeyPair(keyId));

        eddsaJwt.getVersionKeyPairs().remove(keyId);
        assertDoesNotThrow(() -> eddsaJwt.loadKeyPair(keyId));

        assertThrows(IllegalArgumentException.class, () -> eddsaJwt.loadKeyPair("missing"));
    }

    @Test
    void verifyToken_should_cover_active_path_loop_path_and_parse_failure() throws Exception {
        EddsaJwt jwt = new EddsaJwt(properties, tempDir.resolve("verify"));
        assertTrue(jwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = jwt.getKeyVersions(Algorithm.Ed25519).get(0);
        jwt.setActiveKey(keyId);

        JwtProperties props = new JwtProperties("sub", "iss", Instant.now().plusSeconds(60));
        String token = jwt.generateToken(props, Map.of("role", "r"), Algorithm.Ed25519);
        assertTrue(jwt.verifyToken(token));

        jwt.getVersionKeyPairs().clear();
        jwt.activeKeyId = keyId;
        assertTrue(jwt.verifyToken(token));

        jwt.activeKeyId = null;
        jwt.getVersionKeyPairs().clear();
        jwt.keyVersions.put(keyId, new KeyVersion(keyId, Algorithm.Ed25519, jwt.getKeyPath().resolve(keyId).toString()));
        assertTrue(jwt.verifyToken(token));

        EddsaJwt other = new EddsaJwt(properties, tempDir.resolve("verify-other"));
        assertTrue(other.generateKeyPair(Algorithm.Ed25519));
        other.setActiveKey(other.getKeyVersions(Algorithm.Ed25519).get(0));
        String tokenOther = other.generateToken(props, Map.of(), Algorithm.Ed25519);
        assertFalse(jwt.verifyToken(tokenOther));
        other.close();

        jwt.activeKeyId = null;
        jwt.getVersionKeyPairs().clear();
        jwt.currentKeyPath = null;
        assertFalse(jwt.verifyToken(token));

        assertFalse(jwt.verifyToken("not-a-jwt"));
        jwt.close();
    }

    @Test
    void verifyToken_should_cover_kp_null_branch_in_loop() throws Exception {
        EddsaJwt signer = new EddsaJwt(properties, tempDir.resolve("signer"));
        signer.generateKeyPair(Algorithm.Ed25519);
        signer.setActiveKey(signer.getKeyVersions(Algorithm.Ed25519).get(0));
        String token = signer.generateToken(new JwtProperties("s", "i", Instant.now().plusSeconds(60)), Map.of(), Algorithm.Ed25519);
        signer.close();

        EddsaJwt verifier = new EddsaJwt(properties, tempDir.resolve("verifier"));
        verifier.activeKeyId = null;
        verifier.getVersionKeyPairs().clear();
        verifier.keyVersions.put("missing", new KeyVersion("missing", Algorithm.Ed25519, verifier.getKeyPath().resolve("missing").toString()));
        Files.createDirectories(verifier.getKeyPath().resolve("missing"));
        assertFalse(verifier.verifyToken(token));
        verifier.close();
    }

    @Test
    void verifyWithKeyVersion_should_cover_blanks_status_block_missing_keypair_and_parse_failures() throws Exception {
        assertFalse(eddsaJwt.verifyWithKeyVersion(null, "t"));
        assertFalse(eddsaJwt.verifyWithKeyVersion("k", null));

        assertTrue(eddsaJwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = eddsaJwt.getKeyVersions(Algorithm.Ed25519).get(0);
        eddsaJwt.setActiveKey(keyId);

        JwtProperties props = new JwtProperties("sub", "iss", Instant.now().plusSeconds(60));
        String token = eddsaJwt.generateToken(props, Map.of(), Algorithm.Ed25519);

        eddsaJwt.keyVersions.get(keyId).setStatus(KeyStatus.REVOKED);
        assertFalse(eddsaJwt.verifyWithKeyVersion(keyId, token));
        eddsaJwt.keyVersions.get(keyId).setStatus(KeyStatus.ACTIVE);

        eddsaJwt.getVersionKeyPairs().remove(keyId);
        assertTrue(eddsaJwt.verifyWithKeyVersion(keyId, token));

        assertFalse(eddsaJwt.verifyWithKeyVersion("missing", token));
        assertFalse(eddsaJwt.verifyWithKeyVersion(keyId, "not-a-jwt"));

        eddsaJwt.getVersionKeyPairs().remove(keyId);
        eddsaJwt.currentKeyPath = null;
        assertFalse(eddsaJwt.verifyWithKeyVersion(keyId, token));
    }

    @Test
    void verifyWithKeyVersion_should_return_false_when_version_exists_but_keypair_missing() throws Exception {
        EddsaJwt jwt = new EddsaJwt(properties, tempDir.resolve("vk-missing"));
        jwt.keyRepository = null;
        Files.createDirectories(jwt.getKeyPath());

        KeyVersion v = new KeyVersion("k", Algorithm.Ed25519, jwt.getKeyPath().resolve("k").toString());
        v.setStatus(KeyStatus.ACTIVE);
        v.setExpiresAt(Instant.now().plusSeconds(60));
        jwt.keyVersions.put("k", v);

        assertFalse(jwt.verifyWithKeyVersion("k", "a.b.c"));
        jwt.close();
    }

    @Test
    void verifyWithKey_should_cover_unsupported_curve_and_catch_paths() throws Exception {
        OctetKeyPair x25519 = new OctetKeyPair.Builder(Curve.X25519, Base64URL.encode(new byte[32]))
                .d(Base64URL.encode(new byte[32]))
                .keyID("x")
                .build();

        assertTrue(eddsaJwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = eddsaJwt.getKeyVersions(Algorithm.Ed25519).get(0);
        eddsaJwt.setActiveKey(keyId);
        SignedJWT jwt = SignedJWT.parse(eddsaJwt.generateToken(new JwtProperties("s", "i", Instant.now().plusSeconds(60)), Map.of(), Algorithm.Ed25519));
        assertFalse(invokeVerifyWithKey(eddsaJwt, x25519, jwt));
        assertFalse(invokeVerifyWithKey(eddsaJwt, x25519, null));
        assertFalse(invokeVerifyWithKey(eddsaJwt, null, jwt));
    }

    @Test
    void verifyEd25519_and_verifyEd448_should_cover_invalid_lengths_and_exception_branches() throws Exception {
        assertTrue(eddsaJwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = eddsaJwt.getKeyVersions(Algorithm.Ed25519).get(0);
        eddsaJwt.setActiveKey(keyId);
        SignedJWT jwt = SignedJWT.parse(eddsaJwt.generateToken(new JwtProperties("s", "i", Instant.now().plusSeconds(60)), Map.of(), Algorithm.Ed25519));

        OctetKeyPair ed25519BadX = new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(new byte[1]))
                .d(Base64URL.encode(new byte[32]))
                .keyID("k")
                .build();
        assertThrows(IllegalArgumentException.class, () -> invokeVerifyEd25519(eddsaJwt, ed25519BadX, jwt));

        OctetKeyPair ed448BadX = new OctetKeyPair.Builder(Curve.Ed448, Base64URL.encode(new byte[1]))
                .d(Base64URL.encode(new byte[57]))
                .keyID("k2")
                .build();
        assertFalse(invokeVerifyEd448(eddsaJwt, ed448BadX, jwt));

        OctetKeyPair ed448GoodX = new OctetKeyPair.Builder(Curve.Ed448, Base64URL.encode(new byte[57]))
                .d(Base64URL.encode(new byte[57]))
                .keyID("k3")
                .build();
        assertFalse(invokeVerifyEd448(eddsaJwt, ed448GoodX, null));

        OctetKeyPair mockEd25519 = mock(OctetKeyPair.class);
        when(mockEd25519.getDecodedX()).thenReturn(null);
        assertThrows(IllegalArgumentException.class, () -> invokeVerifyEd25519(eddsaJwt, mockEd25519, jwt));

        OctetKeyPair mockEd448 = mock(OctetKeyPair.class);
        when(mockEd448.getDecodedX()).thenReturn(null);
        assertFalse(invokeVerifyEd448(eddsaJwt, mockEd448, jwt));
    }

    @Test
    void generateJwt_should_cover_missing_active_missing_keypair_unsupported_curve_and_success() throws Exception {
        JwtProperties p = new JwtProperties("s", "i", Instant.now().plusSeconds(60));

        assertThrows(IllegalStateException.class, () -> eddsaJwt.generateJwt(p, Map.of(), Algorithm.Ed25519));

        assertTrue(eddsaJwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = eddsaJwt.getKeyVersions(Algorithm.Ed25519).get(0);
        eddsaJwt.setActiveKey(keyId);
        assertNotNull(eddsaJwt.generateJwt(p, null, Algorithm.Ed25519));

        eddsaJwt.getVersionKeyPairs().remove(keyId);
        assertThrows(IllegalStateException.class, () -> eddsaJwt.generateJwt(p, Map.of(), Algorithm.Ed25519));
        eddsaJwt.loadKeyPair(keyId);

        OctetKeyPair x25519 = new OctetKeyPair.Builder(Curve.X25519, Base64URL.encode(new byte[32]))
                .d(Base64URL.encode(new byte[32]))
                .keyID("x")
                .build();
        eddsaJwt.activeKeyId = "x";
        eddsaJwt.getVersionKeyPairs().put("x", x25519);
        assertThrows(RuntimeException.class, () -> eddsaJwt.generateJwt(p, Map.of(), Algorithm.Ed25519));
    }

    @Test
    void decodePayload_should_cover_blank_success_and_invalid_token() {
        assertThrows(IllegalArgumentException.class, () -> eddsaJwt.decodePayload(""));
        assertThrows(RuntimeException.class, () -> eddsaJwt.decodePayload("not-a-jwt"));

        assertTrue(eddsaJwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = eddsaJwt.getKeyVersions(Algorithm.Ed25519).get(0);
        eddsaJwt.setActiveKey(keyId);
        String token = eddsaJwt.generateToken(new JwtProperties("sub", "iss", Instant.now().plusSeconds(60)), Map.of("k", "v"), Algorithm.Ed25519);
        assertEquals("sub", eddsaJwt.decodePayload(token).getSubject());
    }

    @Test
    void decodePayload_should_cover_jti_branch() {
        assertTrue(eddsaJwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = eddsaJwt.getKeyVersions(Algorithm.Ed25519).get(0);
        eddsaJwt.setActiveKey(keyId);

        String token = eddsaJwt.generateToken(new JwtProperties("sub", "iss", Instant.now().plusSeconds(60)), Map.of("jti", "id-1"), Algorithm.Ed25519);
        assertEquals("id-1", eddsaJwt.decodePayload(token).getId());
    }

    @Test
    void getKeyInfo_getAlgorithmInfo_getSignAlgorithm_and_close_should_cover_cleanup() {
        assertTrue(eddsaJwt.getKeyInfo().contains("Active: None"));
        assertTrue(eddsaJwt.getAlgorithmInfo().contains("Ed25519"));
        assertThrows(UnsupportedOperationException.class, () -> eddsaJwt.getSignAlgorithm(Algorithm.Ed25519));

        when(properties.isEnableRotation()).thenReturn(false);
        EddsaJwt disabled = new EddsaJwt(properties, tempDir.resolve("info"));
        assertTrue(disabled.getKeyInfo().contains("disabled"));
        disabled.close();
    }

    @Test
    void getKeyInfo_should_cover_active_present_branch() {
        assertTrue(eddsaJwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = eddsaJwt.getKeyVersions(Algorithm.Ed25519).get(0);
        eddsaJwt.setActiveKey(keyId);
        assertTrue(eddsaJwt.getKeyInfo().contains(keyId));
    }

    @Test
    void getCurrentKey_and_getKeyByVersion_should_cover_branches() {
        assertNull(eddsaJwt.getCurrentKey());
        assertNull(eddsaJwt.getKeyByVersion("missing"));

        assertTrue(eddsaJwt.generateKeyPair(Algorithm.Ed25519));
        String keyId = eddsaJwt.getKeyVersions(Algorithm.Ed25519).get(0);
        eddsaJwt.setActiveKey(keyId);
        assertNotNull(eddsaJwt.getCurrentKey());
        assertNotNull(eddsaJwt.getKeyByVersion(keyId));
    }

    @Test
    void generateAllKeyPairs_should_cover_failure_branch() {
        EddsaJwt spy = spy(new EddsaJwt(properties, tempDir.resolve("all")));
        doReturn(true).when(spy).rotateKey(eq(Algorithm.Ed25519), anyString());
        doReturn(false).when(spy).rotateKey(eq(Algorithm.Ed448), anyString());
        assertFalse(spy.generateAllKeyPairs());
        spy.close();
    }

    @Test
    void loadKeyVersion_and_readers_should_cover_missing_invalid_expired_active_and_transition() throws Exception {
        EddsaJwt jwt = new EddsaJwt(properties, tempDir.resolve("load"));
        Path base = Files.createDirectories(jwt.getKeyPath());

        assertDoesNotThrow(() -> jwt.loadKeyVersion(null));

        Path missing = Files.createDirectories(base.resolve("ed-v-missing"));
        Files.writeString(missing.resolve("status.info"), "ACTIVE", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        jwt.loadKeyVersion(missing);

        Path expired = Files.createDirectories(base.resolve("ed-v-expired"));
        OctetKeyPair okp = generateEd25519Key("expired");
        Files.writeString(expired.resolve("key.jwk"), okp.toJSONString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(expired.resolve("expiration.info"), Instant.now().minus(1, ChronoUnit.DAYS).toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        jwt.loadKeyVersion(expired);

        Path active = Files.createDirectories(base.resolve("ed-v-active"));
        Files.writeString(active.resolve("key.jwk"), okp.toJSONString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(active.resolve("status.info"), "ACTIVE", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(active.resolve("expiration.info"), "BAD", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(active.resolve("transition.info"), "BAD", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(active.resolve("algorithm.info"), "BAD", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        jwt.loadKeyVersion(active);
        assertEquals(active.getFileName().toString(), jwt.getActiveKeyId());

        Path created = Files.createDirectories(base.resolve("ed-v-created"));
        Files.writeString(created.resolve("key.jwk"), okp.toJSONString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(created.resolve("status.info"), "CREATED", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        jwt.loadKeyVersion(created);

        Path transitionOk = Files.createDirectories(base.resolve("ed-v-transition"));
        Files.writeString(transitionOk.resolve("key.jwk"), okp.toJSONString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(transitionOk.resolve("status.info"), "TRANSITIONING", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(transitionOk.resolve("expiration.info"), Instant.now().plusSeconds(60).toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(transitionOk.resolve("transition.info"), Instant.now().plusSeconds(60).toString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        jwt.loadKeyVersion(transitionOk);
        assertNotNull(jwt.keyVersions.get(transitionOk.getFileName().toString()).getTransitionEndsAt());

        Path badJwk = Files.createDirectories(base.resolve("ed-v-badjwk"));
        Files.writeString(badJwk.resolve("key.jwk"), "{", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        jwt.loadKeyVersion(badJwk);

        Path statusEx = Files.createDirectories(base.resolve("ed-v-status-ex"));
        Files.writeString(statusEx.resolve("key.jwk"), okp.toJSONString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Path statusFile = statusEx.resolve("status.info");
        Files.writeString(statusFile, "ACTIVE", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.readString(eq(statusFile), eq(StandardCharsets.UTF_8))).thenThrow(new IOException("io"));
            jwt.loadKeyVersion(statusEx);
        }

        assertDoesNotThrow(() -> jwt.loadKeyVersion(Path.of("C:\\")));

        jwt.close();
    }

    @Test
    void loadKeyPairFromDir_and_getAlgorithmFromDir_should_cover_null_missing_invalid_and_valid() throws Exception {
        assertNull(invokeLoadKeyPairFromDir(eddsaJwt, null));
        assertEquals(Algorithm.Ed25519, invokeGetAlgorithmFromDir(eddsaJwt, tempDir.resolve("missing")));

        Path dir = Files.createDirectories(tempDir.resolve("dir").resolve("eddsa-keys").resolve("ed-v1"));
        assertNull(invokeLoadKeyPairFromDir(eddsaJwt, dir));

        Files.writeString(dir.resolve("key.jwk"), "{", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        assertNull(invokeLoadKeyPairFromDir(eddsaJwt, dir));

        OctetKeyPair okp = generateEd25519Key("k");
        Files.writeString(dir.resolve("key.jwk"), okp.toJSONString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        assertNotNull(invokeLoadKeyPairFromDir(eddsaJwt, dir));

        Files.writeString(dir.resolve("algorithm.info"), "BAD", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        assertEquals(Algorithm.Ed25519, invokeGetAlgorithmFromDir(eddsaJwt, dir));

        Files.writeString(dir.resolve("algorithm.info"), "Ed448", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        assertEquals(Algorithm.Ed448, invokeGetAlgorithmFromDir(eddsaJwt, dir));
    }

    @Test
    void loadLegacyKeyPairs_should_cover_guard_scan_and_failure() throws Exception {
        EddsaJwt jwt = new EddsaJwt(properties, tempDir.resolve("legacy2"));
        jwt.currentKeyPath = null;
        assertDoesNotThrow(() -> invokeLoadLegacyKeyPairs(jwt));

        jwt.currentKeyPath = tempDir.resolve("legacy2").resolve("missing");
        assertDoesNotThrow(() -> invokeLoadLegacyKeyPairs(jwt));

        Path dir = Files.createDirectories(tempDir.resolve("legacy2").resolve("eddsa-keys"));
        jwt.currentKeyPath = dir;
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.list(eq(dir))).thenThrow(new IOException("io"));
            assertDoesNotThrow(() -> invokeLoadLegacyKeyPairs(jwt));
        }

        Files.writeString(dir.resolve("empty.private.key"), " ", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Files.writeString(dir.resolve("bad.private.key"), "{", StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        OctetKeyPair okp = generateEd448Key("legacy-ed448");
        Files.writeString(dir.resolve("good.private.key"), okp.toJSONString(), StandardCharsets.UTF_8, StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        invokeLoadLegacyKeyPairs(jwt);
        assertNotNull(jwt.getActiveKeyId());
        jwt.close();
    }

    @Test
    void determineAlgorithmFromJwk_should_cover_all_branches() throws Exception {
        OctetKeyPair ed25519 = generateEd25519Key("k1");
        OctetKeyPair ed448 = generateEd448Key("k2");
        OctetKeyPair x25519 = new OctetKeyPair.Builder(Curve.X25519, Base64URL.encode(new byte[32])).d(Base64URL.encode(new byte[32])).keyID("k3").build();

        assertEquals(Algorithm.Ed25519, invokeDetermineAlgorithmFromJwk(eddsaJwt, ed25519));
        assertEquals(Algorithm.Ed448, invokeDetermineAlgorithmFromJwk(eddsaJwt, ed448));
        assertEquals(Algorithm.Ed25519, invokeDetermineAlgorithmFromJwk(eddsaJwt, x25519));
    }

    @Test
    void custom_signers_should_cover_d_null_short_trim_and_interfaces() throws Exception {
        OctetKeyPair base25519 = generateEd25519Key("k");
        byte[] d32 = base25519.getDecodedD();
        byte[] d64 = new byte[64];
        System.arraycopy(d32, 0, d64, 0, 32);

        OctetKeyPair longD = new OctetKeyPair.Builder(Curve.Ed25519, base25519.getX())
                .d(Base64URL.encode(d64))
                .keyID("k")
                .build();

        JWSSigner signer = invokeCreateEd25519Signer(eddsaJwt, longD);
        assertEquals(Set.of(JWSAlgorithm.EdDSA), signer.supportedJWSAlgorithms());
        assertNotNull(signer.getJCAContext());

        SignedJWT jwt = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k").build(), invokeBuildClaimsSet(eddsaJwt, new JwtProperties("s", "i", Instant.now().plusSeconds(60)), Map.of()));
        jwt.sign(signer);
        assertNotNull(jwt.serialize());

        OctetKeyPair noD = new OctetKeyPair.Builder(Curve.Ed25519, base25519.getX()).keyID("k").build();
        JWSSigner signerNoD = invokeCreateEd25519Signer(eddsaJwt, noD);
        assertThrows(JOSEException.class, () -> signerNoD.sign(jwt.getHeader(), jwt.getSigningInput()));

        OctetKeyPair shortD = new OctetKeyPair.Builder(Curve.Ed25519, base25519.getX())
                .d(Base64URL.encode(new byte[1]))
                .keyID("k")
                .build();
        JWSSigner signerShort = invokeCreateEd25519Signer(eddsaJwt, shortD);
        assertThrows(JOSEException.class, () -> signerShort.sign(jwt.getHeader(), jwt.getSigningInput()));

        OctetKeyPair base448 = generateEd448Key("k448");
        byte[] d57 = base448.getDecodedD();
        byte[] d60 = new byte[60];
        System.arraycopy(d57, 0, d60, 0, 57);
        OctetKeyPair longD448 = new OctetKeyPair.Builder(Curve.Ed448, base448.getX())
                .d(Base64URL.encode(d60))
                .keyID("k448")
                .build();
        JWSSigner signer448 = invokeCreateEd448Signer(eddsaJwt, longD448);
        assertEquals(Set.of(JWSAlgorithm.EdDSA), signer448.supportedJWSAlgorithms());
        assertNotNull(signer448.getJCAContext());

        SignedJWT jwt448 = new SignedJWT(new JWSHeader.Builder(JWSAlgorithm.EdDSA).keyID("k448").build(), invokeBuildClaimsSet(eddsaJwt, new JwtProperties("s", "i", Instant.now().plusSeconds(60)), Map.of()));
        jwt448.sign(signer448);

        OctetKeyPair noD448 = new OctetKeyPair.Builder(Curve.Ed448, base448.getX()).keyID("k448").build();
        assertThrows(JOSEException.class, () -> invokeCreateEd448Signer(eddsaJwt, noD448).sign(jwt448.getHeader(), jwt448.getSigningInput()));

        OctetKeyPair shortD448 = new OctetKeyPair.Builder(Curve.Ed448, base448.getX()).d(Base64URL.encode(new byte[1])).keyID("k448").build();
        assertThrows(JOSEException.class, () -> invokeCreateEd448Signer(eddsaJwt, shortD448).sign(jwt448.getHeader(), jwt448.getSigningInput()));
    }

    @Test
    void algorithm_config_should_throw_for_unsupported_algorithm() {
        assertThrows(IllegalArgumentException.class, () -> eddsaJwt.getCurveInfo(Algorithm.RSA256));
    }

    @Test
    void private_getAlgorithmConfig_should_throw_for_unsupported() {
        assertThrows(IllegalArgumentException.class, () -> invokeGetAlgorithmConfig(eddsaJwt, Algorithm.RSA256));
    }

    private static OctetKeyPair generateEd25519Key(String kid) {
        org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator kpg = new org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator();
        kpg.init(new org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters(new java.security.SecureRandom()));
        org.bouncycastle.crypto.AsymmetricCipherKeyPair bcKP = kpg.generateKeyPair();
        byte[] d = ((org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters) bcKP.getPrivate()).getEncoded();
        byte[] x = ((org.bouncycastle.crypto.params.Ed25519PublicKeyParameters) bcKP.getPublic()).getEncoded();
        return new OctetKeyPair.Builder(Curve.Ed25519, Base64URL.encode(x))
                .d(Base64URL.encode(d))
                .keyID(kid)
                .algorithm(JWSAlgorithm.EdDSA)
                .keyUse(com.nimbusds.jose.jwk.KeyUse.SIGNATURE)
                .build();
    }

    private static OctetKeyPair generateEd448Key(String kid) throws Exception {
        byte[] x = new byte[57];
        byte[] d = new byte[57];
        new java.security.SecureRandom().nextBytes(x);
        new java.security.SecureRandom().nextBytes(d);
        return new OctetKeyPair.Builder(Curve.Ed448, Base64URL.encode(x)).d(Base64URL.encode(d)).keyID(kid).build();
    }

    private static void invokeRegisterBouncyCastle() throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("registerBouncyCastle");
        m.setAccessible(true);
        try {
            m.invoke(null);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeEnsureBouncyCastle() throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("ensureBouncyCastle");
        m.setAccessible(true);
        m.invoke(null);
    }

    private static void setStaticField(Class<?> cls, String fieldName, Object value) {
        try {
            Field f = cls.getDeclaredField(fieldName);
            f.setAccessible(true);
            f.set(null, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void invokeLoadLegacyKeyPairs(EddsaJwt jwt) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("loadLegacyKeyPairs");
        m.setAccessible(true);
        m.invoke(jwt);
    }

    private static void invokeUpdateKeyVersionWithTransition(EddsaJwt jwt, String keyId, Algorithm algorithm, OctetKeyPair keyPair, int hours) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("updateKeyVersionWithTransition", String.class, Algorithm.class, OctetKeyPair.class, int.class);
        m.setAccessible(true);
        try {
            m.invoke(jwt, keyId, algorithm, keyPair, hours);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static boolean invokeVerifyWithKey(EddsaJwt jwt, OctetKeyPair keyPair, SignedJWT signedJWT) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("verifyWithKey", OctetKeyPair.class, SignedJWT.class);
        m.setAccessible(true);
        try {
            return (boolean) m.invoke(jwt, keyPair, signedJWT);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static boolean invokeVerifyEd25519(EddsaJwt jwt, OctetKeyPair keyPair, SignedJWT signedJWT) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("verifyEd25519", OctetKeyPair.class, SignedJWT.class);
        m.setAccessible(true);
        try {
            return (boolean) m.invoke(jwt, keyPair, signedJWT);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static boolean invokeVerifyEd448(EddsaJwt jwt, OctetKeyPair keyPair, SignedJWT signedJWT) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("verifyEd448", OctetKeyPair.class, SignedJWT.class);
        m.setAccessible(true);
        try {
            return (boolean) m.invoke(jwt, keyPair, signedJWT);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static OctetKeyPair invokeLoadKeyPairFromDir(EddsaJwt jwt, Path dir) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("loadKeyPairFromDir", Path.class);
        m.setAccessible(true);
        return (OctetKeyPair) m.invoke(jwt, dir);
    }

    private static Algorithm invokeGetAlgorithmFromDir(EddsaJwt jwt, Path dir) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("getAlgorithmFromDir", Path.class);
        m.setAccessible(true);
        return (Algorithm) m.invoke(jwt, dir);
    }

    private static Algorithm invokeDetermineAlgorithmFromJwk(EddsaJwt jwt, OctetKeyPair keyPair) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("determineAlgorithmFromJWK", OctetKeyPair.class);
        m.setAccessible(true);
        return (Algorithm) m.invoke(jwt, keyPair);
    }

    private static Object invokeGetAlgorithmConfig(EddsaJwt jwt, Algorithm algorithm) {
        try {
            Method m = EddsaJwt.class.getDeclaredMethod("getAlgorithmConfig", Algorithm.class);
            m.setAccessible(true);
            return m.invoke(jwt, algorithm);
        } catch (Exception e) {
            if (e instanceof java.lang.reflect.InvocationTargetException ite && ite.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw new RuntimeException(e);
        }
    }

    private static JWSSigner invokeCreateEd25519Signer(EddsaJwt jwt, OctetKeyPair keyPair) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("createEd25519Signer", OctetKeyPair.class);
        m.setAccessible(true);
        return (JWSSigner) m.invoke(jwt, keyPair);
    }

    private static JWSSigner invokeCreateEd448Signer(EddsaJwt jwt, OctetKeyPair keyPair) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("createEd448Signer", OctetKeyPair.class);
        m.setAccessible(true);
        return (JWSSigner) m.invoke(jwt, keyPair);
    }

    private static com.nimbusds.jwt.JWTClaimsSet invokeBuildClaimsSet(EddsaJwt jwt, JwtProperties properties, Map<String, Object> claims) throws Exception {
        Method m = EddsaJwt.class.getDeclaredMethod("buildClaimsSet", JwtProperties.class, Map.class);
        m.setAccessible(true);
        return (com.nimbusds.jwt.JWTClaimsSet) m.invoke(jwt, properties, claims);
    }
}


