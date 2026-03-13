package com.chao.keyMinter.domain.service;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.core.Prep;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import com.chao.keyMinter.domain.model.KeyStatus;
import com.chao.keyMinter.domain.model.KeyVersion;
import io.jsonwebtoken.Claims;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mockito;

import java.nio.file.Path;
import java.time.Instant;
import java.time.LocalDateTime;
import java.util.List;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtAlgoTest {

    @Test
    void default_methods_should_throw_or_return_defaults_as_documented() {
        // Arrange
        JwtAlgo algo = new TestAlgo(List.of());

        // Act & Assert
        assertThrows(UnsupportedOperationException.class, () -> algo.generateKeyPair(Algorithm.HMAC256));
        assertFalse(algo.generateHmacKey(Algorithm.HMAC256, 64));
        assertThrows(UnsupportedOperationException.class, algo::generateAllKeyPairs);
        assertThrows(UnsupportedOperationException.class, () -> algo.rotateKey(Algorithm.HMAC256, "x"));
        assertThrows(UnsupportedOperationException.class, () -> algo.rotateHmacKey(Algorithm.HMAC256, "x", 64));
        assertThrows(UnsupportedOperationException.class, algo::getKeyVersions);
        assertThrows(UnsupportedOperationException.class, () -> algo.getKeyVersions(Algorithm.HMAC256));
        assertThrows(UnsupportedOperationException.class, () -> algo.setActiveKey("k1"));
        assertThrows(UnsupportedOperationException.class, algo::getActiveKeyId);
        assertThrows(UnsupportedOperationException.class, () -> algo.keyPairExists(Algorithm.HMAC256));
        assertThrows(UnsupportedOperationException.class, algo::keyPairExists);
        assertNotNull(algo.getDefaultSecretDir());
        assertNull(algo.getDirTimestamp(Path.of("any")));
        assertFalse(algo.verifyWithKeyVersion("k1", "t"));
        assertSame(algo, algo.withKeyDirectory(Path.of("any")));
        assertSame(algo, algo.withKeyDirectory("any"));
        assertSame(algo, algo.withKeyDirectory((String) null));
        assertNull(algo.getCurrentKey());
        assertNull(algo.getKeyByVersion("k1"));
        assertThrows(UnsupportedOperationException.class, algo::getAlgorithmInfo);
        assertThrows(UnsupportedOperationException.class, () -> algo.getCurveInfo(Algorithm.ES256));
        assertThrows(UnsupportedOperationException.class, algo::getKeyInfo);
        assertThrows(UnsupportedOperationException.class, algo::getKeyPath);
        assertDoesNotThrow(algo::close);
        assertDoesNotThrow(algo::cleanupExpiredKeys);
    }

    @Test
    void listKeys_should_route_by_algorithm_and_filter() {
        // Arrange
        KeyVersion h = KeyVersion.builder().keyId("h").algorithm(Algorithm.HMAC256).status(KeyStatus.CREATED).build();
        KeyVersion r = KeyVersion.builder().keyId("r").algorithm(Algorithm.RSA256).status(KeyStatus.CREATED).build();
        KeyVersion e = KeyVersion.builder().keyId("e").algorithm(Algorithm.ES256).status(KeyStatus.CREATED).build();
        KeyVersion ed = KeyVersion.builder().keyId("ed").algorithm(Algorithm.Ed25519).status(KeyStatus.CREATED).build();
        JwtAlgo algo = new TestAlgo(List.of(h, r, e, ed));

        // Act
        List<KeyVersion> hmac = algo.listKeys(Algorithm.HMAC256, "d");
        List<KeyVersion> rsa = algo.listKeys(Algorithm.RSA256, "d");
        List<KeyVersion> ec = algo.listKeys(Algorithm.ES256, "d");
        List<KeyVersion> edKeys = algo.listKeys(Algorithm.Ed25519, "d");

        // Assert
        assertEquals(List.of(h), hmac);
        assertEquals(List.of(r), rsa);
        assertEquals(List.of(e), ec);
        assertEquals(List.of(ed), edKeys);
        assertTrue(algo.isECD(Algorithm.ES256));
        assertTrue(algo.isECD(Algorithm.Ed25519));
        assertFalse(algo.isECD(Algorithm.HMAC256));
    }

    @Test
    void generateToken_overloads_should_delegate_and_validate_claim_type() {
        // Arrange
        TestAlgo algo = new TestAlgo(List.of());
        JwtProperties props = new JwtProperties();
        props.setSubject("s");
        props.setIssuer("i");
        props.setExpiration(Instant.now().plusSeconds(60));

        // Act
        String token1 = algo.generateToken(props, Algorithm.HMAC256);

        // Assert
        assertEquals("token", token1);
        assertEquals(Algorithm.HMAC256, algo.lastAlgorithm);
        assertNull(algo.lastClaims);

        // Act & Assert (wrong type)
        assertThrows(IllegalArgumentException.class, () -> ((JwtAlgo) algo).generateToken(props, Algorithm.HMAC256, 123, (Class) String.class));

        // Act (correct type)
        String token2 = algo.generateToken(props, Algorithm.HMAC256, "{\"k\":\"v\"}", String.class);

        // Assert
        assertEquals("token", token2);
        assertEquals(Map.of("raw", "{\"k\":\"v\"}"), algo.lastClaims);
    }

    @Test
    void static_helpers_should_create_algo_instances(@TempDir Path tempDir) {
        // Arrange
        Path base = tempDir.resolve("keys");

        // Act
        JwtAlgo hmac = JwtAlgo.FirstKey(Algorithm.HMAC256, base, true);
        JwtAlgo rsa = JwtAlgo.WithKeyId(Algorithm.RSA256, base, "kid", true);
        JwtAlgo ec = Prep.getPre(Algorithm.ES256, base, new KeyMinterProperties());
        JwtAlgo ed = Prep.getPre(Algorithm.Ed25519, base, new KeyMinterProperties());

        // Assert
        assertNotNull(hmac);
        assertNotNull(rsa);
        assertNotNull(ec);
        assertNotNull(ed);
        assertNotNull(Prep.getPre(Algorithm.HMAC256, base, new KeyMinterProperties(), Mockito.mock(com.chao.keyMinter.domain.port.out.KeyRepositoryFactory.class)));
        assertNotNull(Prep.getPre(Algorithm.RSA256, base, new KeyMinterProperties(), Mockito.mock(com.chao.keyMinter.domain.port.out.KeyRepositoryFactory.class)));
    }

    private static final class TestAlgo implements JwtAlgo {
        private final List<KeyVersion> keys;
        private volatile Algorithm lastAlgorithm;
        private volatile Map<String, Object> lastClaims;

        private TestAlgo(List<KeyVersion> keys) {
            this.keys = keys;
        }

        @Override
        public String generateToken(JwtProperties properties, Map<String, Object> customClaims, Algorithm algorithm) {
            this.lastAlgorithm = algorithm;
            this.lastClaims = customClaims;
            return "token";
        }

        @Override
        public boolean verifyToken(String token) {
            return false;
        }

        @Override
        public Claims decodePayload(String token) {
            return null;
        }

        @Override
        public boolean manageSecret(String secret) {
            return false;
        }

        @Override
        public boolean generateKeyPair(Algorithm algorithm) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<KeyVersion> listAllKeys(String directory) {
            return keys;
        }

        @Override
        public List<KeyVersion> listAllKeys() {
            return keys;
        }

        @Override
        public List<KeyVersion> listKeys(Algorithm algorithm) {
            return JwtAlgo.super.listKeys(algorithm, null);
        }

        @Override
        public boolean generateHmacKey(Algorithm algorithm, Integer length) {
            return false;
        }

        @Override
        public boolean generateAllKeyPairs() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean rotateKey(Algorithm algorithm, String newKeyIdentifier) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean rotateHmacKey(Algorithm algorithm, String newKeyIdentifier, Integer length) {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<String> getKeyVersions() {
            throw new UnsupportedOperationException();
        }

        @Override
        public List<String> getKeyVersions(Algorithm algorithm) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean setActiveKey(String keyId) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getActiveKeyId() {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean keyPairExists(Algorithm algorithm) {
            throw new UnsupportedOperationException();
        }

        @Override
        public boolean keyPairExists() {
            throw new UnsupportedOperationException();
        }

        @Override
        public LocalDateTime getDirTimestamp(Path dir) {
            return null;
        }

        @Override
        public JwtAlgo autoLoadFirstKey(Algorithm algorithm, String preferredKeyId, boolean force) {
            return this;
        }

        @Override
        public boolean verifyWithKeyVersion(String keyId, String token) {
            return false;
        }

        @Override
        public void loadExistingKeyVersions() {
        }

        @Override
        public JwtAlgo withKeyDirectory(Path keyDir) {
            return this;
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
        public String getAlgorithmInfo() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getCurveInfo(Algorithm algorithm) {
            throw new UnsupportedOperationException();
        }

        @Override
        public String getKeyInfo() {
            throw new UnsupportedOperationException();
        }

        @Override
        public Path getKeyPath() {
            throw new UnsupportedOperationException();
        }

        @Override
        public String generateToken(JwtProperties properties, Algorithm algorithm) {
            return generateToken(properties, null, algorithm);
        }

        @Override
        public <T> Map<String, Object> convertToClaimsMap(T customClaims) {
            if (customClaims == null) {
                return null;
            }
            return Map.of("raw", customClaims);
        }

        @Override
        public KeyVersion getActiveKeyVersion() {
            return null;
        }

        @Override
        public List<String> getKeyVersionsByStatus(KeyStatus status) {
            return List.of();
        }

        @Override
        public void close() {
        }

        @Override
        public void cleanupExpiredKeys() {
        }
    }
}
