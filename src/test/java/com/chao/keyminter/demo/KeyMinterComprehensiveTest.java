package com.chao.keyminter.demo;

import com.chao.keyminter.api.KeyMinter;
import com.chao.keyminter.adapter.in.spring.KeyMinterAutoConfiguration;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.JwtProperties;
import com.chao.keyminter.domain.model.JwtStandardInfo;
import com.chao.keyminter.domain.model.KeyVersion;
import org.junit.jupiter.api.*;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Duration;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;

@SpringBootTest(classes = KeyMinterAutoConfiguration.class)
@Import(KeyMinterAutoConfiguration.class)
@ActiveProfiles("test") // Uses application.yml from src/test/resources
@org.springframework.test.context.TestPropertySource(properties = "key-minter.key-dir=${java.io.tmpdir}/keyminter-test/comprehensive-${random.uuid}")
@TestMethodOrder(MethodOrderer.OrderAnnotation.class)
class KeyMinterComprehensiveTest {

    @Autowired
    private KeyMinter keyMinter;

    // Use property injection or just trust KeyMinter is configured correctly
    // private static final Path TEST_KEY_DIR = Path.of(System.getProperty("user.home"), ".keyminter-test-env");
    
    // We can't easily access the random UUID path here for cleanup in BeforeAll/AfterAll static methods.
    // However, since we use random UUID in tmpdir, we don't strictly need manual cleanup of a fixed directory anymore,
    // as it won't conflict with other tests. The OS or subsequent runs might clean up /tmp.
    // But to be clean, we can inject the value. But static methods can't access injected values.
    // So we'll remove the manual cleanup of the fixed directory and rely on unique temp dirs.

    @BeforeAll
    static void setup() throws IOException {
        // No-op or clean up if we knew the path
    }

    @AfterAll
    static void cleanup() throws IOException {
        // No-op
    }

    // private static void deleteDirectoryRecursively() ... (remove)

    @Test
    @Order(1)
    @DisplayName("HMAC: Lifecycle and Basic Operations")
    void testHmacLifecycle() {
        // 1. Switch
        assertTrue(keyMinter.switchTo(Algorithm.HMAC256));

        // 2. Create Key
        assertTrue(keyMinter.createHmacKey(Algorithm.HMAC256, 64));

        // 3. Generate Token
        JwtProperties props = JwtProperties.builder()
                .subject("test-user")
                .issuer("test-issuer")
                .expiration(Instant.now().plusSeconds(300))
                .build();

        String token = keyMinter.generateToken(props);
        assertNotNull(token);

        // 4. Verify
        assertTrue(keyMinter.isValidToken(token));

        // 5. Decode
        JwtStandardInfo info = keyMinter.getStandardInfo(token);
        assertEquals("test-user", info.getSubject());
        assertEquals("test-issuer", info.getIssuer());

        // 6. Decode Map
        Map<String, Object> map = keyMinter.decodeToFullMap(token);
        assertEquals("test-user", map.get("sub"));

        // 7. Check Decodable
        assertTrue(keyMinter.isTokenDecodable(token));
    }

    @Test
    @Order(2)
    @DisplayName("RSA: Lifecycle and Custom Claims")
    void testRsaLifecycle() {
        assertTrue(keyMinter.switchTo(Algorithm.RSA256));
        assertTrue(keyMinter.createKeyPair(Algorithm.RSA256));

        JwtProperties props = JwtProperties.builder()
                .subject("rsa-user")
                .issuer("test")
                .expiration(Instant.now().plus(Duration.ofMinutes(1)))
                .build();

        Map<String, Object> claims = Map.of("role", "admin", "id", 123);
        String token = keyMinter.generateToken(props, claims, Map.class);

        assertTrue(keyMinter.isValidToken(token));

        // Test Generic Decode
        Map decodedClaims = keyMinter.getCustomClaims(token, Map.class);
        assertEquals("admin", decodedClaims.get("role"));
        assertEquals(123, decodedClaims.get("id"));
    }

    @Test
    @Order(3)
    @DisplayName("ECDSA: Lifecycle and Curve Info")
    void testEcdsaLifecycle() {
        assertTrue(keyMinter.switchTo(Algorithm.ES256));
        assertTrue(keyMinter.createKeyPair(Algorithm.ES256));
        
        String token = keyMinter.generateToken(JwtProperties.builder().subject("ec").issuer("test").expiration(Instant.now().plusSeconds(300)).build());
        assertTrue(keyMinter.isValidToken(token));
        
        String curveInfo = keyMinter.getECDCurveInfo();
        assertNotNull(curveInfo);
        assertTrue(curveInfo.contains("secp256r1") || curveInfo.contains("P-256"));
    }

    @Test
    @Order(4)
    @DisplayName("EdDSA: Lifecycle")
    void testEddsaLifecycle() {
        assertTrue(keyMinter.switchTo(Algorithm.Ed25519));
        assertTrue(keyMinter.createKeyPair(Algorithm.Ed25519));
        
        String token = keyMinter.generateToken(JwtProperties.builder().subject("ed").issuer("test").expiration(Instant.now().plusSeconds(300)).build());
        assertTrue(keyMinter.isValidToken(token));
    }

    @Test
    @Order(5)
    @DisplayName("Key Rotation and Historical Verification")
    void testKeyRotation() throws InterruptedException {
        keyMinter.switchTo(Algorithm.HMAC256);
        keyMinter.createHmacKey(Algorithm.HMAC256, 64);
        
        String tokenV1 = keyMinter.generateToken(JwtProperties.builder().subject("v1").issuer("test").expiration(Instant.now().plusSeconds(300)).build());
        assertTrue(keyMinter.isValidToken(tokenV1));
        
        // Wait for timestamp change (if FS resolution is low)
        TimeUnit.SECONDS.sleep(1);
        
        // Rotate
        assertTrue(keyMinter.createHmacKey(Algorithm.HMAC256, 64));
        String tokenV2 = keyMinter.generateToken(JwtProperties.builder().subject("v2").issuer("test").expiration(Instant.now().plusSeconds(300)).build());
        
        // Verify both
        assertTrue(keyMinter.isValidToken(tokenV2), "New token valid");
        assertTrue(keyMinter.isValidToken(tokenV1), "Old token valid via history");
        
        // Check Versions API
        List<KeyVersion> versions = keyMinter.listKeys();
        assertTrue(versions.size() >= 2);
        
        List<String> versionIds = keyMinter.getKeyVersions();
        assertTrue(versionIds.size() >= 2);
    }

    @Test
    @Order(6)
    @DisplayName("Algorithm Switching and Graceful Period")
    void testAlgorithmSwitching() {
        // HMAC -> RSA
        keyMinter.switchTo(Algorithm.HMAC256);
        String hmacToken = keyMinter.generateToken(JwtProperties.builder().subject("hmac").issuer("test").expiration(Instant.now().plusSeconds(300)).build());
        
        keyMinter.switchTo(Algorithm.RSA256);
        keyMinter.createKeyPair(Algorithm.RSA256);
        
        // Verify Graceful
        assertTrue(keyMinter.isValidToken(hmacToken));
        assertTrue(keyMinter.isValidWithGraceful(hmacToken));
        assertFalse(keyMinter.isValidWithCurrent(hmacToken));
    }

    @Test
    @Order(7)
    @DisplayName("Key Management API Coverage")
    void testKeyManagementApi() {
        // Generate all pairs
        keyMinter.generateAllKeyPairs();
        
        // List All Keys
        List<KeyVersion> allKeys = keyMinter.listAllKeys();
        assertFalse(allKeys.isEmpty());
        
        // Get Key Info
        String keyInfo = keyMinter.getJwtProperties(); // algoInstance.getKeyInfo()
        assertNotNull(keyInfo);
        
        String algoInfo = keyMinter.getAlgorithmInfo();
        assertNotNull(algoInfo);
        
        // Get Key By Version
        String activeKeyId = keyMinter.getActiveKeyId();
        assertNotNull(activeKeyId);
        assertNotNull(keyMinter.getKeyByVersion(activeKeyId));
        
        // Check Exists
        assertTrue(keyMinter.keyPairExists());
        assertTrue(keyMinter.keyPairExists(Algorithm.RSA256));
    }

    @Test
    @Order(8)
    @DisplayName("Advanced Features: Metrics, Cache, Custom Dir")
    void testAdvancedFeatures() {
        // Metrics
        keyMinter.resetMetrics();
        Map<String, Long> metrics = keyMinter.getMetrics();
        assertEquals(0L, metrics.get("gracefulUsage"));
        
        // Cache
        int cacheSize = keyMinter.getCacheSize();
        assertTrue(cacheSize > 0);
        keyMinter.clearCache();
        assertEquals(0, keyMinter.getCacheSize());
        
        // With Key Directory (Factory method)
        // Note: This creates a NEW instance, doesn't change current
        JwtAlgo customAlgo = keyMinter.withKeyDirectory(Path.of(System.getProperty("java.io.tmpdir"), "custom-" + java.util.UUID.randomUUID()));
        assertNotNull(customAlgo);
        
        // Close
        keyMinter.close(); // Should not throw
    }
    
    @Test
    @Order(9)
    @DisplayName("Auto Load")
    void testAutoLoad() {
        // Re-initialize state
        keyMinter.switchTo(Algorithm.RSA256);
        
        // Force reload
        keyMinter.autoLoad(Algorithm.RSA256, true);
        assertNotNull(keyMinter.getActiveKeyId());
        
        // Load with ID (pick one from existing)
        String keyId = keyMinter.getActiveKeyId();
        keyMinter.autoLoad(Algorithm.RSA256, null, keyId);
        assertEquals(keyId, keyMinter.getActiveKeyId());
    }
}