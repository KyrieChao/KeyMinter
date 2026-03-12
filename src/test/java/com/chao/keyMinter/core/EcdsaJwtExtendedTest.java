package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.JwtProperties;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Files;
import java.nio.file.Path;
import java.time.Instant;
import java.util.List;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

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
}


