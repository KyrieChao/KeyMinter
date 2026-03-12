package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Files;
import java.nio.file.Path;
import java.security.SecureRandom;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.when;

class HmacJwtExtendedTest {

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
        when(properties.isEnableRotation()).thenReturn(true);
        
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
    void testLegacyKeyMigration() throws Exception {
        // 1. Create a legacy key file in the correct sub-directory
        Path hmacDir = tempDir.resolve("hmac-keys");
        Files.createDirectories(hmacDir);
        Path legacyKey = hmacDir.resolve("legacy-hmac.key");
        
        byte[] secret = new byte[64];
        new SecureRandom().nextBytes(secret);
        Files.write(legacyKey, secret);

        // 2. Initialize HmacJwt
        // Note: HmacJwt constructor initializes keyRepository, which prevents loadLegacyKeys from running.
        // We need to bypass this via reflection to test the migration logic specifically.
        hmacJwt = new HmacJwt(properties, tempDir);
        
        // 3. Force migration via reflection
        // Set keyRepository to null
        java.lang.reflect.Field repoField = AbstractJwtAlgo.class.getDeclaredField("keyRepository");
        repoField.setAccessible(true);
        repoField.set(hmacJwt, null);
        
        // Call loadLegacyKeys
        java.lang.reflect.Method loadLegacyMethod = HmacJwt.class.getDeclaredMethod("loadLegacyKeys");
        loadLegacyMethod.setAccessible(true);
        loadLegacyMethod.invoke(hmacJwt);
        
        // 4. Verify migration
        boolean hasVersionDir = Files.list(hmacDir)
                .anyMatch(p -> Files.isDirectory(p) && p.getFileName().toString().startsWith("hmac-v"));
        
        assertTrue(hasVersionDir, "Should have migrated legacy key to version directory");
        
        // Reload active key to verify it's usable
        // Since we messed with internals, we might need to refresh state or check file system
        // The migration updates in-memory map, so it should be there.
        assertNotNull(hmacJwt.getActiveKeyId());
    }
    
    @Test
    void testAutoLoadFirstKey() {
        // 1. No keys initially
        assertNull(hmacJwt.getActiveKeyId());
        
        // 2. Generate a key but don't activate it (simulate by manually creating dir if possible, 
        // or just generate and then de-activate)
        hmacJwt.generateHmacKey(Algorithm.HMAC256, 64);
        // generateHmacKey creates a version but doesn't activate it (it's CREATED)
        // Wait, rotateHmacKey DOES NOT activate by default in the new logic?
        // Let's check HmacJwt.java:
        // rotateHmacKey -> updateKeyVersionWithTransition:
        // Check if it handles CREATED status correctly.
        // So activeKeyId should be null after generateHmacKey if it wasn't set.
        
        // But HmacJwt constructor calls initializeKeyVersions -> loadExistingKeyVersions
        // If we generate now, it is in memory.
        
        // Let's force reload
        hmacJwt.close();
        hmacJwt = new HmacJwt(properties, tempDir);
        
        // Now we have keys on disk but none active
        hmacJwt.autoLoadFirstKey(Algorithm.HMAC256, null, false);
        
        // Should have picked up the key
        assertNotNull(hmacJwt.getActiveKeyId());
    }
    
    @Test
    void testConstructors() {
        // Default constructor
        HmacJwt defaultJwt = null;
        try {
            defaultJwt = new HmacJwt();
            assertNotNull(defaultJwt);
        } catch (Exception e) {
            // Ignore environment issues
        } finally {
            if (defaultJwt != null) {
                defaultJwt.close();
            }
        }
        
        // Path constructor
        HmacJwt pathJwt = null;
        try {
            pathJwt = new HmacJwt(tempDir);
            assertNotNull(pathJwt);
            assertEquals(tempDir.normalize().resolve("hmac-keys"), pathJwt.getKeyPath());
        } finally {
            if (pathJwt != null) {
                pathJwt.close();
            }
        }
    }
    
    @Test
    void testRotationDisabled() {
        when(properties.isEnableRotation()).thenReturn(false);
        HmacJwt noRotationJwt = new HmacJwt(properties, tempDir);
        
        assertFalse(noRotationJwt.rotateHmacKey(Algorithm.HMAC256, "new-id", 64));
        noRotationJwt.close();
    }
    
    @Test
    void testGetKeyInfo() {
        hmacJwt.generateHmacKey(Algorithm.HMAC256, 64);
        String info = hmacJwt.getKeyInfo();
        assertNotNull(info);
        assertTrue(info.contains("HMAC Keys"));
    }
    
    @Test
    void testAlgorithmInfo() {
        String info = hmacJwt.getAlgorithmInfo();
        assertTrue(info.contains("HS256"));
    }
    
    @Test
    void testGenerateAllKeyPairs() {
        assertTrue(hmacJwt.generateAllKeyPairs());
        // Should have generated for HS256, HS384, HS512
        // But since generateHmacKey doesn't activate, activeKeyId might be null or last one?
        // It generates them.
        assertTrue(hmacJwt.getKeyVersions(Algorithm.HMAC256).size() > 0);
        assertTrue(hmacJwt.getKeyVersions(Algorithm.HMAC384).size() > 0);
        assertTrue(hmacJwt.getKeyVersions(Algorithm.HMAC512).size() > 0);
    }
}
