package com.chao.keyMinter.api;

import com.chao.keyMinter.core.JwtFactory;
import com.chao.keyMinter.domain.model.*;
import com.chao.keyMinter.domain.service.JwtAlgo;
import lombok.extern.slf4j.Slf4j;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.*;

@Slf4j
class KeyMinterBranchCoverageTest {

    @Mock
    JwtFactory jwtFactory;

    @Mock
    JwtAlgo defaultAlgo;

    @Mock
    JwtAlgo sameAlgo;

    @Mock
    JwtAlgo rsaAlgo;

    @Mock
    JwtAlgo esAlgo;

    private KeyMinter key;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);

        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(defaultAlgo.getKeyInfo()).thenReturn("kid-001");
        when(defaultAlgo.getAlgorithmInfo()).thenReturn("Default Algo Info");
        when(defaultAlgo.keyPairExists()).thenReturn(false);
        when(defaultAlgo.keyPairExists(any())).thenReturn(false);
        when(defaultAlgo.getActiveKeyId()).thenReturn("kid-001");
        when(defaultAlgo.getKeyPath()).thenReturn(Paths.get("/tmp/keys"));
        when(defaultAlgo.listAllKeys()).thenReturn(java.util.Collections.emptyList());
        when(defaultAlgo.listAllKeys(anyString())).thenReturn(java.util.Collections.emptyList());
        when(defaultAlgo.listKeys(any())).thenReturn(java.util.Collections.emptyList());
        when(defaultAlgo.listKeys(any(), anyString())).thenReturn(java.util.Collections.emptyList());
        when(defaultAlgo.getKeyVersions()).thenReturn(java.util.Collections.emptyList());
        when(defaultAlgo.getKeyVersions(any())).thenReturn(java.util.Collections.emptyList());
        when(defaultAlgo.getKeyVersionsByStatus(any())).thenReturn(java.util.Collections.emptyList());
        when(defaultAlgo.setActiveKey(anyString())).thenReturn(true);
        when(defaultAlgo.verifyToken(anyString())).thenReturn(false);
        when(defaultAlgo.isECD(any())).thenReturn(false);

        key = new KeyMinter(jwtFactory);
    }

    @Test
    void testSwitchToSameAlgorithm() {
        // Test switching to the same algorithm instance
        when(jwtFactory.get(Algorithm.HMAC256, (String) null)).thenReturn(defaultAlgo);
        boolean result = key.switchTo(Algorithm.HMAC256);
        assertTrue(result);
    }

    @Test
    void testSwitchToWithNullAlgoInstance() {
        // Test switching when algoInstance is null (simulate initial state)
        // We need to use reflection to set algoInstance to null
        try {
            java.lang.reflect.Field algoInstanceField = KeyMinter.class.getDeclaredField("algoInstance");
            algoInstanceField.setAccessible(true);
            algoInstanceField.set(key, null);

            when(jwtFactory.get(Algorithm.HMAC256, (String) null)).thenReturn(defaultAlgo);
            boolean result = key.switchTo(Algorithm.HMAC256);
            assertTrue(result);
        } catch (Exception e) {
            e.printStackTrace();
            fail("Reflection failed: " + e.getMessage());
        }
    }

    @Test
    void testIsValidWithGracefulWithNullBackup() {
        // Test isValidWithGraceful when there's no backup algorithm
        boolean result = key.isValidWithGraceful("token");
        assertFalse(result);
    }

    @Test
    void testValidateHmacAlgorithmWithNull() {
        // Test validateHmacAlgorithm with null algorithm
        try {
            java.lang.reflect.Method validateMethod = KeyMinter.class.getDeclaredMethod("validateHmacAlgorithm", Algorithm.class);
            validateMethod.setAccessible(true);
            validateMethod.invoke(key, (Algorithm) null);
            // Should not throw exception
        } catch (Exception e) {
            fail("validateHmacAlgorithm should not throw exception for null algorithm: " + e.getMessage());
        }
    }

    @Test
    void testValidateHmacAlgorithmWithHmac() {
        // Test validateHmacAlgorithm with HMAC algorithm
        try {
            java.lang.reflect.Method validateMethod = KeyMinter.class.getDeclaredMethod("validateHmacAlgorithm", Algorithm.class);
            validateMethod.setAccessible(true);
            validateMethod.invoke(key, Algorithm.HMAC256);
            // Should not throw exception
        } catch (Exception e) {
            fail("validateHmacAlgorithm should not throw exception for HMAC algorithm: " + e.getMessage());
        }
    }

    @Test
    void testGenerateAllKeyPairsWithRsaFailure() {
        // Test generateAllKeyPairs with RSA failure
        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(jwtFactory.get(Algorithm.RSA256)).thenReturn(rsaAlgo);
        when(jwtFactory.get(Algorithm.ES256)).thenReturn(esAlgo);
        when(jwtFactory.get(Algorithm.Ed25519)).thenReturn(defaultAlgo);

        when(defaultAlgo.generateAllKeyPairs()).thenReturn(true);
        when(rsaAlgo.generateAllKeyPairs()).thenReturn(false);
        when(esAlgo.generateAllKeyPairs()).thenReturn(true);

        boolean result = key.generateAllKeyPairs();
        assertFalse(result);
    }

    @Test
    void testGenerateAllKeyPairsWithRsaException() {
        // Test generateAllKeyPairs with RSA exception
        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(jwtFactory.get(Algorithm.RSA256)).thenReturn(rsaAlgo);
        when(jwtFactory.get(Algorithm.ES256)).thenReturn(esAlgo);
        when(jwtFactory.get(Algorithm.Ed25519)).thenReturn(defaultAlgo);

        when(defaultAlgo.generateAllKeyPairs()).thenReturn(true);
        when(rsaAlgo.generateAllKeyPairs()).thenThrow(new RuntimeException("RSA error"));
        when(esAlgo.generateAllKeyPairs()).thenReturn(true);

        boolean result = key.generateAllKeyPairs();
        assertFalse(result);
    }

    @Test
    void testGenerateAllKeyPairsWithEcdsaFailure() {
        // Test generateAllKeyPairs with ECDSA failure
        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(jwtFactory.get(Algorithm.RSA256)).thenReturn(rsaAlgo);
        when(jwtFactory.get(Algorithm.ES256)).thenReturn(esAlgo);
        when(jwtFactory.get(Algorithm.Ed25519)).thenReturn(defaultAlgo);

        when(defaultAlgo.generateAllKeyPairs()).thenReturn(true);
        when(rsaAlgo.generateAllKeyPairs()).thenReturn(true);
        when(esAlgo.generateAllKeyPairs()).thenReturn(false);

        boolean result = key.generateAllKeyPairs();
        assertFalse(result);
    }

    @Test
    void testGenerateAllKeyPairsWithEcdsaException() {
        // Test generateAllKeyPairs with ECDSA exception
        when(jwtFactory.get(Algorithm.HMAC256)).thenReturn(defaultAlgo);
        when(jwtFactory.get(Algorithm.RSA256)).thenReturn(rsaAlgo);
        when(jwtFactory.get(Algorithm.ES256)).thenReturn(esAlgo);
        when(jwtFactory.get(Algorithm.Ed25519)).thenReturn(defaultAlgo);

        when(defaultAlgo.generateAllKeyPairs()).thenReturn(true);
        when(rsaAlgo.generateAllKeyPairs()).thenReturn(true);
        when(esAlgo.generateAllKeyPairs()).thenThrow(new RuntimeException("ECDSA error"));

        boolean result = key.generateAllKeyPairs();
        assertFalse(result);
    }

    @Test
    void testCleanupExpiredGracefulAlgo() {
        // Test cleanupExpiredGracefulAlgo with expired previous instance
        try {
            // Set up previousAlgoInstance and an expired timestamp
            java.lang.reflect.Field previousAlgoInstanceField = KeyMinter.class.getDeclaredField("previousAlgoInstance");
            previousAlgoInstanceField.setAccessible(true);
            previousAlgoInstanceField.set(key, defaultAlgo);

            java.lang.reflect.Field previousAlgoExpiryTimeField = KeyMinter.class.getDeclaredField("previousAlgoExpiryTime");
            previousAlgoExpiryTimeField.setAccessible(true);
            previousAlgoExpiryTimeField.set(key, System.currentTimeMillis() - 1000); // Expired

            // Call cleanupExpiredGracefulAlgo
            java.lang.reflect.Method cleanupMethod = KeyMinter.class.getDeclaredMethod("cleanupExpiredGracefulAlgo");
            cleanupMethod.setAccessible(true);
            cleanupMethod.invoke(key);

            // Verify previousAlgoInstance is null
            Object result = previousAlgoInstanceField.get(key);
            assertNull(result);
            verify(defaultAlgo).close();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Reflection failed: " + e.getMessage());
        }
    }

    @Test
    void testCleanupExpiredGracefulAlgoNotExpired() {
        // Test cleanupExpiredGracefulAlgo with non-expired previous instance
        try {
            // Set up previousAlgoInstance and a future timestamp
            java.lang.reflect.Field previousAlgoInstanceField = KeyMinter.class.getDeclaredField("previousAlgoInstance");
            previousAlgoInstanceField.setAccessible(true);
            previousAlgoInstanceField.set(key, defaultAlgo);

            java.lang.reflect.Field previousAlgoExpiryTimeField = KeyMinter.class.getDeclaredField("previousAlgoExpiryTime");
            previousAlgoExpiryTimeField.setAccessible(true);
            previousAlgoExpiryTimeField.set(key, System.currentTimeMillis() + 3600000); // Not expired

            // Call cleanupExpiredGracefulAlgo
            java.lang.reflect.Method cleanupMethod = KeyMinter.class.getDeclaredMethod("cleanupExpiredGracefulAlgo");
            cleanupMethod.setAccessible(true);
            cleanupMethod.invoke(key);

            // Verify previousAlgoInstance is still set
            Object result = previousAlgoInstanceField.get(key);
            assertSame(defaultAlgo, result);
            verify(defaultAlgo, never()).close();
        } catch (Exception e) {
            e.printStackTrace();
            fail("Reflection failed: " + e.getMessage());
        }
    }

    @Test
    void testCleanupExpiredGracefulAlgoNullInstance() {
        // Test cleanupExpiredGracefulAlgo with null previous instance
        try {
            // Ensure previousAlgoInstance is null
            java.lang.reflect.Field previousAlgoInstanceField = KeyMinter.class.getDeclaredField("previousAlgoInstance");
            previousAlgoInstanceField.setAccessible(true);
            previousAlgoInstanceField.set(key, null);

            // Call cleanupExpiredGracefulAlgo
            java.lang.reflect.Method cleanupMethod = KeyMinter.class.getDeclaredMethod("cleanupExpiredGracefulAlgo");
            cleanupMethod.setAccessible(true);
            cleanupMethod.invoke(key);

            // Should not throw exception
        } catch (Exception e) {
            e.printStackTrace();
            fail("Reflection failed: " + e.getMessage());
        }
    }

    @Test
    void testIsValidWithGracefulWithBackup() {
        // Test isValidWithGraceful with backup algorithm
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(rsaAlgo);
        key.switchTo(Algorithm.RSA256);
        when(defaultAlgo.verifyToken("token")).thenReturn(true);

        boolean result = key.isValidWithGraceful("token");
        assertTrue(result);
    }

    @Test
    void testIsValidWithGracefulWithBackupFailure() {
        // Test isValidWithGraceful with backup algorithm that returns false
        when(jwtFactory.get(Algorithm.RSA256, (String) null)).thenReturn(rsaAlgo);
        key.switchTo(Algorithm.RSA256);
        when(defaultAlgo.verifyToken("token")).thenReturn(false);

        boolean result = key.isValidWithGraceful("token");
        assertFalse(result);
    }
}
