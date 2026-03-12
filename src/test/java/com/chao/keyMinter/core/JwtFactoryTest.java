package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.service.JwtAlgo;
import com.chao.keyMinter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyMinter.domain.port.out.SecretDirProvider;
import org.junit.jupiter.api.AfterEach;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class JwtFactoryTest {

    @TempDir
    Path tempDir;

    @Mock
    KeyMinterProperties properties;

    @Mock
    KeyRepositoryFactory repositoryFactory;

    private JwtFactory jwtFactory;
    private AutoCloseable mocks;
    private Path originalBaseDir;

    @BeforeEach
    void setUp() {
        mocks = MockitoAnnotations.openMocks(this);
        
        // Mock default base dir to temp dir
        originalBaseDir = SecretDirProvider.getDefaultBaseDir();
        SecretDirProvider.setDefaultBaseDir(tempDir);
        
        jwtFactory = new JwtFactory();
        
        // Mock properties behavior
        lenient().when(properties.getKeyDir()).thenReturn(tempDir.toString());
        lenient().when(properties.getMaxAlgoInstance()).thenReturn(5);
        
        jwtFactory.setProperties(properties);
        jwtFactory.setRepositoryFactory(repositoryFactory);
    }

    @AfterEach
    void tearDown() throws Exception {
        jwtFactory.close();
        if (mocks != null) {
            mocks.close();
        }
        if (originalBaseDir != null) {
            SecretDirProvider.setDefaultBaseDir(originalBaseDir);
        }
    }

    @Test
    void testGetDefault() {
        JwtAlgo algo = jwtFactory.get();
        assertNotNull(algo);
        assertTrue(algo instanceof HmacJwt);
        assertEquals(1, jwtFactory.getCacheSize());
    }

    @Test
    void testGetWithAlgorithm() {
        JwtAlgo algo = jwtFactory.get(Algorithm.RSA256);
        assertNotNull(algo);
        assertTrue(algo instanceof RsaJwt);
    }

    @Test
    void testGetWithAlgorithmAndPath() {
        // Unset repository factory to ensure we use path-based initialization
        jwtFactory.setRepositoryFactory(null);
        
        JwtAlgo algo = jwtFactory.get(Algorithm.HMAC256, tempDir);
        assertNotNull(algo);
        // Normalize paths for comparison
        Path expected = tempDir.resolve("hmac-keys").toAbsolutePath().normalize();
        Path actual = algo.getKeyPath().toAbsolutePath().normalize();
        assertEquals(expected, actual);
    }

    @Test
    void testCaching() {
        JwtAlgo algo1 = jwtFactory.get(Algorithm.HMAC256, tempDir);
        JwtAlgo algo2 = jwtFactory.get(Algorithm.HMAC256, tempDir);
        
        assertSame(algo1, algo2);
        assertEquals(1, jwtFactory.getCacheSize());
    }

    @Test
    void testDifferentPathsCreateDifferentInstances() {
        JwtAlgo algo1 = jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("dir1"));
        JwtAlgo algo2 = jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("dir2"));
        
        assertNotSame(algo1, algo2);
        assertEquals(2, jwtFactory.getCacheSize());
    }

    @Test
    void testEviction() {
        // Set small max size via properties mock is not enough because it's read on init
        // We need to trigger the cache logic.
        // Since maxAlgoInstance is volatile and set in setProperties, we can try to re-set it?
        // But the cache is initialized in constructor.
        // Wait, the cache implementation reads maxAlgoInstance dynamically in removeEldestEntry?
        // No, `maxAlgoInstance` is a field in JwtFactory. The cache is an anonymous inner class 
        // that captures `this` (implicitly) or accesses the field.
        // Yes, `if (size() > maxAlgoInstance)` inside `removeEldestEntry`.
        
        when(properties.getMaxAlgoInstance()).thenReturn(2);
        jwtFactory.setProperties(properties); // Update max size
        
        jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("1"));
        jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("2"));
        assertEquals(2, jwtFactory.getCacheSize());
        
        jwtFactory.get(Algorithm.HMAC256, tempDir.resolve("3"));
        assertEquals(2, jwtFactory.getCacheSize()); // Should have evicted one
    }

    @Test
    void testAutoLoad() {
        JwtAlgo algo = jwtFactory.autoLoad(Algorithm.HMAC256, tempDir);
        assertNotNull(algo);
        // Since tempDir is empty, it won't load anything, but it should return the algo instance
    }
    
    @Test
    void testClearCache() {
        jwtFactory.get(Algorithm.HMAC256);
        assertEquals(1, jwtFactory.getCacheSize());
        
        jwtFactory.clearCache();
        assertEquals(0, jwtFactory.getCacheSize());
    }
}



