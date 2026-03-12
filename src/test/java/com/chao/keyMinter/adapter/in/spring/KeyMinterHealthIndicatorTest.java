package com.chao.keyMinter.adapter.in.spring;

import com.chao.keyMinter.api.KeyMinter;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.MockitoAnnotations;
import org.springframework.boot.actuate.health.Health;
import org.springframework.boot.actuate.health.Status;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.Mockito.*;

class KeyMinterHealthIndicatorTest {

    @Mock
    KeyMinter keyMinter;

    @InjectMocks
    private KeyMinterHealthIndicator healthIndicator;

    @BeforeEach
    void setUp() {
        MockitoAnnotations.openMocks(this);
    }

    @Test
    void testHealthUp(@TempDir Path tempDir) {
        // Mock successful health check dependencies
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getActiveKeyId()).thenReturn("key-1");
        when(keyMinter.getKeyPath()).thenReturn(tempDir);
        when(keyMinter.getCacheSize()).thenReturn(1);
        when(keyMinter.getAlgorithmInfo()).thenReturn("HMAC256");

        Health health = healthIndicator.health();
        
        assertEquals(Status.UP, health.getStatus());
        assertEquals("key-1", health.getDetails().get("activeKeyId"));
        assertEquals(1, health.getDetails().get("cacheSize"));
        assertEquals(true, health.getDetails().get("dirReadable"));
        assertEquals(tempDir.toString(), health.getDetails().get("keyDir"));
        assertEquals("HMAC256", health.getDetails().get("algorithm"));
    }
    
    @Test
    void testHealthDown() {
        // Mock failure
        when(keyMinter.keyPairExists()).thenReturn(false);
        when(keyMinter.getKeyPath()).thenReturn(null);
        
        Health health = healthIndicator.health();
        
        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("none", health.getDetails().get("activeKeyId"));
        assertEquals("null", health.getDetails().get("keyDir"));
        assertEquals(false, health.getDetails().get("dirReadable"));
        assertEquals("unknown", health.getDetails().get("algorithm"));
    }

    @Test
    void testDirNotReadable_NullPath() {
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getKeyPath()).thenReturn(null);

        Health health = healthIndicator.health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals(false, health.getDetails().get("dirReadable"));
    }

    @Test
    void testDirNotReadable_NonExistentPath(@TempDir Path tempDir) {
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getKeyPath()).thenReturn(tempDir.resolve("non-existent"));

        Health health = healthIndicator.health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals(false, health.getDetails().get("dirReadable"));
    }

    @Test
    void testDirNotReadable_NotDirectory(@TempDir Path tempDir) throws IOException {
        Path file = tempDir.resolve("test-file");
        Files.createFile(file);
        
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getKeyPath()).thenReturn(file);

        Health health = healthIndicator.health();

        assertEquals(Status.UP, health.getStatus());
        assertEquals(false, health.getDetails().get("dirReadable"));
    }

    @Test
    void testDirNotReadable_PermissionDenied(@TempDir Path tempDir) {
        Path restrictedDir = tempDir.resolve("restricted");
        try {
            Files.createDirectories(restrictedDir);
            File file = restrictedDir.toFile();
            // Try to make it unreadable. 
            // Note: This often fails on Windows or root users.
            boolean success = file.setReadable(false);
            
            if (success) {
                when(keyMinter.keyPairExists()).thenReturn(true);
                when(keyMinter.getKeyPath()).thenReturn(restrictedDir);

                Health health = healthIndicator.health();

                assertEquals(Status.UP, health.getStatus());
                assertEquals(false, health.getDetails().get("dirReadable"));
            } else {
                System.out.println("Skipping testDirNotReadable_PermissionDenied as setReadable(false) failed");
            }
        } catch (IOException e) {
            fail("Setup failed");
        }
    }
    
    @Test
    void testHealthException() {
        when(keyMinter.keyPairExists()).thenThrow(new RuntimeException("Error"));
        
        Health health = healthIndicator.health();
        
        assertEquals(Status.DOWN, health.getStatus());
        assertNotNull(health.getDetails().get("error"));
    }
}
