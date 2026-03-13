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
        // Arrange
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getActiveKeyId()).thenReturn("key-1");
        when(keyMinter.getKeyPath()).thenReturn(tempDir);
        when(keyMinter.getCacheSize()).thenReturn(1);
        when(keyMinter.getAlgorithmInfo()).thenReturn("HMAC256");

        // Act
        Health health = healthIndicator.health();

        // Assert
        assertEquals(Status.UP, health.getStatus());
        assertEquals("key-1", health.getDetails().get("activeKeyId"));
        assertEquals(1, health.getDetails().get("cacheSize"));
        assertEquals(true, health.getDetails().get("dirReadable"));
        assertEquals(tempDir.toString(), health.getDetails().get("keyDir"));
        assertEquals("HMAC256", health.getDetails().get("algorithm"));
    }
    
    @Test
    void testHealthDown() {
        // Arrange
        when(keyMinter.keyPairExists()).thenReturn(false);
        when(keyMinter.getKeyPath()).thenReturn(null);

        // Act
        Health health = healthIndicator.health();

        // Assert
        assertEquals(Status.DOWN, health.getStatus());
        assertEquals("none", health.getDetails().get("activeKeyId"));
        assertEquals("null", health.getDetails().get("keyDir"));
        assertEquals(false, health.getDetails().get("dirReadable"));
        assertEquals("unknown", health.getDetails().get("algorithm"));
    }

    @Test
    void dirReadable_should_be_false_when_keyPath_is_null() {
        // Arrange
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getKeyPath()).thenReturn(null);

        // Act
        Health health = healthIndicator.health();

        // Assert
        assertEquals(Status.UP, health.getStatus());
        assertEquals(false, health.getDetails().get("dirReadable"));
    }

    @Test
    void dirReadable_should_be_false_when_path_not_exists() {
        // Arrange
        Path keyPath = Path.of("not-exist-dir");
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getKeyPath()).thenReturn(keyPath);

        // Act
        try (org.mockito.MockedStatic<Files> files = org.mockito.Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(keyPath)).thenReturn(false);

            Health health = healthIndicator.health();

            // Assert
            assertEquals(Status.UP, health.getStatus());
            assertEquals(false, health.getDetails().get("dirReadable"));
            files.verify(() -> Files.isDirectory(any()), never());
            files.verify(() -> Files.isReadable(any()), never());
        }
    }

    @Test
    void dirReadable_should_be_false_when_path_is_not_directory() {
        // Arrange
        Path keyPath = Path.of("a-file");
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getKeyPath()).thenReturn(keyPath);

        // Act
        try (org.mockito.MockedStatic<Files> files = org.mockito.Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(keyPath)).thenReturn(true);
            files.when(() -> Files.isDirectory(keyPath)).thenReturn(false);

            Health health = healthIndicator.health();

            // Assert
            assertEquals(Status.UP, health.getStatus());
            assertEquals(false, health.getDetails().get("dirReadable"));
            files.verify(() -> Files.isReadable(any()), never());
        }
    }

    @Test
    void dirReadable_should_be_false_when_directory_not_readable() {
        // Arrange
        Path keyPath = Path.of("no-read-dir");
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getKeyPath()).thenReturn(keyPath);

        // Act
        try (org.mockito.MockedStatic<Files> files = org.mockito.Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(keyPath)).thenReturn(true);
            files.when(() -> Files.isDirectory(keyPath)).thenReturn(true);
            files.when(() -> Files.isReadable(keyPath)).thenReturn(false);

            Health health = healthIndicator.health();

            // Assert
            assertEquals(Status.UP, health.getStatus());
            assertEquals(false, health.getDetails().get("dirReadable"));
        }
    }
    
    @Test
    void dirReadable_should_be_true_when_directory_exists_is_directory_and_readable() {
        // Arrange
        Path keyPath = Path.of("readable-dir");
        when(keyMinter.keyPairExists()).thenReturn(true);
        when(keyMinter.getKeyPath()).thenReturn(keyPath);

        // Act
        try (org.mockito.MockedStatic<Files> files = org.mockito.Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(keyPath)).thenReturn(true);
            files.when(() -> Files.isDirectory(keyPath)).thenReturn(true);
            files.when(() -> Files.isReadable(keyPath)).thenReturn(true);

            Health health = healthIndicator.health();

            // Assert
            assertEquals(Status.UP, health.getStatus());
            assertEquals(true, health.getDetails().get("dirReadable"));
        }
    }

    @Test
    void testHealthException() {
        // Arrange
        when(keyMinter.keyPairExists()).thenThrow(new RuntimeException("Error"));

        // Act
        Health health = healthIndicator.health();

        // Assert
        assertEquals(Status.DOWN, health.getStatus());
        assertNotNull(health.getDetails().get("error"));
    }
}
