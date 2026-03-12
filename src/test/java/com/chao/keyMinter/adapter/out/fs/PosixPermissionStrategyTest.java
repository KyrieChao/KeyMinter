package com.chao.keyMinter.adapter.out.fs;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.PosixFilePermission;
import java.util.Set;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class PosixPermissionStrategyTest {

    @TempDir
    Path tempDir;

    private PosixPermissionStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new PosixPermissionStrategy();
    }

    @Test
    void testSetRestrictivePermissions_MockedPosix() throws IOException {
        Path file = tempDir.resolve("test-file");
        Files.createFile(file);

        try (MockedStatic<Files> filesMock = mockStatic(Files.class, CALLS_REAL_METHODS)) {
            PosixFileAttributeView viewMock = mock(PosixFileAttributeView.class);
            
            // Return mock view when requested
            filesMock.when(() -> Files.getFileAttributeView(any(), eq(PosixFileAttributeView.class)))
                    .thenReturn(viewMock);

            assertDoesNotThrow(() -> strategy.setRestrictivePermissions(file));

            // Verify permissions were set
            verify(viewMock).setPermissions(any(Set.class));
        }
    }
    
    @Test
    void testSetRestrictivePermissions_NotSupported() throws IOException {
        Path file = tempDir.resolve("test-file-nosupport");
        Files.createFile(file);

        try (MockedStatic<Files> filesMock = mockStatic(Files.class, CALLS_REAL_METHODS)) {
            // Return null (not supported)
            filesMock.when(() -> Files.getFileAttributeView(any(), eq(PosixFileAttributeView.class)))
                    .thenReturn(null);

            assertDoesNotThrow(() -> strategy.setRestrictivePermissions(file));
        }
    }

    @Test
    void testEnsureAccessible() throws IOException {
        Path dir = tempDir.resolve("test-dir");
        Files.createDirectories(dir);

        assertDoesNotThrow(() -> strategy.ensureAccessible(dir));
    }
    
    @Test
    void testEnsureAccessible_ReadOnly() throws IOException {
        Path dir = tempDir.resolve("readonly-dir");
        Files.createDirectories(dir);
        File file = dir.toFile();
        
        // Try to trigger the !isWritable branch
        if (file.setWritable(false)) {
            // If mocking Posix view works, ensureAccessible calls setRestrictivePermissions
            // But ensureAccessible checks File.canWrite() first usually.
            
            assertDoesNotThrow(() -> strategy.ensureAccessible(dir));
            file.setWritable(true); // cleanup
        }
    }
}
