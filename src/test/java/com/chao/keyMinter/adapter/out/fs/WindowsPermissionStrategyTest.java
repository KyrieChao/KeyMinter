package com.chao.keyMinter.adapter.out.fs;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.UserPrincipal;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class WindowsPermissionStrategyTest {

    @TempDir
    Path tempDir;

    private WindowsPermissionStrategy strategy;

    @BeforeEach
    void setUp() {
        strategy = new WindowsPermissionStrategy();
    }

    @Test
    void testSetRestrictivePermissions_IcaclsSuccess() throws IOException {
        Path file = tempDir.resolve("test-file-success");
        Files.createFile(file);

        try (MockedConstruction<ProcessBuilder> mockedPb = mockConstruction(ProcessBuilder.class,
                (mock, context) -> {
                    Process process = mock(Process.class);
                    when(mock.start()).thenReturn(process);
                    when(process.getInputStream()).thenReturn(new ByteArrayInputStream("Successfully processed 1 files".getBytes()));
                    when(process.waitFor()).thenReturn(0);
                })) {
            
            assertDoesNotThrow(() -> strategy.setRestrictivePermissions(file));
        }
    }
    
    @Test
    void testSetRestrictivePermissions_IcaclsFailure_NioFallback() throws IOException {
        Path file = tempDir.resolve("test-file-fallback");
        Files.createFile(file);

        try (MockedConstruction<ProcessBuilder> mockedPb = mockConstruction(ProcessBuilder.class,
                (mock, context) -> {
                    Process process = mock(Process.class);
                    when(mock.start()).thenReturn(process);
                    when(process.getInputStream()).thenReturn(new ByteArrayInputStream("Failed".getBytes()));
                    when(process.waitFor()).thenReturn(1); // Non-zero exit code
                })) {
            
            // This should trigger fallback to NIO
            assertDoesNotThrow(() -> strategy.setRestrictivePermissions(file));
        }
    }

    @Test
    void testSetRestrictivePermissions_IcaclsException_NioFallback() throws IOException {
        Path file = tempDir.resolve("test-file-exception");
        Files.createFile(file);

        try (MockedConstruction<ProcessBuilder> mockedPb = mockConstruction(ProcessBuilder.class,
                (mock, context) -> {
                    when(mock.start()).thenThrow(new IOException("Process start failed"));
                })) {
            
            // This should catch exception and trigger fallback to NIO
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
    void testEnsureAccessible_Fail() {
        // Pass null to cause NPE inside, which should be caught
        assertDoesNotThrow(() -> strategy.ensureAccessible(null));
    }

    @Test
    void testSetRestrictivePermissions_NioFallback_AddAdminFail() throws IOException {
        Path file = tempDir.resolve("test-file-nio-fail");
        Files.createFile(file);

        // Force icacls failure
        try (MockedConstruction<ProcessBuilder> mockedPb = mockConstruction(ProcessBuilder.class,
                (mock, context) -> {
                    when(mock.start()).thenThrow(new IOException("Fail"));
                })) {
            
            try (MockedStatic<Files> filesMock = mockStatic(Files.class, CALLS_REAL_METHODS)) {
                 AclFileAttributeView aclViewMock = mock(AclFileAttributeView.class);
                 filesMock.when(() -> Files.getFileAttributeView(any(), eq(AclFileAttributeView.class)))
                         .thenReturn(aclViewMock);
                 
                 // Mock Files.getOwner
                 UserPrincipal ownerMock = mock(UserPrincipal.class);
                 filesMock.when(() -> Files.getOwner(any())).thenReturn(ownerMock);
                 
                 Path mockPath = mock(Path.class);
                 when(mockPath.toAbsolutePath()).thenReturn(file.toAbsolutePath());
                 when(mockPath.getFileSystem()).thenThrow(new RuntimeException("FS Error"));
                 
                 // We need Files.getFileAttributeView(mockPath) to return our mock view
                 filesMock.when(() -> Files.getFileAttributeView(eq(mockPath), eq(AclFileAttributeView.class)))
                         .thenReturn(aclViewMock);
                  filesMock.when(() -> Files.getOwner(eq(mockPath))).thenReturn(ownerMock);

                 assertDoesNotThrow(() -> strategy.setRestrictivePermissions(mockPath));
                 
                 // Verify setAcl was called (so the flow continued after catch)
                 verify(aclViewMock).setAcl(anyList());
            }
        }
    }
}
