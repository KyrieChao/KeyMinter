package com.chao.keyMinter.adapter.out.fs;

import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.model.KeyVersionData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mockStatic;

class FileSystemKeyRepositoryTest {

    @TempDir
    Path tempDir;

    private FileSystemKeyRepository repository;

    @BeforeEach
    void setUp() {
        repository = new FileSystemKeyRepository(tempDir);
    }

    @Test
    void testConstructorEnsuresDirExists() {
        Path newDir = tempDir.resolve("new-repo");
        new FileSystemKeyRepository(newDir);
        assertTrue(Files.exists(newDir));
        assertTrue(Files.isDirectory(newDir));
    }
    
    @Test
    void testConstructorFailToCreateDir() {
        Path file = tempDir.resolve("file-blocker");
        try {
            Files.createFile(file);
        } catch (IOException e) {
            fail("Setup failed");
        }
        assertThrows(java.io.UncheckedIOException.class, () -> new FileSystemKeyRepository(file));
    }

    @Test
    void testSaveAndLoadKeyVersion() throws IOException {
        String keyId = "test-key";
        Map<String, byte[]> files = new HashMap<>();
        files.put("secret.key", "secret-data".getBytes(StandardCharsets.UTF_8));
        files.put("meta.info", "meta-data".getBytes(StandardCharsets.UTF_8));

        KeyVersionData data = KeyVersionData.builder()
                .keyId(keyId)
                .algorithm(Algorithm.HMAC256)
                .files(files)
                .build();

        repository.saveKeyVersion(data);

        Path keyDir = tempDir.resolve(keyId);
        assertTrue(Files.exists(keyDir));
        assertTrue(Files.exists(keyDir.resolve("secret.key")));
        
        Optional<byte[]> loadedSecret = repository.loadKey(keyId, "secret.key");
        assertTrue(loadedSecret.isPresent());
        assertArrayEquals("secret-data".getBytes(StandardCharsets.UTF_8), loadedSecret.get());
    }

    @Test
    void testSaveKeyVersionAtomicReplacement() throws IOException {
        String keyId = "atomic-key";
        Map<String, byte[]> files1 = new HashMap<>();
        files1.put("data", "v1".getBytes(StandardCharsets.UTF_8));
        
        repository.saveKeyVersion(KeyVersionData.builder().keyId(keyId).algorithm(Algorithm.HMAC256).files(files1).build());
        
        Optional<byte[]> v1 = repository.loadKey(keyId, "data");
        assertEquals("v1", new String(v1.get(), StandardCharsets.UTF_8));

        Map<String, byte[]> files2 = new HashMap<>();
        files2.put("data", "v2".getBytes(StandardCharsets.UTF_8));
        
        repository.saveKeyVersion(KeyVersionData.builder().keyId(keyId).algorithm(Algorithm.HMAC256).files(files2).build());
        
        Optional<byte[]> v2 = repository.loadKey(keyId, "data");
        assertEquals("v2", new String(v2.get(), StandardCharsets.UTF_8));
    }
    
    @Test
    void testSaveKeyVersionWithException() {
        String keyId = "error-key";
        Map<String, byte[]> files = new HashMap<>();
        files.put("invalid/filename", "data".getBytes()); 
        
        KeyVersionData data = KeyVersionData.builder().keyId(keyId).files(files).build();
        
        assertThrows(IOException.class, () -> repository.saveKeyVersion(data));
    }

    @Test
    void testMetadataOperations() throws IOException {
        String keyId = "meta-key";
        Files.createDirectories(tempDir.resolve(keyId));

        repository.saveMetadata(keyId, "status", "ACTIVE");

        Optional<String> status = repository.loadMetadata(keyId, "status");
        assertTrue(status.isPresent());
        assertEquals("ACTIVE", status.get());
        
        repository.deleteMetadata(keyId, "status");
        Optional<String> deleted = repository.loadMetadata(keyId, "status");
        assertTrue(deleted.isEmpty());
    }

    @Test
    void testLoadKeyNotFound() throws IOException {
        Optional<byte[]> result = repository.loadKey("non-existent", "file");
        assertTrue(result.isEmpty());
    }

    @Test
    void testExists() throws IOException {
        String keyId = "exist-key";
        assertFalse(repository.exists(keyId));
        
        Files.createDirectories(tempDir.resolve(keyId));
        assertTrue(repository.exists(keyId));
    }

    @Test
    void testListKeys() throws IOException {
        Files.createDirectories(tempDir.resolve("key-1"));
        Files.createDirectories(tempDir.resolve("key-2"));
        Files.createDirectories(tempDir.resolve("other-3")); 
        Files.createFile(tempDir.resolve("file-not-dir"));

        List<String> allKeys = repository.listKeys(null);
        assertEquals(3, allKeys.size());
        
        List<String> prefixKeys = repository.listKeys("key-");
        assertEquals(2, prefixKeys.size());
    }

    @Test
    void testListKeysNoBaseDir() throws IOException {
        Path missingDir = tempDir.resolve("missing");
        FileSystemKeyRepository repo = new FileSystemKeyRepository(missingDir);
        Files.delete(missingDir); 
        
        List<String> keys = repo.listKeys(null);
        assertTrue(keys.isEmpty());
    }

    @Test
    void testDelete() throws IOException {
        String keyId = "del-key";
        Path keyDir = tempDir.resolve(keyId);
        Files.createDirectories(keyDir);
        Files.writeString(keyDir.resolve("file.txt"), "content");
        Files.createDirectories(keyDir.resolve("subdir"));
        Files.writeString(keyDir.resolve("subdir/subfile.txt"), "sub-content");

        repository.delete(keyId);

        assertFalse(Files.exists(keyDir));
    }
    
    @Test
    void testDeleteNonExistent() throws IOException {
        assertDoesNotThrow(() -> repository.delete("non-existent"));
    }

    @Test
    void testSaveKeyVersionAtomicMoveFallback() throws IOException {
        String keyId = "fallback-key";
        KeyVersionData data = KeyVersionData.builder()
                .keyId(keyId)
                .files(Map.of("test", "data".getBytes()))
                .build();

        Path targetDir = tempDir.resolve(keyId);
        Files.createDirectories(targetDir);

        try (MockedStatic<Files> filesMock = mockStatic(Files.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
            filesMock.when(() -> Files.move(any(), any(), eq(StandardCopyOption.ATOMIC_MOVE)))
                    .thenThrow(new IOException("Atomic move failed"));

            repository.saveKeyVersion(data);
            assertTrue(Files.exists(targetDir.resolve("test")));
        }
    }

    @Test
    void testSaveKeyVersionRollback() throws IOException {
        String keyId = "rollback-key";
        KeyVersionData data = KeyVersionData.builder()
                .keyId(keyId)
                .files(Map.of("test", "data".getBytes()))
                .build();

        Path targetDir = tempDir.resolve(keyId);
        Files.createDirectories(targetDir);
        Files.writeString(targetDir.resolve("old.txt"), "old");

        try (MockedStatic<Files> filesMock = mockStatic(Files.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
            filesMock.when(() -> Files.move(any(), any(), any()))
                    .thenAnswer(invocation -> {
                        Path source = invocation.getArgument(0);
                        if (source.getFileName().toString().startsWith(".temp_")) {
                            throw new IOException("Simulated move failure");
                        }
                        return invocation.callRealMethod();
                    });

            assertThrows(IOException.class, () -> repository.saveKeyVersion(data));
            assertTrue(Files.exists(targetDir));
            assertTrue(Files.exists(targetDir.resolve("old.txt")));
        }
    }
    
    @Test
    void testSaveKeyVersionRollbackFailure() throws IOException {
        String keyId = "rollback-fail-key";
        KeyVersionData data = KeyVersionData.builder()
                .keyId(keyId)
                .files(Map.of("test", "data".getBytes()))
                .build();

        Path targetDir = tempDir.resolve(keyId);
        Files.createDirectories(targetDir);
        Files.writeString(targetDir.resolve("old.txt"), "old");

        try (MockedStatic<Files> filesMock = mockStatic(Files.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
            filesMock.when(() -> Files.move(any(), any(), any()))
                    .thenAnswer(invocation -> {
                        Path source = invocation.getArgument(0);
                        if (source.getFileName().toString().startsWith(".temp_")) {
                            throw new IOException("Simulated move failure");
                        }
                        if (source.getFileName().toString().startsWith(".backup_")) {
                            throw new IOException("Simulated rollback failure");
                        }
                        return invocation.callRealMethod();
                    });

            assertThrows(IOException.class, () -> repository.saveKeyVersion(data));
            assertFalse(Files.exists(targetDir));
        }
    }
    
    @Test
    void testEnsureDirExists_ConcurrentCreation() {
        Path dir = tempDir.resolve("concurrent");
        try (MockedStatic<Files> filesMock = mockStatic(Files.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
            // Use answer to return false first, then true
            filesMock.when(() -> Files.exists(dir))
                .thenAnswer(inv -> {
                    // We can check if createDirectories was called? 
                    // Or just use a sequence of return values if we know the order of calls.
                    // 1. ensureDirExists -> !exists(dir) -> returns false
                    // 2. createDirectories throws
                    // 3. catch block -> !exists(dir) -> returns true (concurrently created)
                    return false;
                })
                .thenAnswer(inv -> true); 

            // However, subsequent calls in test (setUp/etc) might use Files.exists too.
            // Better to match the specific argument.
            
            // Re-define mock behavior strictly for this method
            // Note: Consecutive stubbing
            filesMock.when(() -> Files.exists(dir)).thenReturn(false, true);
            filesMock.when(() -> Files.isDirectory(dir)).thenReturn(true);
            
            filesMock.when(() -> Files.createDirectories(dir)).thenThrow(new IOException("Simulated concurrency"));
            
            assertDoesNotThrow(() -> new FileSystemKeyRepository(dir));
        }
    }

    @Test
    void testEnsureDirExists_Failure() {
        Path dir = tempDir.resolve("fail");
        try (MockedStatic<Files> filesMock = mockStatic(Files.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
            // 1. !exists -> false
            // 2. createDirectories throws
            // 3. !exists -> false (still missing)
            filesMock.when(() -> Files.exists(dir)).thenReturn(false, false);
            filesMock.when(() -> Files.createDirectories(dir)).thenThrow(new IOException("Simulated failure"));
            
            assertThrows(java.io.UncheckedIOException.class, () -> new FileSystemKeyRepository(dir));
        }
    }

    @Test
    void testDelete_Failure() throws IOException {
        String keyId = "del-fail";
        Path keyDir = tempDir.resolve(keyId);
        Files.createDirectories(keyDir);
        Path file = keyDir.resolve("file");
        Files.createFile(file);
        
        try (MockedStatic<Files> filesMock = mockStatic(Files.class, org.mockito.Mockito.CALLS_REAL_METHODS)) {
            // Mock delete to throw exception for the file
            filesMock.when(() -> Files.delete(file)).thenThrow(new IOException("Delete failed"));
            
            // Should catch exception and log warn, but not throw
            assertDoesNotThrow(() -> repository.delete(keyId));
        }
    }
}
