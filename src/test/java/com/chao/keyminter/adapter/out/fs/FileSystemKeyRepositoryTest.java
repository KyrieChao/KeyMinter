package com.chao.keyminter.adapter.out.fs;

import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.model.KeyVersionData;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Optional;

import static org.junit.jupiter.api.Assertions.*;

class FileSystemKeyRepositoryTest {

    @TempDir
    Path tempDir;

    private FileSystemKeyRepository repository;

    @BeforeEach
    void setUp() {
        repository = new FileSystemKeyRepository(tempDir);
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

        // Verify files exist
        Path keyDir = tempDir.resolve(keyId);
        assertTrue(Files.exists(keyDir));
        assertTrue(Files.exists(keyDir.resolve("secret.key")));
        assertTrue(Files.exists(keyDir.resolve("meta.info")));

        // Load key
        Optional<byte[]> loadedSecret = repository.loadKey(keyId, "secret.key");
        assertTrue(loadedSecret.isPresent());
        assertArrayEquals("secret-data".getBytes(StandardCharsets.UTF_8), loadedSecret.get());
    }

    @Test
    void testMetadataOperations() throws IOException {
        String keyId = "meta-key";
        Files.createDirectories(tempDir.resolve(keyId));

        repository.saveMetadata(keyId, "status", "ACTIVE");

        Optional<String> status = repository.loadMetadata(keyId, "status");
        assertTrue(status.isPresent());
        assertEquals("ACTIVE", status.get());
    }

    @Test
    void testListKeys() throws IOException {
        Files.createDirectories(tempDir.resolve("key1"));
        Files.createDirectories(tempDir.resolve("key2"));
        Files.createDirectories(tempDir.resolve("other")); // Should also be listed if it's a dir

        List<String> keys = repository.listKeys(null);
        assertTrue(keys.contains("key1"));
        assertTrue(keys.contains("key2"));
        assertTrue(keys.contains("other"));
    }

    @Test
    void testDelete() throws IOException {
        String keyId = "del-key";
        Path keyDir = tempDir.resolve(keyId);
        Files.createDirectories(keyDir);
        Files.writeString(keyDir.resolve("file.txt"), "content");

        repository.delete(keyId);

        assertFalse(Files.exists(keyDir));
    }
}
