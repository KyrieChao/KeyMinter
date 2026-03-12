package com.chao.keyMinter.adapter.out.fs;

import com.chao.keyMinter.domain.model.KeyVersionData;
import com.chao.keyMinter.domain.port.out.KeyRepository;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.UncheckedIOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.stream.Collectors;
import java.util.stream.Stream;

/**
 * File System based Key Repository (Adapter)
 * Corresponds to Driven Adapter in Hexagonal Architecture
 */
@Slf4j
public class FileSystemKeyRepository implements KeyRepository {

    private final Path baseDir;

    public FileSystemKeyRepository(Path baseDir) {
        this.baseDir = baseDir;
        ensureDirExists(baseDir);
    }

    private void ensureDirExists(Path dir) {
        if (Files.exists(dir)) {
            if (!Files.isDirectory(dir)) {
                throw new UncheckedIOException(new IOException("Path exists but is not a directory: " + dir));
            }
        } else {
            try {
                Files.createDirectories(dir);
            } catch (IOException e) {
                // Ignore exception if directory created concurrently
                if (!Files.exists(dir) || !Files.isDirectory(dir)) {
                     throw new UncheckedIOException("Failed to create base directory: " + dir, e);
                }
            }
        }
    }

    @Override
    public void saveKeyVersion(KeyVersionData data) throws IOException {
        Path tempDir = baseDir.resolve(".temp_" + data.getKeyId() + "_" + System.nanoTime());
        Path targetDir = baseDir.resolve(data.getKeyId());
        Path backupDir = baseDir.resolve(".backup_" + data.getKeyId() + "_" + System.nanoTime());

        try {
            Files.createDirectories(tempDir);
            for (Map.Entry<String, byte[]> entry : data.getFiles().entrySet()) {
                Files.write(tempDir.resolve(entry.getKey()), entry.getValue());
            }

            // Strategy:
            // 1. If target doesn't exist, just move temp -> target
            // 2. If target exists, move target -> backup, then temp -> target, then delete backup
            // Note: Direct replace of non-empty directory is not supported on all FS (e.g. Windows)
            
            if (Files.exists(targetDir)) {
                try {
                    Files.move(targetDir, backupDir, StandardCopyOption.ATOMIC_MOVE);
                } catch (IOException e) {
                    Files.move(targetDir, backupDir, StandardCopyOption.REPLACE_EXISTING);
                }
            }
            
            try {
                Files.move(tempDir, targetDir, StandardCopyOption.ATOMIC_MOVE);
            } catch (IOException e) {
                Files.move(tempDir, targetDir, StandardCopyOption.REPLACE_EXISTING);
            }
            
        } catch (Exception e) {
            if (Files.exists(backupDir) && !Files.exists(targetDir)) {
                try {
                    Files.move(backupDir, targetDir, StandardCopyOption.ATOMIC_MOVE);
                } catch (IOException restoreEx) {
                    log.error("Failed to restore backup for key {}", data.getKeyId(), restoreEx);
                }
            }
            throw new IOException("Failed to save key version for " + data.getKeyId(), e);
        } finally {
            if (Files.exists(tempDir)) {
                deleteDir(tempDir);
            }
            if (Files.exists(backupDir)) {
                deleteDir(backupDir);
            }
        }
    }

    private void deleteDir(Path dir) throws IOException {
        try (Stream<Path> walk = Files.walk(dir)) {
            walk.sorted((a, b) -> -a.compareTo(b))
                    .forEach(p -> {
                        try {
                            Files.delete(p);
                        } catch (IOException e) {
                            log.warn("Failed to delete temp {}: {}", p, e.getMessage());
                        }
                    });
        }
    }

    @Override
    public void saveKey(String keyId, String fileName, byte[] content) throws IOException {
        Path keyDir = baseDir.resolve(keyId);
        if (!Files.exists(keyDir)) {
            Files.createDirectories(keyDir);
        }
        Path keyFile = keyDir.resolve(fileName);
        Files.write(keyFile, content);
    }

    @Override
    public Optional<byte[]> loadKey(String keyId, String fileName) throws IOException {
        Path keyFile = baseDir.resolve(keyId).resolve(fileName);
        if (Files.exists(keyFile)) {
            return Optional.of(Files.readAllBytes(keyFile));
        }
        return Optional.empty();
    }

    @Override
    public void delete(String keyId) throws IOException {
        Path keyDir = baseDir.resolve(keyId);
        if (Files.exists(keyDir)) {
            try (Stream<Path> walk = Files.walk(keyDir)) {
                walk.sorted((a, b) -> -a.compareTo(b))
                        .forEach(p -> {
                            try {
                                Files.delete(p);
                            } catch (IOException e) {
                                log.warn("Failed to delete {}: {}", p, e.getMessage());
                            }
                        });
            }
        }
    }

    @Override
    public boolean exists(String keyId) {
        return Files.exists(baseDir.resolve(keyId));
    }

    @Override
    public List<String> listKeys(String prefix) throws IOException {
        if (!Files.exists(baseDir)) {
            return Collections.emptyList();
        }
        
        try (Stream<Path> stream = Files.list(baseDir)) {
            return stream.filter(Files::isDirectory)
                    .map(p -> p.getFileName().toString())
                    .filter(name -> prefix == null || name.startsWith(prefix))
                    .collect(Collectors.toList());
        }
    }

    @Override
    public void saveMetadata(String keyId, String metaKey, String content) throws IOException {
        saveKey(keyId, metaKey, content.getBytes(StandardCharsets.UTF_8));
    }

    @Override
    public Optional<String> loadMetadata(String keyId, String metaKey) throws IOException {
        return loadKey(keyId, metaKey).map(bytes -> new String(bytes, StandardCharsets.UTF_8));
    }

    @Override
    public void deleteMetadata(String keyId, String metaKey) throws IOException {
        Path metaFile = baseDir.resolve(keyId).resolve(metaKey);
        Files.deleteIfExists(metaFile);
    }
}
