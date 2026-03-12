package com.chao.keyminter.domain.port.out;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

@Slf4j
public final class SecretDirProvider {
    private static volatile Path DEFAULT_BASE_DIR = Paths.get(System.getProperty("user.home"), ".chao");

    static {
        cleanupOrphanLockFiles();
    }

    private SecretDirProvider() {
    }

    public static Path getDefaultBaseDir() {
        return DEFAULT_BASE_DIR;
    }

    public static void setDefaultBaseDir(Path baseDir) {
        if (baseDir != null) {
            log.info("Setting default base directory to {}", baseDir);
            DEFAULT_BASE_DIR = baseDir.normalize();
        }
    }

    private static void cleanupOrphanLockFiles() {
        Path base = getDefaultBaseDir();
        if (base == null || !Files.exists(base) || !Files.isDirectory(base)) {
            return;
        }
        try (var s = Files.list(base)) {
            s.filter(Files::isDirectory)
                    .map(p -> p.resolve(".rotation.lock"))
                    .filter(Files::exists)
                    .forEach(lock -> {
                        try {
                            try (RandomAccessFile raf = new RandomAccessFile(lock.toFile(), "rw");
                                 FileLock l = raf.getChannel().tryLock()) {
                                if (l != null) {
                                    Files.deleteIfExists(lock);
                                    log.info("Deleted orphan lock file: {}", lock);
                                }
                            }
                        } catch (IOException e) {
                            log.error("Cannot delete lock {}, probably in use: {}", lock, e.getMessage());
                        }
                    });
        } catch (IOException e) {
            log.error("Failed to list base dir for orphan locks", e);
        }
    }
}
