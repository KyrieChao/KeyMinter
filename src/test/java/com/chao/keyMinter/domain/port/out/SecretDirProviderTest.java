package com.chao.keyMinter.domain.port.out;

import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.Test;
import org.mockito.MockedConstruction;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.nio.channels.FileChannel;
import java.nio.channels.FileLock;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.assertDoesNotThrow;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;

class SecretDirProviderTest {

    private final Path originalBaseDir = SecretDirProvider.getDefaultBaseDir();

    @AfterEach
    void tearDown() {
        SecretDirProvider.setDefaultBaseDir(originalBaseDir);
    }

    @Test
    void cleanupOrphanLockFiles_should_return_when_base_is_null() throws Exception {
        setDefaultBaseDirUnsafe(null);
        assertDoesNotThrow(SecretDirProviderTest::invokeCleanupOrphanLockFiles);
    }

    @Test
    void cleanupOrphanLockFiles_should_return_when_base_not_exists() throws Exception {
        Path base = Path.of("base");
        SecretDirProvider.setDefaultBaseDir(base);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(base)).thenReturn(false);

            invokeCleanupOrphanLockFiles();

            files.verify(() -> Files.isDirectory(any()), never());
            files.verify(() -> Files.list(any()), never());
        }
    }

    @Test
    void cleanupOrphanLockFiles_should_return_when_base_not_directory() throws Exception {
        Path base = Path.of("base");
        SecretDirProvider.setDefaultBaseDir(base);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(base)).thenReturn(true);
            files.when(() -> Files.isDirectory(base)).thenReturn(false);

            invokeCleanupOrphanLockFiles();

            files.verify(() -> Files.list(any()), never());
        }
    }
    @Test
    void test() {
        SecretDirProvider.setDefaultBaseDir(null);
    }

    @Test
    void cleanupOrphanLockFiles_should_swallow_when_list_throws() throws Exception {
        Path base = Path.of("base");
        SecretDirProvider.setDefaultBaseDir(base);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(base)).thenReturn(true);
            files.when(() -> Files.isDirectory(base)).thenReturn(true);
            files.when(() -> Files.list(base)).thenThrow(new IOException("boom"));

            assertDoesNotThrow(SecretDirProviderTest::invokeCleanupOrphanLockFiles);
        }
    }

    @Test
    void cleanupOrphanLockFiles_should_delete_lock_when_tryLock_returns_non_null() throws Exception {
        Path base = Path.of("base");
        Path dir = Path.of("base", "d1");
        Path lock = dir.resolve(".rotation.lock");
        SecretDirProvider.setDefaultBaseDir(base);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(base)).thenReturn(true);
            files.when(() -> Files.isDirectory(base)).thenReturn(true);
            files.when(() -> Files.list(base)).thenReturn(Stream.of(dir));

            files.when(() -> Files.isDirectory(dir)).thenReturn(true);
            files.when(() -> Files.exists(lock)).thenReturn(true);
            files.when(() -> Files.deleteIfExists(lock)).thenReturn(true);

            try (MockedConstruction<RandomAccessFile> rafs = Mockito.mockConstruction(RandomAccessFile.class, (raf, context) -> {
                FileChannel channel = Mockito.mock(FileChannel.class);
                FileLock fileLock = Mockito.mock(FileLock.class);
                Mockito.when(raf.getChannel()).thenReturn(channel);
                Mockito.when(channel.tryLock()).thenReturn(fileLock);
            })) {
                invokeCleanupOrphanLockFiles();

                files.verify(() -> Files.deleteIfExists(lock), times(1));
                org.junit.jupiter.api.Assertions.assertEquals(1, rafs.constructed().size());
            }
        }
    }

    @Test
    void cleanupOrphanLockFiles_should_not_delete_lock_when_tryLock_returns_null() throws Exception {
        Path base = Path.of("base");
        Path dir = Path.of("base", "d1");
        Path lock = dir.resolve(".rotation.lock");
        SecretDirProvider.setDefaultBaseDir(base);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(base)).thenReturn(true);
            files.when(() -> Files.isDirectory(base)).thenReturn(true);
            files.when(() -> Files.list(base)).thenReturn(Stream.of(dir));

            files.when(() -> Files.isDirectory(dir)).thenReturn(true);
            files.when(() -> Files.exists(lock)).thenReturn(true);

            try (MockedConstruction<RandomAccessFile> rafs = Mockito.mockConstruction(RandomAccessFile.class, (raf, context) -> {
                FileChannel channel = Mockito.mock(FileChannel.class);
                Mockito.when(raf.getChannel()).thenReturn(channel);
                Mockito.when(channel.tryLock()).thenReturn(null);
            })) {
                invokeCleanupOrphanLockFiles();

                files.verify(() -> Files.deleteIfExists(any()), never());
                org.junit.jupiter.api.Assertions.assertEquals(1, rafs.constructed().size());
            }
        }
    }

    @Test
    void cleanupOrphanLockFiles_should_swallow_when_delete_throws_ioexception() throws Exception {
        Path base = Path.of("base");
        Path dir = Path.of("base", "d1");
        Path lock = dir.resolve(".rotation.lock");
        SecretDirProvider.setDefaultBaseDir(base);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(base)).thenReturn(true);
            files.when(() -> Files.isDirectory(base)).thenReturn(true);
            files.when(() -> Files.list(base)).thenReturn(Stream.of(dir));

            files.when(() -> Files.isDirectory(dir)).thenReturn(true);
            files.when(() -> Files.exists(lock)).thenReturn(true);
            files.when(() -> Files.deleteIfExists(lock)).thenThrow(new IOException("io"));

            try (MockedConstruction<RandomAccessFile> rafs = Mockito.mockConstruction(RandomAccessFile.class, (raf, context) -> {
                FileChannel channel = Mockito.mock(FileChannel.class);
                FileLock fileLock = Mockito.mock(FileLock.class);
                Mockito.when(raf.getChannel()).thenReturn(channel);
                Mockito.when(channel.tryLock()).thenReturn(fileLock);
            })) {
                assertDoesNotThrow(SecretDirProviderTest::invokeCleanupOrphanLockFiles);
                org.junit.jupiter.api.Assertions.assertEquals(1, rafs.constructed().size());
            }
        }
    }

    @Test
    void cleanupOrphanLockFiles_should_swallow_when_tryLock_throws_ioexception() throws Exception {
        Path base = Path.of("base");
        Path dir = Path.of("base", "d1");
        Path lock = dir.resolve(".rotation.lock");
        SecretDirProvider.setDefaultBaseDir(base);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class)) {
            files.when(() -> Files.exists(base)).thenReturn(true);
            files.when(() -> Files.isDirectory(base)).thenReturn(true);
            files.when(() -> Files.list(base)).thenReturn(Stream.of(dir));

            files.when(() -> Files.isDirectory(dir)).thenReturn(true);
            files.when(() -> Files.exists(lock)).thenReturn(true);

            try (MockedConstruction<RandomAccessFile> rafs = Mockito.mockConstruction(RandomAccessFile.class, (raf, context) -> {
                FileChannel channel = Mockito.mock(FileChannel.class);
                Mockito.when(raf.getChannel()).thenReturn(channel);
                Mockito.when(channel.tryLock()).thenThrow(new IOException("io"));
            })) {
                assertDoesNotThrow(SecretDirProviderTest::invokeCleanupOrphanLockFiles);
                org.junit.jupiter.api.Assertions.assertEquals(1, rafs.constructed().size());
            }
        }
    }

    private static void invokeCleanupOrphanLockFiles() throws Exception {
        Method m = SecretDirProvider.class.getDeclaredMethod("cleanupOrphanLockFiles");
        m.setAccessible(true);
        m.invoke(null);
    }

    private static void setDefaultBaseDirUnsafe(Path baseDir) throws Exception {
        Field f = SecretDirProvider.class.getDeclaredField("DEFAULT_BASE_DIR");
        f.setAccessible(true);
        f.set(null, baseDir);
    }
}
