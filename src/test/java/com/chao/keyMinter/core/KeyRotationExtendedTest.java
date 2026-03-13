package com.chao.keyMinter.core;

import com.chao.keyMinter.domain.port.out.LockProvider;
import com.chao.keyMinter.domain.port.out.PermissionStrategy;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.mockito.MockedStatic;
import org.mockito.Mockito;

import sun.misc.Unsafe;

import java.io.IOException;
import java.lang.reflect.Field;
import java.lang.reflect.Method;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.channels.FileChannel;
import java.nio.file.AccessDeniedException;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.FileSystem;
import java.nio.file.FileSystems;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.StandardCopyOption;
import java.nio.file.StandardOpenOption;
import java.nio.file.attribute.AclFileAttributeView;
import java.nio.file.attribute.PosixFileAttributeView;
import java.nio.file.attribute.UserPrincipal;
import java.util.List;
import java.util.Set;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Lock;
import java.util.stream.Stream;

import static org.junit.jupiter.api.Assertions.*;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyLong;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.*;

class KeyRotationExtendedTest {

    @TempDir
    Path tempDir;

    private String originalOsName;

    @BeforeEach
    void setUp() {
        originalOsName = System.getProperty("os.name");
        KeyRotation.setLockProvider(null);
    }

    @AfterEach
    void tearDown() {
        System.setProperty("os.name", originalOsName);
        KeyRotation.setLockProvider(null);
        Thread.interrupted();
    }

    @Test
    void static_init_should_cover_posix_permission_strategy_in_separate_classloader() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Linux");
            URL classesUrl = Path.of("target", "classes").toUri().toURL();
            URL testClassesUrl = Path.of("target", "test-classes").toUri().toURL();
            try (ChildFirstForKeyRotation loader = new ChildFirstForKeyRotation(new URL[]{testClassesUrl, classesUrl}, getClass().getClassLoader())) {
                Class<?> cls = Class.forName("com.chao.keyMinter.core.KeyRotation", true, loader);
                Field f = cls.getDeclaredField("permissionStrategy");
                f.setAccessible(true);
                Object strategy = f.get(null);
                assertTrue(strategy.getClass().getName().endsWith("PosixPermissionStrategy"));
            }
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void constructor_should_be_covered() {
        assertNotNull(new KeyRotation());
    }

    @Test
    void rotateKeyAtomic_should_return_false_when_distributed_lock_not_acquired() throws Exception {
        LockProvider provider = mock(LockProvider.class);
        Lock lock = mock(Lock.class);
        when(provider.getLock(anyString())).thenReturn(lock);
        when(lock.tryLock(anyLong(), any())).thenReturn(false);
        KeyRotation.setLockProvider(provider);

        boolean result = KeyRotation.rotateKeyAtomic(
                "k",
                tempDir.resolve("keys"),
                () -> "v",
                (v, d) -> Files.writeString(d.resolve("key.txt"), v),
                v -> {
                }
        );

        assertFalse(result);
        verify(lock, never()).unlock();
    }

    @Test
    void rotateKeyAtomic_should_return_false_when_distributed_lock_interrupted() throws Exception {
        LockProvider provider = mock(LockProvider.class);
        Lock lock = mock(Lock.class);
        when(provider.getLock(anyString())).thenReturn(lock);
        when(lock.tryLock(anyLong(), any())).thenThrow(new InterruptedException("i"));
        KeyRotation.setLockProvider(provider);

        boolean result = KeyRotation.rotateKeyAtomic(
                "k",
                tempDir.resolve("keys2"),
                () -> "v",
                (v, d) -> Files.writeString(d.resolve("key.txt"), v),
                v -> {
                }
        );

        assertFalse(result);
        assertTrue(Thread.currentThread().isInterrupted());
    }

    @Test
    void rotateKeyAtomic_should_swallow_unlock_exception() throws Exception {
        LockProvider provider = mock(LockProvider.class);
        Lock lock = mock(Lock.class);
        when(provider.getLock(anyString())).thenReturn(lock);
        when(lock.tryLock(anyLong(), any())).thenReturn(true);
        doThrow(new RuntimeException("unlock")).when(lock).unlock();
        KeyRotation.setLockProvider(provider);

        boolean result = KeyRotation.rotateKeyAtomic(
                "k",
                tempDir.resolve("keys3"),
                () -> "v",
                (v, d) -> Files.writeString(d.resolve("key.txt"), v),
                v -> {
                }
        );

        assertTrue(result);
    }

    @Test
    void rotateKeyAtomic_should_return_false_when_file_lock_cannot_be_acquired() throws Exception {
        Path keyDirAsFile = tempDir.resolve("not-dir");
        Files.writeString(keyDirAsFile, "x");

        boolean result = KeyRotation.rotateKeyAtomic(
                "k",
                keyDirAsFile,
                () -> "v",
                (v, d) -> Files.writeString(d.resolve("key.txt"), v),
                v -> {
                }
        );

        assertFalse(result);
    }

    @Test
    void doRotateWithBackup_should_restore_old_target_when_memory_update_fails() throws Exception {
        String keyId = "k1";
        Path keyDir = tempDir.resolve("keys");

        assertTrue(KeyRotation.rotateKeyAtomic(
                keyId,
                keyDir,
                () -> "old",
                (v, d) -> Files.writeString(d.resolve("key.txt"), v),
                v -> {
                }
        ));

        assertEquals("old", Files.readString(keyDir.resolve(keyId).resolve("key.txt")));

        boolean result = KeyRotation.rotateKeyAtomic(
                keyId,
                keyDir,
                () -> "new",
                (v, d) -> Files.writeString(d.resolve("key.txt"), v),
                v -> {
                    throw new RuntimeException("boom");
                }
        );

        assertFalse(result);
        assertEquals("old", Files.readString(keyDir.resolve(keyId).resolve("key.txt")));
        assertTrue(Files.exists(keyDir.resolve(keyId + ".backup")));
    }

    @Test
    void doRotateWithBackup_should_cover_permission_strategy_exception_catch() throws Exception {
        Path keyDir = tempDir.resolve("keys-perm");
        String keyId = "k2";

        PermissionStrategy original = (PermissionStrategy) getStaticField(KeyRotation.class, "permissionStrategy");
        PermissionStrategy mockStrategy = mock(PermissionStrategy.class);
        doThrow(new IOException("io")).when(mockStrategy).setRestrictivePermissions(any(Path.class));
        setStaticFinalField(KeyRotation.class, "permissionStrategy", mockStrategy);
        try {
            assertTrue(KeyRotation.rotateKeyAtomic(
                    keyId,
                    keyDir,
                    () -> "v",
                    (v, d) -> Files.writeString(d.resolve("key.txt"), v),
                    v -> {
                    }
            ));
            assertEquals("v", Files.readString(keyDir.resolve(keyId).resolve("key.txt")));
        } finally {
            setStaticFinalField(KeyRotation.class, "permissionStrategy", original);
        }
    }

    @Test
    void writeVersionMetadata_should_throw_unchecked_ioexception_on_failure() {
        Path dir = tempDir.resolve("meta");
        assertDoesNotThrow(() -> Files.createDirectories(dir));

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.writeString(any(Path.class), anyString())).thenThrow(new RuntimeException("x"));
            assertThrows(java.io.UncheckedIOException.class, () -> invokeWriteVersionMetadata(dir, "kid"));
        }
    }

    @Test
    void createTempKeyDir_should_cover_retry_sleep_interrupted_path() {
        Path parent = tempDir.resolve("p");
        assertDoesNotThrow(() -> Files.createDirectories(parent));
        Thread.currentThread().interrupt();
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.createDirectories(any(Path.class))).thenThrow(new IOException("io"));
            assertThrows(IOException.class, () -> invokeCreateTempKeyDir(parent, "kid"));
        }
    }

    @Test
    void createTempKeyDir_should_cover_exhausted_retries() throws Exception {
        Path parent = tempDir.resolve("parent");
        Files.createDirectories(parent);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.createDirectories(any(Path.class))).thenThrow(new IOException("io"));
            assertThrows(IOException.class, () -> invokeCreateTempKeyDir(parent, "kid"));
        }
    }

    @Test
    void createTempKeyDir_should_create_parent_dir_when_missing() throws Exception {
        Path parent = tempDir.resolve("missing-parent");
        assertFalse(Files.exists(parent));

        PermissionStrategy original = (PermissionStrategy) getStaticField(KeyRotation.class, "permissionStrategy");
        PermissionStrategy noOp = new PermissionStrategy() {
            @Override
            public void setRestrictivePermissions(Path path) {
            }

            @Override
            public void ensureAccessible(Path dir) {
            }
        };
        setStaticFinalField(KeyRotation.class, "permissionStrategy", noOp);
        try {
            Path created = invokeCreateTempKeyDir(parent, "kid");
            assertTrue(Files.exists(parent));
            assertEquals(parent, created.getParent());
            assertTrue(created.getFileName().toString().startsWith(".tmp-kid-"));
        } finally {
            setStaticFinalField(KeyRotation.class, "permissionStrategy", original);
        }
    }

    @Test
    void waitForDirectoryExists_should_cover_list_ioexception_and_interrupt() {
        Path d = tempDir.resolve("w");
        assertDoesNotThrow(() -> Files.createDirectories(d));
        Thread.currentThread().interrupt();
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.exists(eq(d))).thenReturn(true);
            files.when(() -> Files.isDirectory(eq(d))).thenReturn(true);
            files.when(() -> Files.list(eq(d))).thenThrow(new IOException("io"));
            assertFalse(invokeWaitForDirectoryExists(d));
        }
    }

    @Test
    void tryDeleteIfExists_should_cover_null_and_exception_paths() {
        assertDoesNotThrow(() -> invokeTryDeleteIfExists(null));
        Path p = tempDir.resolve("x");
        assertDoesNotThrow(() -> Files.createDirectories(p));
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.exists(eq(p))).thenThrow(new RuntimeException("boom"));
            assertDoesNotThrow(() -> invokeTryDeleteIfExists(p));
        }
    }

    @Test
    void tryDeleteIfExists_should_delete_existing_path() throws Exception {
        Path p = Files.createDirectories(tempDir.resolve("delme"));
        Files.writeString(p.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        invokeTryDeleteIfExists(p);
        assertFalse(Files.exists(p));
    }

    @Test
    void waitForDirectoryExists_should_cover_exists_false_branch() {
        Path d = tempDir.resolve("missing-wait");
        Thread.currentThread().interrupt();
        assertFalse(invokeWaitForDirectoryExists(d));
    }

    @Test
    void waitForDirectoryExists_should_cover_is_directory_false_branch() throws Exception {
        Path f = tempDir.resolve("file");
        Files.writeString(f, "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Thread.currentThread().interrupt();
        assertFalse(invokeWaitForDirectoryExists(f));
    }

    @Test
    void createTempKeyDir_should_cover_wait_false_branch_and_retry_path() {
        Path parent = tempDir.resolve("p2");
        assertDoesNotThrow(() -> Files.createDirectories(parent));
        Object original = null;
        try {
            Field f = KeyRotation.class.getDeclaredField("permissionStrategy");
            f.setAccessible(true);
            original = f.get(null);
            PermissionStrategy noOp = new PermissionStrategy() {
                @Override
                public void setRestrictivePermissions(Path path) {
                }

                @Override
                public void ensureAccessible(Path dir) {
                }
            };
            setStaticFinalField(KeyRotation.class, "permissionStrategy", noOp);

            try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                files.when(() -> Files.exists(any(Path.class))).thenReturn(true);
                files.when(() -> Files.isDirectory(any(Path.class))).thenReturn(true);
                files.when(() -> Files.list(Mockito.<Path>any())).thenThrow(new IOException("io"));
                Thread.currentThread().interrupt();
                assertThrows(IOException.class, () -> invokeCreateTempKeyDir(parent, "kid"));
            }
        } catch (Exception e) {
            throw new RuntimeException(e);
        } finally {
            if (original != null) {
                try {
                    setStaticFinalField(KeyRotation.class, "permissionStrategy", original);
                } catch (Exception ignored) {
                }
            }
        }
    }

    @Test
    void moveTempToTarget_should_cover_atomic_move_success_and_non_windows_branch() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Linux");
            Path parent = tempDir.resolve("mv");
            Files.createDirectories(parent);
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Path target = parent.resolve("target");
            invokeMoveTempToTarget(temp, target);
            assertTrue(Files.exists(target.resolve("a.txt")));
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_create_missing_parent_directories() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Linux");
            Path temp = Files.createDirectories(tempDir.resolve("mv-parent").resolve("temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Path target = tempDir.resolve("mv-parent").resolve("missing").resolve("target");
            invokeMoveTempToTarget(temp, target);
            assertTrue(Files.exists(target.resolve("a.txt")));
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_cover_null_parent_dir_branch() throws Exception {
        String prev = System.getProperty("os.name");
        Path target = Path.of("tmp-noparent-" + System.nanoTime());
        try {
            System.setProperty("os.name", "Linux");
            Path temp = Files.createDirectories(tempDir.resolve("mv-noparent-temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                files.when(() -> Files.move(eq(temp), eq(target), eq(StandardCopyOption.ATOMIC_MOVE)))
                        .thenThrow(new AtomicMoveNotSupportedException("", "", "x"));
                invokeMoveTempToTarget(temp, target);
            }

            assertTrue(Files.exists(target.resolve("a.txt")));
        } finally {
            System.setProperty("os.name", prev);
            invokeTryDeleteIfExists(target);
        }
    }

    @Test
    void moveTempToTarget_should_cover_rename_to_true_branch() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Linux");
            Path parent = Files.createDirectories(tempDir.resolve("mv-rename"));
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Path target = parent.resolve("target");

            try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                files.when(() -> Files.move(eq(temp), eq(target), eq(StandardCopyOption.ATOMIC_MOVE))).thenThrow(new AtomicMoveNotSupportedException("", "", "x"));
                files.when(() -> Files.walk(eq(temp))).thenThrow(new IOException("walk"));
                assertDoesNotThrow(() -> invokeMoveTempToTarget(temp, target));
            }
            assertTrue(Files.exists(target));
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_cover_rename_to_returned_false_throw_line() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Linux");
            Path parent = Files.createDirectories(tempDir.resolve("mv-rename-false-throw"));
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Path target = Files.createDirectories(parent.resolve("target"));
            Files.writeString(target.resolve("existing.txt"), "y", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

            try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                files.when(() -> Files.exists(eq(target))).thenReturn(false);
                files.when(() -> Files.move(eq(temp), eq(target), eq(StandardCopyOption.ATOMIC_MOVE)))
                        .thenThrow(new AtomicMoveNotSupportedException("", "", "x"));
                invokeMoveTempToTarget(temp, target);
            }

            assertTrue(Files.exists(target.resolve("a.txt")));
            assertTrue(Files.exists(target.resolve("existing.txt")));
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_cover_rename_to_false_branch_and_copy_fallback() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Linux");
            Path parent = Files.createDirectories(tempDir.resolve("mv-rename-false"));
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Path target = Files.createDirectories(parent.resolve("target"));

            Path locked = target.resolve("locked.txt");
            Files.writeString(locked, "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            try (FileChannel ch = FileChannel.open(locked, StandardOpenOption.WRITE)) {
                try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                    files.when(() -> Files.move(eq(temp), eq(target), eq(StandardCopyOption.ATOMIC_MOVE))).thenThrow(new AtomicMoveNotSupportedException("", "", "x"));
                    invokeMoveTempToTarget(temp, target);
                }
            }
            assertTrue(Files.exists(target.resolve("a.txt")));
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_cover_copy_delete_success_lines() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Linux");
            Path parent = Files.createDirectories(tempDir.resolve("mv-copy"));
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Path target = parent.resolve("target");

            Thread.currentThread().interrupt();
            try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                files.when(() -> Files.move(eq(temp), eq(target), eq(StandardCopyOption.ATOMIC_MOVE))).thenThrow(new AccessDeniedException("x"));
                invokeMoveTempToTarget(temp, target);
            }

            assertTrue(Files.exists(target.resolve("a.txt")));
            assertFalse(Files.exists(temp));
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_throw_runtime_exception_when_interrupted_during_windows_wait() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Windows");
            Path parent = Files.createDirectories(tempDir.resolve("mv-win-interrupt"));
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Path target = parent.resolve("target");
            Thread.currentThread().interrupt();
            assertThrows(RuntimeException.class, () -> invokeMoveTempToTarget(temp, target));
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_cover_atomic_move_failure_and_rename_to_success() throws Exception {
        Path parent = tempDir.resolve("mv2");
        Files.createDirectories(parent);
        Path temp = Files.createDirectories(parent.resolve("temp"));
        Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Path target = parent.resolve("target");

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.move(eq(temp), eq(target), eq(StandardCopyOption.ATOMIC_MOVE))).thenThrow(new AtomicMoveNotSupportedException("", "", "x"));
            invokeMoveTempToTarget(temp, target);
        }
        assertTrue(Files.exists(target.resolve("a.txt")));
    }

    @Test
    void moveTempToTarget_should_cover_copy_delete_fallback_success() throws Exception {
        Path parent = tempDir.resolve("mv3");
        Files.createDirectories(parent);
        Path temp = Files.createDirectories(parent.resolve("temp"));
        Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Path target = parent.resolve("target");

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.move(eq(temp), eq(target), eq(StandardCopyOption.ATOMIC_MOVE))).thenThrow(new AccessDeniedException("x"));
            invokeMoveTempToTarget(temp, target);
        }
        assertTrue(Files.exists(target.resolve("a.txt")));
    }

    @Test
    void moveTempToTarget_should_throw_when_all_move_strategies_fail() throws Exception {
        Path parent = tempDir.resolve("mv4");
        Files.createDirectories(parent);
        Path temp = Files.createDirectories(parent.resolve("temp"));
        Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Path target = parent.resolve("target");

        Thread.currentThread().interrupt();
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.move(eq(temp), eq(target), eq(StandardCopyOption.ATOMIC_MOVE))).thenThrow(new AtomicMoveNotSupportedException("", "", "x"));
            files.when(() -> Files.walk(eq(temp))).thenThrow(new IOException("walk"));
            assertThrows(IOException.class, () -> invokeMoveTempToTarget(temp, target));
        }
    }

    @Test
    void moveTempToTarget_should_cover_windows_accessibility_fix_and_throw() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Windows");
            Path parent = tempDir.resolve("mv5");
            Files.createDirectories(parent);
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Path target = parent.resolve("target");
            try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                files.when(() -> Files.list(any(Path.class))).thenThrow(new IOException("io"));
                assertThrows(IOException.class, () -> invokeMoveTempToTarget(temp, target));
            }
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_cover_windows_accessibility_fix_and_success() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Windows");
            Path parent = tempDir.resolve("mv5-success");
            Files.createDirectories(parent);
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Path target = parent.resolve("target");

            AtomicInteger calls = new AtomicInteger();
            try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                files.when(() -> Files.list(eq(target))).thenAnswer(inv -> {
                    if (calls.getAndIncrement() == 0) {
                        throw new IOException("io");
                    }
                    return Stream.empty();
                });
                assertDoesNotThrow(() -> invokeMoveTempToTarget(temp, target));
            }

            assertTrue(Files.exists(target.resolve("a.txt")));
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_cover_windows_permission_strategy_exception_catch() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Windows");
            Path parent = Files.createDirectories(tempDir.resolve("mv5b"));
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Path target = parent.resolve("target");

            PermissionStrategy original = (PermissionStrategy) getStaticField(KeyRotation.class, "permissionStrategy");
            PermissionStrategy mockStrategy = mock(PermissionStrategy.class);
            doThrow(new IOException("io")).when(mockStrategy).setRestrictivePermissions(any(Path.class));
            setStaticFinalField(KeyRotation.class, "permissionStrategy", mockStrategy);
            try {
                try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                    files.when(() -> Files.list(any(Path.class))).thenThrow(new IOException("io"));
                    assertThrows(IOException.class, () -> invokeMoveTempToTarget(temp, target));
                }
            } finally {
                setStaticFinalField(KeyRotation.class, "permissionStrategy", original);
            }
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void moveTempToTarget_should_throw_runtime_exception_when_interrupted_during_permission_fix_sleep() throws Exception {
        String prev = System.getProperty("os.name");
        try {
            System.setProperty("os.name", "Windows");
            Path parent = Files.createDirectories(tempDir.resolve("mv5c"));
            Path temp = Files.createDirectories(parent.resolve("temp"));
            Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
            Path target = parent.resolve("target");

            PermissionStrategy original = (PermissionStrategy) getStaticField(KeyRotation.class, "permissionStrategy");
            PermissionStrategy interrupting = new PermissionStrategy() {
                @Override
                public void setRestrictivePermissions(Path path) {
                    Thread.currentThread().interrupt();
                }

                @Override
                public void ensureAccessible(Path dir) {
                }
            };
            setStaticFinalField(KeyRotation.class, "permissionStrategy", interrupting);
            try {
                try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
                    files.when(() -> Files.list(any(Path.class))).thenThrow(new IOException("io"));
                    assertThrows(RuntimeException.class, () -> invokeMoveTempToTarget(temp, target));
                }
            } finally {
                setStaticFinalField(KeyRotation.class, "permissionStrategy", original);
            }
        } finally {
            System.setProperty("os.name", prev);
        }
    }

    @Test
    void isDirectoryAccessible_should_cover_both_paths() throws Exception {
        Path dir = Files.createDirectories(tempDir.resolve("acc"));
        assertFalse(invokeIsDirectoryAccessible(dir));

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.list(eq(dir))).thenThrow(new IOException("io"));
            assertTrue(invokeIsDirectoryAccessible(dir));
        }
    }

    @Test
    void copyDirectory_should_cover_success_and_unchecked_ioexception() throws Exception {
        Path src = Files.createDirectories(tempDir.resolve("src"));
        Files.writeString(src.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Path dst = tempDir.resolve("dst");

        invokeCopyDirectory(src, dst);
        assertEquals("x", Files.readString(dst.resolve("a.txt")));

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.copy(any(Path.class), any(Path.class), eq(StandardCopyOption.REPLACE_EXISTING))).thenThrow(new IOException("io"));
            assertThrows(java.io.UncheckedIOException.class, () -> invokeCopyDirectory(src, tempDir.resolve("dst2")));
        }
    }

    @Test
    void createBackup_restoreFromBackup_and_cleanupBackup_should_cover_paths() throws Exception {
        Path targetDir = Files.createDirectories(tempDir.resolve("t"));
        Files.writeString(targetDir.resolve("a.txt"), "old", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Path backupDir = tempDir.resolve("b");

        invokeCreateBackup(targetDir, backupDir);
        assertEquals("old", Files.readString(backupDir.resolve("a.txt")));

        Files.writeString(targetDir.resolve("a.txt"), "new", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        invokeRestoreFromBackup(targetDir, backupDir);
        assertEquals("old", Files.readString(targetDir.resolve("a.txt")));

        invokeCleanupBackup(backupDir);
        assertFalse(Files.exists(backupDir));

        assertDoesNotThrow(() -> invokeRestoreFromBackup(targetDir, tempDir.resolve("missing")));
    }

    @Test
    void createBackup_should_cover_existing_backup_delete_and_copy_failure() throws Exception {
        Path targetDir = Files.createDirectories(tempDir.resolve("t-exists"));
        Files.writeString(targetDir.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Path backupDir = Files.createDirectories(tempDir.resolve("b-exists"));
        Files.writeString(backupDir.resolve("old.txt"), "y", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        invokeCreateBackup(targetDir, backupDir);
        assertTrue(Files.exists(backupDir.resolve("a.txt")));

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.copy(any(Path.class), any(Path.class), any(java.nio.file.CopyOption[].class))).thenThrow(new IOException("io"));
            assertThrows(java.io.UncheckedIOException.class, () -> invokeCreateBackup(targetDir, tempDir.resolve("b-fail")));
        }
    }

    @Test
    void restoreFromBackup_should_cover_copy_failure_catch() throws Exception {
        Path targetDir = Files.createDirectories(tempDir.resolve("t2"));
        Path backupDir = Files.createDirectories(tempDir.resolve("b2"));
        Files.writeString(backupDir.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.copy(any(Path.class), any(Path.class), any(java.nio.file.CopyOption[].class))).thenThrow(new IOException("io"));
            assertDoesNotThrow(() -> invokeRestoreFromBackup(targetDir, backupDir));
        }
    }

    @Test
    void cleanupBackup_should_cover_exception_catch() throws Exception {
        Path backupDir = Files.createDirectories(tempDir.resolve("b3"));
        Files.writeString(backupDir.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.walk(eq(backupDir))).thenThrow(new IOException("io"));
            assertDoesNotThrow(() -> invokeCleanupBackup(backupDir));
        }
    }

    @Test
    void applyRestrictivePermissionsRecursively_should_cover_success_and_failures() throws Exception {
        Path dir = Files.createDirectories(tempDir.resolve("perm"));
        Files.writeString(dir.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        assertDoesNotThrow(() -> invokeApplyRestrictivePermissionsRecursively(dir));

        PermissionStrategy original = (PermissionStrategy) getStaticField(KeyRotation.class, "permissionStrategy");
        PermissionStrategy mockStrategy = mock(PermissionStrategy.class);
        doThrow(new IOException("io")).when(mockStrategy).setRestrictivePermissions(any(Path.class));
        setStaticFinalField(KeyRotation.class, "permissionStrategy", mockStrategy);
        try {
            assertThrows(java.io.UncheckedIOException.class, () -> invokeApplyRestrictivePermissionsRecursively(dir));
        } finally {
            setStaticFinalField(KeyRotation.class, "permissionStrategy", original);
        }

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.walk(eq(dir))).thenThrow(new IOException("io"));
            assertThrows(java.io.UncheckedIOException.class, () -> invokeApplyRestrictivePermissionsRecursively(dir));
        }
    }

    @Test
    void applyRestrictivePermissions_should_cover_posix_and_acl_branches() throws Exception {
        Path p = Files.createDirectories(tempDir.resolve("perm2"));

        FileSystem posixFs = mock(FileSystem.class);
        when(posixFs.supportedFileAttributeViews()).thenReturn(Set.of("posix"));
        PosixFileAttributeView posixView = mock(PosixFileAttributeView.class);

        try (MockedStatic<FileSystems> fs = Mockito.mockStatic(FileSystems.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            fs.when(FileSystems::getDefault).thenReturn(posixFs);
            files.when(() -> Files.getFileAttributeView(eq(p), eq(PosixFileAttributeView.class))).thenReturn(posixView);
            invokeApplyRestrictivePermissions(p);
            verify(posixView).setPermissions(any());
        }

        try (MockedStatic<FileSystems> fs = Mockito.mockStatic(FileSystems.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            fs.when(FileSystems::getDefault).thenReturn(posixFs);
            files.when(() -> Files.getFileAttributeView(eq(p), eq(PosixFileAttributeView.class))).thenReturn(null);
            invokeApplyRestrictivePermissions(p);
        }

        FileSystem aclFs = mock(FileSystem.class);
        when(aclFs.supportedFileAttributeViews()).thenReturn(Set.of());
        AclFileAttributeView aclView = mock(AclFileAttributeView.class);
        UserPrincipal owner = mock(UserPrincipal.class);

        try (MockedStatic<FileSystems> fs = Mockito.mockStatic(FileSystems.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            fs.when(FileSystems::getDefault).thenReturn(aclFs);
            files.when(() -> Files.getFileAttributeView(eq(p), eq(AclFileAttributeView.class))).thenReturn(aclView);
            files.when(() -> Files.getOwner(eq(p))).thenReturn(owner);
            invokeApplyRestrictivePermissions(p);
            verify(aclView).setAcl(any());
        }

        try (MockedStatic<FileSystems> fs = Mockito.mockStatic(FileSystems.class, Mockito.CALLS_REAL_METHODS);
             MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            fs.when(FileSystems::getDefault).thenReturn(aclFs);
            files.when(() -> Files.getFileAttributeView(eq(p), eq(AclFileAttributeView.class))).thenReturn(null);
            invokeApplyRestrictivePermissions(p);
        }
    }

    @Test
    void cleanupOldBackups_should_cover_branches_and_exceptions() throws Exception {
        assertDoesNotThrow(() -> invokeCleanupOldBackups(null, "k"));
        assertDoesNotThrow(() -> invokeCleanupOldBackups(Path.of("x"), "k"));

        Path keyDir = Files.createDirectories(tempDir.resolve("keys").resolve("kid"));
        String keyId = "kid";
        Path parent = keyDir.getParent();
        for (int i = 0; i < 5; i++) {
            Files.writeString(parent.resolve(keyId + ".backup." + i), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        }

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            Path fail = parent.resolve(keyId + ".backup.0");
            files.when(() -> Files.deleteIfExists(eq(fail))).thenThrow(new IOException("io"));
            invokeCleanupOldBackups(keyDir, keyId);
        }

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.list(eq(parent))).thenThrow(new IOException("io"));
            assertDoesNotThrow(() -> invokeCleanupOldBackups(keyDir, keyId));
        }
    }

    @Test
    void cleanupOnFailure_should_cover_all_branches() throws Exception {
        Path temp = Files.createDirectories(tempDir.resolve("tmp"));
        Files.writeString(temp.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        Path target = Files.createDirectories(tempDir.resolve("tgt"));

        AutoCloseable closeable = mock(AutoCloseable.class);
        doThrow(new RuntimeException("close")).when(closeable).close();

        invokeCleanupOnFailure(temp, target, closeable);
        assertFalse(Files.exists(temp));
        assertFalse(Files.exists(target));

        Path temp2 = Files.createDirectories(tempDir.resolve("tmp2"));
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.walk(eq(temp2))).thenThrow(new IOException("io"));
            invokeCleanupOnFailure(temp2, Files.createDirectories(tempDir.resolve("tgt2")), new Object());
        }
    }

    @Test
    void cleanupOnFailure_should_cover_missing_dirs_and_non_incomplete_target() throws Exception {
        assertDoesNotThrow(() -> invokeCleanupOnFailure(null, null, new Object()));

        Path missing = tempDir.resolve("missing");
        assertDoesNotThrow(() -> invokeCleanupOnFailure(missing, null, new Object()));

        Path target = Files.createDirectories(tempDir.resolve("tgt-nonempty"));
        Files.writeString(target.resolve("a.txt"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        invokeCleanupOnFailure(null, target, new Object());
        assertTrue(Files.exists(target));
    }

    @Test
    void cleanupOnFailure_should_cover_target_delete_exception_catch() throws Exception {
        Path target = Files.createDirectories(tempDir.resolve("tgt-ex"));
        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.walk(eq(target))).thenThrow(new IOException("io"));
            assertDoesNotThrow(() -> invokeCleanupOnFailure(null, target, new Object()));
        }
    }

    @Test
    void cleanupOnFailure_should_cover_autocloseable_success_path() throws Exception {
        AutoCloseable c = mock(AutoCloseable.class);
        invokeCleanupOnFailure(null, null, c);
        verify(c).close();
    }

    @Test
    void deleteDirectoryRecursively_should_cover_return_and_delete_failure_warn() throws Exception {
        Path missing = tempDir.resolve("missing");
        assertDoesNotThrow(() -> invokeDeleteDirectoryRecursively(missing));

        Path dir = Files.createDirectories(tempDir.resolve("del"));
        Path file = dir.resolve("a.txt");
        Files.writeString(file, "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        try (FileChannel ch = FileChannel.open(file, StandardOpenOption.READ)) {
            assertDoesNotThrow(() -> invokeDeleteDirectoryRecursively(dir));
        }
    }

    @Test
    void deleteDirectoryRecursively_should_cover_delete_exception_path() throws Exception {
        Path dir = Files.createDirectories(tempDir.resolve("del2"));
        Path file = dir.resolve("a.txt");
        Files.writeString(file, "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.delete(eq(file))).thenThrow(new IOException("io"));
            assertDoesNotThrow(() -> invokeDeleteDirectoryRecursively(dir));
        }
    }

    @Test
    void isIncompleteKeyDirectory_should_cover_all_paths() throws Exception {
        Path file = tempDir.resolve("f");
        Files.writeString(file, "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        assertFalse(invokeIsIncompleteKeyDirectory(file));

        Path empty = Files.createDirectories(tempDir.resolve("empty"));
        assertTrue(invokeIsIncompleteKeyDirectory(empty));

        Path nonEmpty = Files.createDirectories(tempDir.resolve("nonEmpty"));
        Files.writeString(nonEmpty.resolve("a"), "x", StandardOpenOption.CREATE, StandardOpenOption.TRUNCATE_EXISTING);
        assertFalse(invokeIsIncompleteKeyDirectory(nonEmpty));

        try (MockedStatic<Files> files = Mockito.mockStatic(Files.class, Mockito.CALLS_REAL_METHODS)) {
            files.when(() -> Files.isDirectory(eq(nonEmpty))).thenReturn(true);
            files.when(() -> Files.list(eq(nonEmpty))).thenThrow(new IOException("io"));
            assertTrue(invokeIsIncompleteKeyDirectory(nonEmpty));
        }
    }

    private static final class ChildFirstForKeyRotation extends URLClassLoader {
        ChildFirstForKeyRotation(URL[] urls, ClassLoader parent) {
            super(urls, parent);
        }

        @Override
        public Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if ("com.chao.keyMinter.core.KeyRotation".equals(name)) {
                Class<?> c = findLoadedClass(name);
                if (c == null) {
                    c = findClass(name);
                }
                if (resolve) {
                    resolveClass(c);
                }
                return c;
            }
            return super.loadClass(name, resolve);
        }
    }

    private static void invokeWriteVersionMetadata(Path dir, String keyId) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("writeVersionMetadata", Path.class, String.class);
        m.setAccessible(true);
        try {
            m.invoke(null, dir, keyId);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static Path invokeCreateTempKeyDir(Path parent, String keyId) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("createTempKeyDir", Path.class, String.class);
        m.setAccessible(true);
        try {
            return (Path) m.invoke(null, parent, keyId);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof Exception ex) {
                throw ex;
            }
            throw e;
        }
    }

    private static boolean invokeWaitForDirectoryExists(Path dir) {
        try {
            Method m = KeyRotation.class.getDeclaredMethod("waitForDirectoryExists", Path.class);
            m.setAccessible(true);
            return (boolean) m.invoke(null, dir);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void invokeTryDeleteIfExists(Path path) {
        try {
            Method m = KeyRotation.class.getDeclaredMethod("tryDeleteIfExists", Path.class);
            m.setAccessible(true);
            m.invoke(null, path);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static void invokeMoveTempToTarget(Path tempDir, Path targetDir) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("moveTempToTarget", Path.class, Path.class);
        m.setAccessible(true);
        try {
            m.invoke(null, tempDir, targetDir);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof Exception ex) {
                throw ex;
            }
            throw e;
        }
    }

    private static boolean invokeIsDirectoryAccessible(Path dir) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("isDirectoryAccessible", Path.class);
        m.setAccessible(true);
        return (boolean) m.invoke(null, dir);
    }

    private static void invokeCopyDirectory(Path src, Path dst) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("copyDirectory", Path.class, Path.class);
        m.setAccessible(true);
        try {
            m.invoke(null, src, dst);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeCreateBackup(Path targetDir, Path backupDir) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("createBackup", Path.class, Path.class);
        m.setAccessible(true);
        try {
            m.invoke(null, targetDir, backupDir);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeRestoreFromBackup(Path targetDir, Path backupDir) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("restoreFromBackup", Path.class, Path.class);
        m.setAccessible(true);
        m.invoke(null, targetDir, backupDir);
    }

    private static void invokeCleanupBackup(Path backupDir) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("cleanupBackup", Path.class);
        m.setAccessible(true);
        try {
            m.invoke(null, backupDir);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeApplyRestrictivePermissionsRecursively(Path dir) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("applyRestrictivePermissionsRecursively", Path.class);
        m.setAccessible(true);
        try {
            m.invoke(null, dir);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeApplyRestrictivePermissions(Path p) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("applyRestrictivePermissions", Path.class);
        m.setAccessible(true);
        m.invoke(null, p);
    }

    private static void invokeCleanupOldBackups(Path keyDir, String keyId) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("cleanupOldBackups", Path.class, String.class);
        m.setAccessible(true);
        try {
            m.invoke(null, keyDir, keyId);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeCleanupOnFailure(Path tempDir, Path targetDir, Object newKey) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("cleanupOnFailure", Path.class, Path.class, Object.class);
        m.setAccessible(true);
        try {
            m.invoke(null, tempDir, targetDir, newKey);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static void invokeDeleteDirectoryRecursively(Path dir) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("deleteDirectoryRecursively", Path.class);
        m.setAccessible(true);
        try {
            m.invoke(null, dir);
        } catch (java.lang.reflect.InvocationTargetException e) {
            if (e.getCause() instanceof RuntimeException re) {
                throw re;
            }
            throw e;
        }
    }

    private static boolean invokeIsIncompleteKeyDirectory(Path dir) throws Exception {
        Method m = KeyRotation.class.getDeclaredMethod("isIncompleteKeyDirectory", Path.class);
        m.setAccessible(true);
        return (boolean) m.invoke(null, dir);
    }

    private static Object getStaticField(Class<?> cls, String fieldName) throws Exception {
        Field f = cls.getDeclaredField(fieldName);
        f.setAccessible(true);
        return f.get(null);
    }

    private static void setStaticFinalField(Class<?> cls, String fieldName, Object value) {
        try {
            Field f = cls.getDeclaredField(fieldName);
            f.setAccessible(true);
            Field uf = Unsafe.class.getDeclaredField("theUnsafe");
            uf.setAccessible(true);
            Unsafe u = (Unsafe) uf.get(null);
            Object base = u.staticFieldBase(f);
            long off = u.staticFieldOffset(f);
            u.putObjectVolatile(base, off, value);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }
}

