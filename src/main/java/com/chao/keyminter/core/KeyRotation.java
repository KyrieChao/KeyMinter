package com.chao.keyminter.core;

import com.chao.keyminter.domain.port.out.LockProvider;
import lombok.Setter;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.io.RandomAccessFile;
import java.io.UncheckedIOException;
import java.nio.channels.FileLock;
import java.nio.file.*;
import java.nio.file.attribute.*;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReentrantLock;
import java.util.regex.Pattern;

import com.chao.keyminter.domain.port.out.PermissionStrategy;
import com.chao.keyminter.adapter.out.fs.PosixPermissionStrategy;
import com.chao.keyminter.adapter.out.fs.WindowsPermissionStrategy;

/**
 * 密钥轮换工具类
 * 提供原子性密钥轮换功能，支持本地锁和分布式锁
 */
@Slf4j
public class KeyRotation {

    private static final ConcurrentHashMap<String, ReentrantLock> LOCAL_LOCKS = new ConcurrentHashMap<>();
    private static final String LOCK_FILE_NAME = ".rotation.lock";
    private static final String BACKUP_SUFFIX = ".backup";
    private static final int MAX_BACKUPS = 3;
    
    // 权限策略
    private static final PermissionStrategy permissionStrategy;

    static {
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            permissionStrategy = new WindowsPermissionStrategy();
        } else {
            permissionStrategy = new PosixPermissionStrategy();
        }
    }

    @Setter
    private static volatile LockProvider lockProvider;

    @FunctionalInterface
    public interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    @FunctionalInterface
    public interface FileSaverWithDir<T> {
        void accept(T t, Path tempDir) throws Exception;
    }

    @FunctionalInterface
    public interface MemoryUpdater<T> {
        void accept(T t) throws Exception;
    }

    /**
     * 原子性密钥轮换（支持本地锁和分布式锁）
     */
    public static <T> boolean rotateKeyAtomic(String keyId, Path keyDir,ThrowingSupplier<T> keyGenerator,
                                              FileSaverWithDir<T> fileSaver,MemoryUpdater<T> memoryUpdater) throws IOException {
        Objects.requireNonNull(keyId, "Key ID cannot be null");
        Objects.requireNonNull(keyDir, "Key directory cannot be null");
        Objects.requireNonNull(keyGenerator, "Key generator cannot be null");
        Objects.requireNonNull(fileSaver, "File saver cannot be null");
        Objects.requireNonNull(memoryUpdater, "Memory updater cannot be null");

        // 1. 获取分布式锁（如果配置了）
        Lock distLock = null;
        if (lockProvider != null) {
            distLock = lockProvider.getLock(keyDir.toAbsolutePath().toString());
            try {
                if (!distLock.tryLock(30, TimeUnit.SECONDS)) {
                    log.warn("Failed to acquire distributed lock for {}", keyDir);
                    return false;
                }
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                log.warn("Interrupted while acquiring distributed lock for {}", keyDir);
                return false;
            }
        }

        try {
            // 2. 获取本地 JVM 锁
            ReentrantLock localLock = LOCAL_LOCKS.computeIfAbsent(
                    keyDir.toAbsolutePath().toString(),k -> new ReentrantLock()
            );
            localLock.lock();
            try {
                // 确保父目录存在
                if (!Files.exists(keyDir)) {
                    Files.createDirectories(keyDir);
                }
                // 3. 获取本地文件锁（跨进程）
                Path lockFile = keyDir.resolve(LOCK_FILE_NAME);
                try (RandomAccessFile raf = new RandomAccessFile(lockFile.toFile(), "rw");
                     FileLock ignored = raf.getChannel().lock()) {
                    return doRotateWithBackup(keyId, keyDir, keyGenerator, fileSaver, memoryUpdater);
                } catch (IOException e) {
                    log.error("Failed to acquire file lock for {}: {}", keyDir, e.getMessage());
                    return false;
                }
            } finally {
                localLock.unlock();
            }
        } finally {
            if (distLock != null) {
                try {
                    distLock.unlock();
                } catch (Exception e) {
                    log.warn("Failed to release distributed lock: {}", e.getMessage());
                }
            }
        }
    }

    private static <T> boolean doRotateWithBackup(String keyId, Path keyDir, ThrowingSupplier<T> keyGenerator,
                                                  FileSaverWithDir<T> fileSaver, MemoryUpdater<T> memoryUpdater) {
        T newKey = null;
        Path tempDir = null;
        Path targetDir = keyDir.resolve(keyId);
        Path backupDir = keyDir.resolve(keyId + BACKUP_SUFFIX);
        try {
            log.debug("Generating new key for: {}", keyId);
            newKey = keyGenerator.get();

            log.debug("Creating temporary directory for key: {}", keyId);
            tempDir = createTempKeyDir(keyDir, keyId);

            log.debug("Saving key files to temporary directory: {}", tempDir);
            fileSaver.accept(newKey, tempDir);
            writeVersionMetadata(tempDir, keyId);

            // FIX: Windows - 先不收紧权限，确保移动时不会被 ACL 拦截
            // applyRestrictivePermissionsRecursively(tempDir); // 移到移动之后

            if (Files.exists(targetDir)) {
                createBackup(targetDir, backupDir);
            }

            log.debug("Atomically moving temporary directory to target: {}", targetDir);
            moveTempToTarget(tempDir, targetDir);

            // FIX: 移动到目标位置后再收紧权限（此时目录已"转正"）
            try {
                permissionStrategy.setRestrictivePermissions(targetDir);
            } catch (Exception e) {
                log.warn("Failed to set restrictive permissions: {}", e.getMessage());
            }

            log.debug("Updating memory mappings for key: {}", keyId);
            memoryUpdater.accept(newKey);

            log.info("Key rotation completed successfully for key: {}", keyId);
            cleanupBackup(backupDir);
            cleanupOldBackups(keyDir, keyId);
            return true;
        } catch (Exception e) {
            log.error("Key rotation failed for key {}: {}", keyId, e.getMessage(), e);
            cleanupOnFailure(tempDir, targetDir, newKey);
            restoreFromBackup(targetDir, backupDir);
            return false;
        }
    }

    private static void writeVersionMetadata(Path tempDir, String keyId) {
        try {
            Path meta = tempDir.resolve("version.json");
            String timestamp = LocalDateTime.now().format(DateTimeFormatter.ISO_LOCAL_DATE_TIME);
            String content = String.format("{\"keyId\":\"%s\",\"createdTime\":\"%s\"}", keyId, timestamp);
            Files.writeString(meta, content);
        } catch (Exception e) {
            log.error("Failed to write version metadata for key {}: {}", keyId, e.getMessage());
            throw new UncheckedIOException("Failed to write version metadata",
                    new IOException(e));
        }
    }

    private static Path createTempKeyDir(Path parentDir, String keyId) throws IOException {
        Objects.requireNonNull(parentDir, "Parent directory cannot be null");
        if (!Files.exists(parentDir)) Files.createDirectories(parentDir);
        // FIX: 增加重试次数和等待时间，解决 Windows Defender/索引延迟
        int maxRetries = 5;
        Path tempDir;
        IOException lastException = null;

        for (int i = 0; i < maxRetries; i++) {
            String tempDirName = ".tmp-" + keyId + "-" + UUID.randomUUID().toString().substring(0, 8) +
                    "-" + System.currentTimeMillis();
            tempDir = parentDir.resolve(tempDirName);

            try {
                Files.createDirectories(tempDir);
                
                // 使用策略模式设置权限
                permissionStrategy.ensureAccessible(tempDir);
                
                // FIX: 延长等待时间到 3 秒，给 Windows Defender/索引服务放行
                if (waitForDirectoryExists(tempDir, 3000)) {
                    log.debug("Created temporary directory: {} (attempt {})", tempDir, i + 1);
                    return tempDir;
                } else {
                    lastException = new IOException("Directory created but not visible after wait: " + tempDir);
                    tryDeleteIfExists(tempDir);
                }
            } catch (IOException e) {
                lastException = e;
                log.warn("Attempt {} failed to create temp dir {}: {}", i + 1, tempDir, e.getMessage());
                tryDeleteIfExists(tempDir);
                if (i < maxRetries - 1) {
                    try {
                        Thread.sleep(100); // 增加延迟到 100ms
                    } catch (InterruptedException ie) {
                        Thread.currentThread().interrupt();
                        throw new IOException("Interrupted while creating temp directory", ie);
                    }
                }
            }
        }
        throw new IOException("Failed to create temporary directory after " + maxRetries + " attempts", lastException);
    }

    /**
     * FIX: 等待目录在文件系统中可见（解决 Windows 文件系统延迟）
     */
    private static boolean waitForDirectoryExists(Path dir, int timeoutMillis) {
        long deadline = System.currentTimeMillis() + timeoutMillis;
        int checks = 0;
        while (System.currentTimeMillis() < deadline) {
            checks++;
            // 双重验证：Files.exists 和 File.isDirectory
            if (Files.exists(dir) && Files.isDirectory(dir)) {
                // 额外验证：能否列出目录内容（确认真的有访问权限）
                try {
                    Files.list(dir).close();
                    log.debug("Directory {} verified after {} checks (~{}ms)", dir, checks,
                            (System.currentTimeMillis() - (deadline - timeoutMillis)));
                    return true;
                } catch (IOException e) {
                    // 存在但无权访问，继续等待
                }
            }
            try {
                Thread.sleep(20); // 更频繁的检查
            } catch (InterruptedException e) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        // 最后一次尝试用 File 对象（绕过 NIO 缓存）
        return dir.toFile().isDirectory();
    }

    /**
     * FIX: 安全删除（忽略异常）
     */
    private static void tryDeleteIfExists(Path path) {
        if (path == null) return;
        try {
            if (Files.exists(path)) {
                deleteDirectoryRecursively(path);
            }
        } catch (Exception e) {
            log.debug("Failed to cleanup path {}: {}", path, e.getMessage());
        }
    }

    private static void moveTempToTarget(Path tempDir, Path targetDir) throws IOException {
        Objects.requireNonNull(tempDir, "Temp directory cannot be null");
        Objects.requireNonNull(targetDir, "Target directory cannot be null");

        Path parentDir = targetDir.getParent();
        if (parentDir != null && !Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
        }

        if (Files.exists(targetDir)) {
            log.debug("Target directory already exists, deleting: {}", targetDir);
            deleteDirectoryRecursively(targetDir);
        }

        // FIX: Windows 兼容策略 - 三步降级
        boolean moved = false;
        IOException lastException = null;

        // 1. 尝试 NIO 原子移动（Unix/Linux 最优）
        try {
            Files.move(tempDir, targetDir, StandardCopyOption.ATOMIC_MOVE);
            moved = true;
            log.debug("Moved {} to {} atomically", tempDir, targetDir);
        } catch (AccessDeniedException | AtomicMoveNotSupportedException e) {
            lastException = e;
            log.debug("Atomic move failed ({}), trying File.renameTo: {}", e.getClass().getSimpleName(), e.getMessage());
        }

        // 2. Windows 备选：传统 File.renameTo()（绕过 NIO 句柄问题）
        if (!moved) {
            try {
                // FIX: 等待 100ms 让 Defender/索引服务释放句柄
                Thread.sleep(100);

                // 先确保临时目录完全关闭（触发 finalize）
                System.gc();
                Thread.sleep(50);

                if (tempDir.toFile().renameTo(targetDir.toFile())) {
                    moved = true;
                    log.debug("Moved {} to {} using File.renameTo (legacy IO)", tempDir, targetDir);
                } else {
                    throw new IOException("File.renameTo returned false");
                }
            } catch (Exception e) {
                lastException = new IOException("File.renameTo failed: " + e.getMessage(), e);
                log.debug("File.renameTo failed: {}", e.getMessage());
            }
        }
        // 3. 最终备选：复制 + 删除（非原子但一定成功）
        if (!moved) {
            log.warn("Using copy+delete fallback for {} -> {} (Windows Defender may be locking the directory)",
                    tempDir, targetDir);
            try {
                copyDirectory(tempDir, targetDir);
                deleteDirectoryRecursively(tempDir);
                moved = true;
                log.debug("Copied {} to {} and deleted source (fallback)", tempDir, targetDir);
            } catch (Exception e) {
                throw new IOException("All move strategies failed. Last error: " + lastException.getMessage(), e);
            }
        }
        // 4. 移动后立即验证并设置权限
        if (System.getProperty("os.name").toLowerCase().contains("win")) {
            // 等待文件系统同步
            try {
                Thread.sleep(200);
            } catch (InterruptedException e) {
                throw new RuntimeException(e);
            }
            // 验证目录可访问
            if (isDirectoryAccessible(targetDir)) {
                log.warn("Directory not accessible after move, setting permissions again: {}", targetDir);
                try {
                    permissionStrategy.setRestrictivePermissions(targetDir);
                } catch (IOException e) {
                    log.warn("Failed to re-apply permissions: {}", e.getMessage());
                }
                // 再次验证
                try {
                    Thread.sleep(100);
                } catch (InterruptedException e) {
                    throw new RuntimeException(e);
                }
                if (isDirectoryAccessible(targetDir)) {
                    throw new IOException("Directory remains inaccessible after permission fix: " + targetDir);
                }
            }
        }
    }

    private static boolean isDirectoryAccessible(Path dir) {
        try {
            // 尝试列出目录内容
            Files.list(dir).close();
            return false;
        } catch (IOException e) {
            return true;
        }
    }

    private static void copyDirectory(Path source, Path target) throws IOException {
        try (var paths = Files.walk(source)) {
            paths.forEach(srcPath -> {
                Path relative = source.relativize(srcPath);
                Path destPath = target.resolve(relative);
                try {
                    if (Files.isDirectory(srcPath)) {
                        Files.createDirectories(destPath);
                    } else {
                        Files.copy(srcPath, destPath, StandardCopyOption.REPLACE_EXISTING);
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException(
                            "Failed to copy from " + srcPath + " to " + destPath, e);
                }
            });
        }
    }

    private static void createBackup(Path targetDir, Path backupDir) throws IOException {
        if (Files.exists(backupDir)) {
            deleteDirectoryRecursively(backupDir);
        }
        Files.createDirectories(backupDir);

        try (var paths = Files.walk(targetDir)) {
            paths.forEach(p -> {
                Path rel = targetDir.relativize(p);
                Path dest = backupDir.resolve(rel);
                try {
                    if (Files.isDirectory(p)) {
                        Files.createDirectories(dest);
                    } else {
                        Files.copy(p, dest);
                    }
                } catch (IOException e) {
                    throw new UncheckedIOException("Failed to create backup", e);
                }
            });
        }
        log.debug("Created backup at {}", backupDir);
    }

    private static void restoreFromBackup(Path targetDir, Path backupDir) {
        try {
            if (!Files.exists(backupDir)) {
                return;
            }

            deleteDirectoryRecursively(targetDir);
            Files.createDirectories(targetDir);

            try (var paths = Files.walk(backupDir)) {
                paths.forEach(p -> {
                    Path rel = backupDir.relativize(p);
                    Path dest = targetDir.resolve(rel);
                    try {
                        if (Files.isDirectory(p)) {
                            Files.createDirectories(dest);
                        } else {
                            Files.copy(p, dest, StandardCopyOption.REPLACE_EXISTING);
                        }
                    } catch (IOException e) {
                        throw new UncheckedIOException("Failed to restore from backup", e);
                    }
                });
            }
            log.warn("Restored target dir from backup: {}", backupDir);
        } catch (Exception e) {
            log.error("Failed to restore from backup {}: {}", backupDir, e.getMessage());
        }
    }

    private static void cleanupBackup(Path backupDir) {
        try {
            if (Files.exists(backupDir)) {
                deleteDirectoryRecursively(backupDir);
            }
        } catch (IOException e) {
            log.debug("Failed to cleanup backup {}: {}", backupDir, e.getMessage());
        }
    }

    private static void applyRestrictivePermissionsRecursively(Path dir) {
        try (var paths = Files.walk(dir)) {
            paths.forEach(p -> {
                try {
                    permissionStrategy.setRestrictivePermissions(p);
                } catch (Exception e) {
                    log.warn("Failed to apply restrictive permissions to {}: {}", p, e.getMessage());
                    throw new UncheckedIOException("Failed to apply restrictive permissions", new IOException(e));
                }
            });
        } catch (IOException e) {
            log.warn("Failed to apply restrictive permissions: {}", e.getMessage());
            throw new UncheckedIOException("Failed to walk directory for permissions", e);
        }
    }

    private static void applyRestrictivePermissions(Path path) throws IOException {
        FileSystem fs = FileSystems.getDefault();
        boolean posix = fs.supportedFileAttributeViews().contains("posix");

        if (posix) {
            PosixFileAttributeView view = Files.getFileAttributeView(path, PosixFileAttributeView.class);
            if (view != null) {
                var perms = EnumSet.of(
                        PosixFilePermission.OWNER_READ,
                        PosixFilePermission.OWNER_WRITE
                );
                view.setPermissions(perms);
            }
        } else {
            AclFileAttributeView aclView = Files.getFileAttributeView(path, AclFileAttributeView.class);
            if (aclView != null) {
                UserPrincipal owner = Files.getOwner(path);
                AclEntry entry = AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(owner)
                        .setPermissions(
                                AclEntryPermission.READ_DATA,
                                AclEntryPermission.WRITE_DATA
                        )
                        .build();
                aclView.setAcl(java.util.List.of(entry));
            }
        }
    }

    private static void cleanupOldBackups(Path keyDir, String keyId) {
        if (keyDir == null || keyDir.getParent() == null) {
            return;
        }

        try (var s = Files.list(keyDir.getParent())) {
            String pattern = Pattern.quote(keyId) + "\\.backup\\.\\d+";
            s.filter(p -> p.getFileName().toString().matches(pattern))
                    .sorted(Comparator.reverseOrder())
                    .skip(MAX_BACKUPS)
                    .forEach(p -> {
                        try {
                            Files.deleteIfExists(p);
                        } catch (IOException e) {
                            log.debug("Failed to delete old backup {}: {}", p, e.getMessage());
                        }
                    });
        } catch (IOException e) {
            log.debug("Failed to cleanup old backups for {}: {}", keyId, e.getMessage());
        }
    }

    private static <T> void cleanupOnFailure(Path tempDir, Path targetDir, T newKey) {
        if (tempDir != null && Files.exists(tempDir)) {
            try {
                deleteDirectoryRecursively(tempDir);
                log.debug("Cleaned up temporary directory: {}", tempDir);
            } catch (IOException e) {
                log.warn("Failed to cleanup temporary directory {}: {}", tempDir, e.getMessage());
            }
        }

        if (targetDir != null && Files.exists(targetDir) && isIncompleteKeyDirectory(targetDir)) {
            try {
                log.warn("Detected incomplete key directory, cleaning up: {}", targetDir);
                deleteDirectoryRecursively(targetDir);
            } catch (IOException e) {
                log.warn("Failed to cleanup target directory {}: {}", targetDir, e.getMessage());
            }
        }

        if (newKey instanceof AutoCloseable) {
            try {
                ((AutoCloseable) newKey).close();
            } catch (Exception e) {
                log.debug("Failed to close key resource: {}", e.getMessage());
            }
        }
    }

    private static void deleteDirectoryRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) {
            return;
        }

        try (var paths = Files.walk(dir)) {
            paths.sorted((a, b) -> -a.compareTo(b))
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            log.warn("Failed to delete {}: {}", path, e.getMessage());
                        }
                    });
        }
    }

    private static boolean isIncompleteKeyDirectory(Path dir) {
        try {
            if (!Files.isDirectory(dir)) {
                return false;
            }

            try (var stream = Files.list(dir)) {
                return stream.findAny().isEmpty();
            }
        } catch (IOException e) {
            return true;
        }
    }
}