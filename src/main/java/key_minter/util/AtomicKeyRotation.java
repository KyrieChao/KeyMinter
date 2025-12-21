package key_minter.util;

import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.*;
import java.util.UUID;

@Slf4j
public class AtomicKeyRotation {
    // 存储当前操作的临时目录
    private static final ThreadLocal<Path> CURRENT_TEMP_DIR = new ThreadLocal<>();

    // 函数式接口定义
    @FunctionalInterface
    public interface ThrowingSupplier<T> {
        T get() throws Exception;
    }

    @FunctionalInterface
    public interface ThrowingConsumer<T> {
        void accept(T t) throws Exception;
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
     * 原子性密钥轮换操作（主要方法，带临时目录传递）
     */
    public static <T> boolean rotateKeyAtomic(
            String keyId,
            Path keyDir,
            ThrowingSupplier<T> keyGenerator,
            FileSaverWithDir<T> fileSaver,
            MemoryUpdater<T> memoryUpdater) {

        T newKey = null;
        Path tempDir = null;
        Path targetDir = keyDir.resolve(keyId);

        try {
            // 1. 生成新密钥
            log.debug("Generating new key for: {}", keyId);
            newKey = keyGenerator.get();

            // 2. 创建临时目录
            log.debug("Creating temporary directory for key: {}", keyId);
            tempDir = createTempKeyDir(keyDir.getParent(), keyId);
            CURRENT_TEMP_DIR.set(tempDir);

            // 3. 保存到临时目录
            log.debug("Saving key files to temporary directory: {}", tempDir);
            fileSaver.accept(newKey, tempDir);

            // 4. 原子性移动临时目录到目标位置
            log.debug("Atomically moving temporary directory to target: {}", targetDir);
            moveTempToTarget(tempDir, targetDir);

            // 5. 更新内存（最后一步）
            log.debug("Updating memory mappings for key: {}", keyId);
            memoryUpdater.accept(newKey);

            log.info("Key rotation completed successfully for key: {}", keyId);
            return true;

        } catch (Exception e) {
            // 清理失败的部分
            log.error("Key rotation failed for key {}: {}", keyId, e.getMessage());
            cleanupOnFailure(tempDir, targetDir, newKey);
            return false;
        } finally {
            CURRENT_TEMP_DIR.remove();
        }
    }

    /**
     * 创建临时密钥目录
     */
    private static Path createTempKeyDir(Path parentDir, String keyId) throws IOException {
        // 确保父目录存在
        if (!Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
        }

        // 生成唯一的临时目录名
        String tempDirName = ".tmp-" + keyId + "-" +
                UUID.randomUUID().toString().substring(0, 8) +
                "-" + System.currentTimeMillis();

        // 创建临时目录
        Path tempDir = parentDir.resolve(tempDirName);
        Files.createDirectories(tempDir);
        log.debug("Created temporary directory: {}", tempDir);

        return tempDir;
    }

    /**
     * 原子性移动临时目录到目标位置
     */
    private static void moveTempToTarget(Path tempDir, Path targetDir) throws IOException {
        if (tempDir == null || !Files.exists(tempDir)) {
            throw new IOException("Temporary directory does not exist: " + tempDir);
        }

        // 确保目标目录的父目录存在
        Path parentDir = targetDir.getParent();
        if (!Files.exists(parentDir)) {
            Files.createDirectories(parentDir);
        }

        // 如果目标目录已存在，先删除（标准轮换场景）
        if (Files.exists(targetDir)) {
            log.debug("Target directory already exists, deleting: {}", targetDir);
            deleteDirectoryRecursively(targetDir);
        }

        // 原子性移动
        Files.move(tempDir, targetDir, StandardCopyOption.ATOMIC_MOVE);
        log.debug("Moved {} to {} atomically", tempDir, targetDir);
    }

    /**
     * 清理失败时的残留资源
     */
    private static <T> void cleanupOnFailure(Path tempDir, Path targetDir, T newKey) {
        // 1. 清理临时目录
        if (tempDir != null && Files.exists(tempDir)) {
            try {
                deleteDirectoryRecursively(tempDir);
                log.debug("Cleaned up temporary directory: {}", tempDir);
            } catch (IOException e) {
                log.warn("Failed to cleanup temporary directory {}: {}", tempDir, e.getMessage());
            }
        }

        // 2. 清理部分创建的目标目录（如果移动失败但部分文件已存在）
        // 注意：这里只清理如果目录存在但明显不完整的情况
        if (targetDir != null && Files.exists(targetDir)) {
            try {
                // 检查目录是否看起来不完整
                if (isIncompleteKeyDirectory(targetDir)) {
                    log.warn("Detected incomplete key directory, cleaning up: {}", targetDir);
                    deleteDirectoryRecursively(targetDir);
                }
            } catch (IOException e) {
                log.warn("Failed to cleanup target directory {}: {}", targetDir, e.getMessage());
            }
        }

        // 3. 清理密钥资源（如果有资源清理方法）
        if (newKey != null) {
            cleanupKeyResource(newKey);
        }
    }

    /**
     * 递归删除目录
     */
    private static void deleteDirectoryRecursively(Path dir) throws IOException {
        if (!Files.exists(dir)) return;

        // 递归删除目录内容
        try (var paths = Files.walk(dir)) {
            paths.sorted((a, b) -> -a.compareTo(b)) // 逆序，先删除文件再删除目录
                    .forEach(path -> {
                        try {
                            Files.delete(path);
                        } catch (IOException e) {
                            log.warn("Failed to delete {}: {}", path, e.getMessage());
                        }
                    });
        }
    }

    /**
     * 检查目录是否不完整
     */
    private static boolean isIncompleteKeyDirectory(Path dir) {
        try {
            // 简单检查：目录为空或缺少关键文件
            if (!Files.isDirectory(dir)) return false;

            try (var stream = Files.list(dir)) {
                long fileCount = stream.count();
                // 如果目录创建但没有任何密钥文件，可能是不完整的
                return fileCount == 0;
            }
        } catch (IOException e) {
            return true; // 无法访问，认为可能有问题
        }
    }

    /**
     * 清理密钥资源
     */
    private static <T> void cleanupKeyResource(T key) {
        // 这里根据密钥类型进行清理
        if (key instanceof AutoCloseable) {
            try {
                ((AutoCloseable) key).close();
            } catch (Exception e) {
                log.debug("Failed to close key resource: {}", e.getMessage());
            }
        }
    }
}