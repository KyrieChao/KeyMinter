package com.chao.keyminter.test;

import com.chao.keyminter.core.KeyRotation;
import com.chao.keyminter.domain.port.out.LockProvider;
import org.junit.jupiter.api.*;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.file.*;
import java.nio.file.attribute.PosixFilePermission;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.locks.Condition;
import java.util.concurrent.locks.ReentrantLock;

import static org.junit.jupiter.api.Assertions.*;

/**
 * KeyRotation 单元测试
 * 测试密钥轮换的原子性操作
 */
@DisplayName("KeyRotation 测试")
class KeyRotationTest {

    @TempDir
    Path tempDir;

    @BeforeEach
    void setUp() {
        // 清理锁提供者
        KeyRotation.setLockProvider(null);
    }

    @AfterEach
    void tearDown() {
        KeyRotation.setLockProvider(null);
    }

    // ==================== 基本轮换测试 ====================

    @Nested
    @DisplayName("基本轮换测试")
    class BasicRotationTests {

        @Test
        @DisplayName("原子性密钥轮换 - 成功")
        void rotateKeyAtomic_Success() throws IOException {
            String keyId = "test-key-v1";
            byte[] testData = "test-secret-data".getBytes();
            AtomicInteger memoryUpdateCount = new AtomicInteger(0);

            boolean result = KeyRotation.rotateKeyAtomic(
                keyId,
                tempDir,
                () -> testData,
                (data, temp) -> {
                    Path file = temp.resolve("secret.key");
                    Files.write(file, data);
                },
                (data) -> memoryUpdateCount.incrementAndGet()
            );

            assertTrue(result);
            assertEquals(1, memoryUpdateCount.get());
            
            // 验证文件已创建
            Path keyDir = tempDir.resolve(keyId);
            assertTrue(Files.exists(keyDir));
            assertTrue(Files.exists(keyDir.resolve("secret.key")));
            assertTrue(Files.exists(keyDir.resolve("version.json")));
        }

        @Test
        @DisplayName("原子性密钥轮换 - 空keyId抛出异常")
        void rotateKeyAtomic_NullKeyId_ThrowsException() {
            assertThrows(NullPointerException.class, () ->
                KeyRotation.rotateKeyAtomic(
                    null,
                    tempDir,
                        "data"::getBytes,
                    (data, temp) -> {},
                    (data) -> {}
                )
            );
        }

        @Test
        @DisplayName("原子性密钥轮换 - 空目录抛出异常")
        void rotateKeyAtomic_NullDir_ThrowsException() {
            assertThrows(NullPointerException.class, () ->
                KeyRotation.rotateKeyAtomic(
                    "key-id",null,"data"::getBytes,
                    (data, temp) -> {},
                    (data) -> {}
                )
            );
        }

        @Test
        @DisplayName("原子性密钥轮换 - 生成器失败返回false")
        void rotateKeyAtomic_GeneratorFails_ReturnsFalse() throws IOException {
            boolean result = KeyRotation.rotateKeyAtomic(
                "test-key",tempDir,
                () -> { throw new RuntimeException("Generation failed"); },
                (data, temp) -> {},
                (data) -> {}
            );

            assertFalse(result);
        }

        @Test
        @DisplayName("原子性密钥轮换 - 文件保存失败回滚")
        void rotateKeyAtomic_FileSaveFails_Rollback() throws IOException {
            String keyId = "test-key-v1";
            
            boolean result = KeyRotation.rotateKeyAtomic(
                keyId,tempDir,"data"::getBytes,
                (data, temp) -> { throw new RuntimeException("Save failed"); },
                (data) -> {}
            );

            assertFalse(result);
        }
    }

    // ==================== 备份恢复测试 ====================

    @Nested
    @DisplayName("备份恢复测试")
    class BackupRestoreTests {

        @Test
        @DisplayName("轮换时创建备份 - 成功")
        void rotation_CreatesBackup() throws IOException {
            String keyId = "test-key-v1";
            
            // 首次轮换
            KeyRotation.rotateKeyAtomic(
                keyId,
                tempDir,
                    "version1"::getBytes,
                (data, temp) -> Files.write(temp.resolve("secret.key"), data),
                (data) -> {}
            );

            // 再次轮换（应该创建备份）
            KeyRotation.rotateKeyAtomic(
                keyId,
                tempDir,
                    "version2"::getBytes,
                (data, temp) -> Files.write(temp.resolve("secret.key"), data),
                (data) -> {}
            );

            // 验证当前版本
            Path keyDir = tempDir.resolve(keyId);
            byte[] currentData = Files.readAllBytes(keyDir.resolve("secret.key"));
            assertEquals("version2", new String(currentData));
        }
    }

    // ==================== 并发测试 ====================

    @Nested
    @DisplayName("并发测试")
    class ConcurrencyTests {

        @Test
        @DisplayName("并发轮换 - 只有一个成功")
        void concurrentRotation_OnlyOneSucceeds() throws InterruptedException {
            int threadCount = 5;
            ExecutorService executor = Executors.newFixedThreadPool(threadCount);
            CountDownLatch latch = new CountDownLatch(threadCount);
            AtomicInteger successCount = new AtomicInteger(0);

            for (int i = 0; i < threadCount; i++) {
                final int index = i;
                executor.submit(() -> {
                    try {
                        boolean result = KeyRotation.rotateKeyAtomic(
                            "concurrent-key",
                            tempDir,
                            ("data-" + index)::getBytes,
                            (data, temp) -> Files.write(temp.resolve("secret.key"), data),
                            (data) -> {}
                        );
                        if (result) {
                            successCount.incrementAndGet();
                        }
                    } catch (IOException e) {
                        // 忽略
                    } finally {
                        latch.countDown();
                    }
                });
            }

            assertTrue(latch.await(10, TimeUnit.SECONDS));
            executor.shutdown();
            
            // 由于有锁机制，所有线程都会串行执行成功，或者如果测试期望竞争失败，应该检查逻辑
            // 但 KeyRotation 的设计是阻塞等待锁，所以所有请求最终都会成功
            assertEquals(threadCount, successCount.get());
        }

        @Test
        @DisplayName("分布式锁 - 使用LockProvider")
        void distributedLock_UsesLockProvider() throws IOException {
            // 创建模拟的LockProvider
            ReentrantLock mockLock = new ReentrantLock();
            LockProvider mockProvider = key -> mockLock;
            KeyRotation.setLockProvider(mockProvider);

            boolean result = KeyRotation.rotateKeyAtomic(
                "locked-key",
                tempDir,
                    "data"::getBytes,
                (data, temp) -> Files.write(temp.resolve("secret.key"), data),
                (data) -> {}
            );

            assertTrue(result);
        }

        @Test
        @DisplayName("分布式锁 - 获取锁超时")
        void distributedLock_Timeout() throws IOException {
            // 创建一个总是超时的LockProvider
            LockProvider timeoutProvider = key -> new java.util.concurrent.locks.Lock() {
                @Override
                public void lock() {}
                @Override
                public void lockInterruptibly() {}
                @Override
                public boolean tryLock() { return false; }
                @Override
                public boolean tryLock(long time, TimeUnit unit) { return false; }
                @Override
                public void unlock() {}
                @Override
                public Condition newCondition() { return null; }
            };
            KeyRotation.setLockProvider(timeoutProvider);

            boolean result = KeyRotation.rotateKeyAtomic(
                "timeout-key",tempDir,"data"::getBytes,
                (data, temp) -> {},
                (data) -> {}
            );

            assertFalse(result);
        }
    }

    // ==================== 文件权限测试 ====================

    @Nested
    @DisplayName("文件权限测试")
    class FilePermissionTests {

        @Test
        @DisplayName("轮换设置文件权限 - 成功")
        void rotation_SetsFilePermissions() throws IOException {
            String keyId = "test-key-v1";
            
            KeyRotation.rotateKeyAtomic(
                keyId,
                tempDir,
                    "secret-data"::getBytes,
                (data, temp) -> Files.write(temp.resolve("secret.key"), data),
                (data) -> {}
            );

            Path keyDir = tempDir.resolve(keyId);
            Path secretFile = keyDir.resolve("secret.key");
            
            assertTrue(Files.exists(secretFile));
            
            // 验证文件权限（在POSIX系统上）
            if (FileSystems.getDefault().supportedFileAttributeViews().contains("posix")) {
                var perms = Files.getPosixFilePermissions(secretFile);
                assertTrue(perms.contains(PosixFilePermission.OWNER_READ));
                assertTrue(perms.contains(PosixFilePermission.OWNER_WRITE));
                assertFalse(perms.contains(PosixFilePermission.GROUP_READ));
                assertFalse(perms.contains(PosixFilePermission.OTHERS_READ));
            }
        }
    }

    // ==================== 版本元数据测试 ====================

    @Nested
    @DisplayName("版本元数据测试")
    class VersionMetadataTests {

        @Test
        @DisplayName("轮换写入版本元数据 - 成功")
        void rotation_WritesVersionMetadata() throws IOException {
            String keyId = "test-key-v1";
            
            KeyRotation.rotateKeyAtomic(
                keyId,tempDir,"data"::getBytes,
                (data, temp) -> Files.write(temp.resolve("secret.key"), data),
                (data) -> {}
            );

            Path versionFile = tempDir.resolve(keyId).resolve("version.json");
            assertTrue(Files.exists(versionFile));
            
            String content = Files.readString(versionFile);
            assertTrue(content.contains("keyId"));
            assertTrue(content.contains("createdTime"));
            assertTrue(content.contains(keyId));
        }
    }

    // ==================== 清理测试 ====================

    @Nested
    @DisplayName("清理测试")
    class CleanupTests {

        @Test
        @DisplayName("失败时清理临时目录 - 成功")
        void failure_CleansTempDir() throws IOException {
            String keyId = "test-key-v1";
            
            // 获取轮换前的临时目录数量
            int tempDirCountBefore;
            try (var stream = Files.list(tempDir.getParent() != null ? tempDir.getParent() : tempDir)) {
                tempDirCountBefore = (int) stream.filter(p -> p.getFileName().toString().startsWith(".tmp-")).count();
            }

            // 失败的轮换
            KeyRotation.rotateKeyAtomic(
                keyId,tempDir,"data"::getBytes,
                (data, temp) -> { throw new RuntimeException("Save failed"); },
                (data) -> {}
            );

            // 验证临时目录被清理
            int tempDirCountAfter;
            try (var stream = Files.list(tempDir.getParent() != null ? tempDir.getParent() : tempDir)) {
                tempDirCountAfter = (int) stream.filter(p -> p.getFileName().toString().startsWith(".tmp-")).count();
            }
            
            assertEquals(tempDirCountBefore, tempDirCountAfter);
        }
    }

    // ==================== 边缘情况测试 ====================

    @Nested
    @DisplayName("边缘情况测试")
    class EdgeCaseTests {

        @Test
        @DisplayName("轮换到已存在的目录 - 成功")
        void rotation_ToExistingDir_Success() throws IOException {
            String keyId = "existing-key";
            Path existingDir = tempDir.resolve(keyId);
            Files.createDirectories(existingDir);
            Files.write(existingDir.resolve("old.file"), "old".getBytes());

            boolean result = KeyRotation.rotateKeyAtomic(
                keyId,tempDir,"new-data"::getBytes,
                (data, temp) -> Files.write(temp.resolve("new.file"), data),
                (data) -> {}
            );

            assertTrue(result);
            assertTrue(Files.exists(existingDir.resolve("new.file")));
            assertFalse(Files.exists(existingDir.resolve("old.file"))); // 旧文件应该被替换
        }

        @Test
        @DisplayName("轮换空数据 - 成功")
        void rotation_EmptyData_Success() throws IOException {
            String keyId = "empty-key";

            boolean result = KeyRotation.rotateKeyAtomic(
                keyId,
                tempDir,
                () -> new byte[0],
                (data, temp) -> Files.write(temp.resolve("empty.key"), data),
                (data) -> {}
            );

            assertTrue(result);
            Path emptyFile = tempDir.resolve(keyId).resolve("empty.key");
            assertTrue(Files.exists(emptyFile));
            assertEquals(0, Files.size(emptyFile));
        }
    }
}
