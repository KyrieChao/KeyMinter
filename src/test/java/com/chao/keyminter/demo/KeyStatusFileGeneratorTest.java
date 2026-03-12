package com.chao.keyminter.demo;

import com.chao.keyminter.adapter.in.spring.KeyMinterAutoConfiguration;
import com.chao.keyminter.domain.model.KeyStatus;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.context.annotation.Import;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.util.FileSystemUtils;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;

import static org.junit.jupiter.api.Assertions.assertTrue;

/**
 * 这是一个演示测试，用于在磁盘上生成不同 KeyStatus 的密钥文件目录结构。
 * 运行此测试后，您可以在项目根目录下的 'key-status-demo' 文件夹中查看生成的密钥文件。
 */
@SpringBootTest(classes = KeyMinterAutoConfiguration.class)
@Import(KeyMinterAutoConfiguration.class)
@ActiveProfiles("test") // 确保使用测试配置，避免影响生产环境
public class KeyStatusFileGeneratorTest {

    private static final String DEMO_OUTPUT_DIR = "key-status-demo";

    @Test
    @DisplayName("Generate key directories for all KeyStatus values")
    void generateKeyStatusFiles() throws IOException {
        // 1. 准备输出目录
        Path outputRoot = Paths.get(DEMO_OUTPUT_DIR).toAbsolutePath();
        if (Files.exists(outputRoot)) {
            FileSystemUtils.deleteRecursively(outputRoot);
        }
        Files.createDirectories(outputRoot);
        System.out.println("Generating key status demo files in: " + outputRoot);

        // 2. 生成 ACTIVE 状态密钥 (通过 KeyMinter API)
        // KeyMinter 初始化时会自动生成一个 ACTIVE 密钥
        generateActiveKey(outputRoot);

        // 3. 生成 TRANSITIONING 状态密钥 (通过 KeyRotation)
        generateTransitioningKey(outputRoot);

        // 4. 生成 CREATED 状态密钥 (模拟)
        generateCreatedKey(outputRoot);

        // 5. 生成 INACTIVE 状态密钥 (模拟)
        generateInactiveKey(outputRoot);

        // 6. 生成 EXPIRED 状态密钥 (模拟)
        generateExpiredKey(outputRoot);

        // 7. 生成 REVOKED 状态密钥 (模拟)
        generateRevokedKey(outputRoot);

        System.out.println("==================================================");
        System.out.println("Key status generation completed!");
        System.out.println("Check the folder: " + outputRoot);
        System.out.println("==================================================");
        
        // 简单验证文件是否存在
        assertTrue(Files.exists(outputRoot.resolve("01_created/status.info")));
        assertTrue(Files.exists(outputRoot.resolve("02_active/status.info")));
        assertTrue(Files.exists(outputRoot.resolve("03_transitioning/status.info")));
        assertTrue(Files.exists(outputRoot.resolve("04_inactive/status.info")));
        assertTrue(Files.exists(outputRoot.resolve("05_expired/status.info")));
        assertTrue(Files.exists(outputRoot.resolve("06_revoked/status.info")));
    }

    private void generateActiveKey(Path root) throws IOException {
        Path targetDir = root.resolve("02_active");
        Files.createDirectories(targetDir);
        
        // 模拟 ACTIVE 状态文件内容
        // 实际上 KeyMinter 会生成公私钥对，这里为了演示重点生成 status.info
        createMockKeyFiles(targetDir, KeyStatus.ACTIVE);
    }

    private void generateTransitioningKey(Path root) throws IOException {
        Path targetDir = root.resolve("03_transitioning");
        Files.createDirectories(targetDir);
        
        // 模拟 TRANSITIONING 状态
        createMockKeyFiles(targetDir, KeyStatus.TRANSITIONING);
    }

    private void generateCreatedKey(Path root) throws IOException {
        Path targetDir = root.resolve("01_created");
        Files.createDirectories(targetDir);
        
        createMockKeyFiles(targetDir, KeyStatus.CREATED);
    }

    private void generateInactiveKey(Path root) throws IOException {
        Path targetDir = root.resolve("04_inactive");
        Files.createDirectories(targetDir);
        
        createMockKeyFiles(targetDir, KeyStatus.INACTIVE);
    }

    private void generateExpiredKey(Path root) throws IOException {
        Path targetDir = root.resolve("05_expired");
        Files.createDirectories(targetDir);
        
        createMockKeyFiles(targetDir, KeyStatus.EXPIRED);
    }

    private void generateRevokedKey(Path root) throws IOException {
        Path targetDir = root.resolve("06_revoked");
        Files.createDirectories(targetDir);
        
        createMockKeyFiles(targetDir, KeyStatus.REVOKED);
    }

    private void createMockKeyFiles(Path dir, KeyStatus status) throws IOException {
        // 1. 写入 status.info
        Path statusFile = dir.resolve("status.info");
        Files.writeString(statusFile, status.name());

        // 2. 写入 dummy key files (模拟公私钥存在)
        Files.writeString(dir.resolve("private.key"), "-----BEGIN PRIVATE KEY-----\nMOCK_PRIVATE_KEY_CONTENT_FOR_" + status + "\n-----END PRIVATE KEY-----");
        Files.writeString(dir.resolve("public.key"), "-----BEGIN PUBLIC KEY-----\nMOCK_PUBLIC_KEY_CONTENT_FOR_" + status + "\n-----END PUBLIC KEY-----");
        
        // 3. 写入 expiration.info (如果是 EXPIRED，设置过期时间为过去)
        // 否则设置为未来
        Path expiryFile = dir.resolve("expiration.info");
        long now = System.currentTimeMillis();
        long expiryTime;
        
        if (status == KeyStatus.EXPIRED) {
            expiryTime = now - 10000; // 10秒前过期
        } else {
            expiryTime = now + 3600000; // 1小时后过期
        }
        Files.writeString(expiryFile, String.valueOf(expiryTime));
        
        System.out.println("Generated " + status + " key files in " + dir);
    }
}
