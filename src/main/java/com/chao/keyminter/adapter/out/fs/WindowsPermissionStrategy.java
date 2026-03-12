package com.chao.keyminter.adapter.out.fs;

import com.chao.keyminter.domain.port.out.PermissionStrategy;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Windows 平台权限策略
 * 使用 icacls 或 NIO ACL 设置权限
 */
@Slf4j
public class WindowsPermissionStrategy implements PermissionStrategy {

    @Override
    public void setRestrictivePermissions(Path path) throws IOException {
        try {
            // 1. 尝试使用 icacls 命令 (更可靠)
            setWindowsPermissionsViaIcacls(path);
        } catch (Exception e) {
            log.warn("Failed to set Windows permissions via icacls: {}, falling back to NIO", e.getMessage());
            // 2. 备选：使用 Java NIO
            setWindowsPermissionsViaNio(path);
        }
    }

    @Override
    public void ensureAccessible(Path dir) throws IOException {
        // Windows 上尝试设置为非隐藏、非系统
        try {
            DosFileAttributeView dosView = Files.getFileAttributeView(dir, DosFileAttributeView.class);
            if (dosView != null) {
                dosView.setHidden(false);
                dosView.setSystem(false);
            }
            // 确保当前用户有权访问
            setRestrictivePermissions(dir);
        } catch (Exception e) {
            log.warn("Failed to ensure directory accessibility: {}", e.getMessage());
        }
    }

    private void setWindowsPermissionsViaIcacls(Path path) throws Exception {
        String userName = System.getProperty("user.name");
        ProcessBuilder pb = new ProcessBuilder(
                "icacls", path.toAbsolutePath().toString(),
                "/grant", userName + ":F",
                "/T"
        );
        pb.redirectErrorStream(true);
        Process process = pb.start();
        
        try (var reader = new java.io.BufferedReader(new java.io.InputStreamReader(process.getInputStream()))) {
            while (reader.readLine() != null) {
                // 忽略输出
            }
        }
        
        int exitCode = process.waitFor();
        if (exitCode != 0) {
            throw new IOException("icacls command failed with exit code " + exitCode);
        }
    }

    private void setWindowsPermissionsViaNio(Path path) throws IOException {
        AclFileAttributeView aclView = Files.getFileAttributeView(path, AclFileAttributeView.class);
        if (aclView != null) {
            UserPrincipal currentUser = Files.getOwner(path);
            List<AclEntry> aclEntries = new ArrayList<>();

            // 当前用户完全控制
            aclEntries.add(AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(currentUser)
                    .setPermissions(AclEntryPermission.values()) // Full control
                    .build());

            // 尝试添加管理员组
            try {
                UserPrincipalLookupService lookupService = path.getFileSystem().getUserPrincipalLookupService();
                UserPrincipal administrators = lookupService.lookupPrincipalByName("Administrators");
                aclEntries.add(AclEntry.newBuilder()
                        .setType(AclEntryType.ALLOW)
                        .setPrincipal(administrators)
                        .setPermissions(AclEntryPermission.values())
                        .build());
            } catch (Exception e) {
                log.debug("Could not add Administrators group: {}", e.getMessage());
            }

            aclView.setAcl(aclEntries);
        }
    }
}
