package com.chao.keyminter.adapter.out.fs;

import com.chao.keyminter.domain.port.out.PermissionStrategy;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * Linux/Unix/Mac 平台权限策略
 * 使用 POSIX 权限设置 (chmod)
 */
@Slf4j
public class PosixPermissionStrategy implements PermissionStrategy {

    @Override
    public void setRestrictivePermissions(Path path) throws IOException {
        try {
            // rw------- (600) for files, rwx------ (700) for directories
            Set<PosixFilePermission> perms;
            if (Files.isDirectory(path)) {
                perms = PosixFilePermissions.fromString("rwx------");
            } else {
                perms = PosixFilePermissions.fromString("rw-------");
            }
            Files.setPosixFilePermissions(path, perms);
        } catch (UnsupportedOperationException e) {
            log.warn("POSIX permissions not supported on this filesystem: {}", path);
        }
    }

    @Override
    public void ensureAccessible(Path dir) throws IOException {
        // POSIX 系统下通常不需要像 Windows 那样特殊的处理
        // 只要当前用户是 owner 且有 rw 权限即可
        if (!Files.isReadable(dir) || !Files.isWritable(dir)) {
             setRestrictivePermissions(dir);
        }
    }
}
