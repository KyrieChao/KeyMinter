package com.chao.keyMinter.adapter.out.fs;

import com.chao.keyMinter.domain.port.out.PermissionStrategy;
import lombok.extern.slf4j.Slf4j;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermission;
import java.nio.file.attribute.PosixFilePermissions;
import java.util.Set;

/**
 * Linux/Unix/Mac Permission Strategy
 * Uses POSIX permissions (chmod)
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
        // POSIX systems check permissions
        // Ensure owner has rw access
        if (!Files.isReadable(dir) || !Files.isWritable(dir)) {
             setRestrictivePermissions(dir);
        }
    }
}
