package com.chao.keyMinter.domain.port.out;

import java.io.IOException;
import java.nio.file.Path;

/**
 * Permission Strategy Interface.
 * Abstraction for handling file system permissions (POSIX, Windows ACL).
 */
public interface PermissionStrategy {
    
    /**
     * Set restrictive permissions on a file or directory.
     * For example, 600 or 700 on POSIX.
     * @param path The path to secure.
     * @throws IOException If an I/O error occurs.
     */
    void setRestrictivePermissions(Path path) throws IOException;
    
    /**
     * Ensure the directory is accessible.
     * On Windows, this might handle specific ACL issues.
     * @param dir The directory to check.
     * @throws IOException If an I/O error occurs.
     */
    void ensureAccessible(Path dir) throws IOException;
}
