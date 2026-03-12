package com.chao.keyMinter.adapter.out.fs;

import com.chao.keyMinter.domain.port.out.PermissionStrategy;
import lombok.extern.slf4j.Slf4j;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.*;
import java.util.ArrayList;
import java.util.List;

/**
 * Windows Permission Strategy
 * Uses icacls or NIO ACL
 */
@Slf4j
public class WindowsPermissionStrategy implements PermissionStrategy {

    @Override
    public void setRestrictivePermissions(Path path) throws IOException {
        try {
            // 1. Try icacls first
            setWindowsPermissionsViaIcacls(path);
        } catch (Exception e) {
            log.warn("Failed to set Windows permissions via icacls: {}, falling back to NIO", e.getMessage());
            // 2. Fallback to Java NIO
            setWindowsPermissionsViaNio(path);
        }
    }

    @Override
    public void ensureAccessible(Path dir) {
        // Windows hidden file attribute check
        try {
            DosFileAttributeView dosView = Files.getFileAttributeView(dir, DosFileAttributeView.class);
            if (dosView != null) {
                dosView.setHidden(false);
                dosView.setSystem(false);
            }
            // Ensure permissions
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

        try (var reader = new BufferedReader(new InputStreamReader(process.getInputStream()))) {
            String line;
            while ((line = reader.readLine()) != null) {
                log.debug("icacls output: {}", line);
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

            // Allow current user full control
            aclEntries.add(AclEntry.newBuilder()
                    .setType(AclEntryType.ALLOW)
                    .setPrincipal(currentUser)
                    .setPermissions(AclEntryPermission.values()) // Full control
                    .build());

            // Try adding Administrators group
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
