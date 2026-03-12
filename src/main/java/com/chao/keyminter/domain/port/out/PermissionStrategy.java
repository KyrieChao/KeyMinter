package com.chao.keyminter.domain.port.out;

import java.io.IOException;
import java.nio.file.Path;

/**
 * 权限控制策略接口
 * 负责跨平台的权限设置（Windows ACL / Linux POSIX）
 */
public interface PermissionStrategy {
    
    /**
     * 设置严格的文件/目录权限
     * 通常仅允许所有者读写（600/700）
     * @param path 文件或目录路径
     * @throws IOException IO异常
     */
    void setRestrictivePermissions(Path path) throws IOException;
    
    /**
     * 确保目录可访问（解决 Windows 下可能被系统锁定或权限继承问题）
     * @param dir 目录路径
     * @throws IOException IO异常
     */
    void ensureAccessible(Path dir) throws IOException;
}
