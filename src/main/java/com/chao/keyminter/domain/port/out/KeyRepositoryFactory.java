package com.chao.keyminter.domain.port.out;

import java.nio.file.Path;

/**
 * KeyRepository 工厂接口
 * 用于动态创建针对不同存储位置的 Repository 实例
 */
public interface KeyRepositoryFactory {
    /**
     * 创建针对特定文件系统路径的 Repository
     * @param path 存储路径（通常是算法特定的子目录）
     * @return Repository 实例
     */
    KeyRepository create(Path path);
}
