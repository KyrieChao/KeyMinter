package com.chao.keyminter.adapter.out.fs;

import com.chao.keyminter.domain.port.out.KeyRepository;
import com.chao.keyminter.domain.port.out.KeyRepositoryFactory;
import java.nio.file.Path;

/**
 * FileSystemKeyRepository 的工厂实现
 */
public class FileSystemKeyRepositoryFactory implements KeyRepositoryFactory {
    @Override
    public KeyRepository create(Path path) {
        return new FileSystemKeyRepository(path);
    }
}
