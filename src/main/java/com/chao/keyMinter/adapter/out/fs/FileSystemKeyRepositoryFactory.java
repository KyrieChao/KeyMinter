package com.chao.keyMinter.adapter.out.fs;

import com.chao.keyMinter.domain.port.out.KeyRepository;
import com.chao.keyMinter.domain.port.out.KeyRepositoryFactory;
import java.nio.file.Path;

/**
 * FileSystemKeyRepository Factory
 */
public class FileSystemKeyRepositoryFactory implements KeyRepositoryFactory {
    @Override
    public KeyRepository create(Path path) {
        return new FileSystemKeyRepository(path);
    }
}
