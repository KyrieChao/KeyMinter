package com.chao.keyMinter.adapter.out.fs;

import com.chao.keyMinter.domain.port.out.KeyRepository;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FileSystemKeyRepositoryFactoryTest {

    @Test
    void testCreate(@TempDir Path tempDir) {
        FileSystemKeyRepositoryFactory factory = new FileSystemKeyRepositoryFactory();
        KeyRepository repository = factory.create(tempDir);
        
        assertNotNull(repository);
        assertTrue(repository instanceof FileSystemKeyRepository);
    }
}


