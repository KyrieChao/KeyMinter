package com.chao.keyMinter.domain.port.out;

import java.nio.file.Path;

/**
 * KeyRepository Factory Interface.
 * Creates KeyRepository instances for a specific directory path.
 */
public interface KeyRepositoryFactory {
    /**
     * Create a KeyRepository for the specified path.
     * @param path The directory path where keys are stored.
     * @return A KeyRepository instance.
     */
    KeyRepository create(Path path);
}
