package com.chao.keyMinter.domain.port.out;

import com.chao.keyMinter.domain.model.KeyVersionData;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * Key Repository Interface.
 * Abstraction for persistent key storage (File, Redis, S3, etc.).
 */
public interface KeyRepository {

    /**
     * Save a key version with all its associated files/metadata.
     *
     * @param data Key version data to save.
     * @throws IOException If an I/O error occurs.
     */
    void saveKeyVersion(KeyVersionData data) throws IOException;

    /**
     * Save a specific key file.
     *
     * @param keyId    Key ID.
     * @param fileName Filename (e.g. "private.key", "public.key", "key.dat").
     * @param content  File content bytes.
     * @throws IOException If an I/O error occurs.
     */
    void saveKey(String keyId, String fileName, byte[] content) throws IOException;

    /**
     * Load a specific key file.
     *
     * @param keyId    Key ID.
     * @param fileName Filename to load.
     * @return Optional containing the file content if found.
     * @throws IOException If an I/O error occurs.
     */
    Optional<byte[]> loadKey(String keyId, String fileName) throws IOException;

    /**
     * Delete a key version and all its files.
     *
     * @param keyId Key ID.
     * @throws IOException If an I/O error occurs.
     */
    void delete(String keyId) throws IOException;

    /**
     * Check if a key version exists.
     *
     * @param keyId Key ID.
     * @return True if exists, false otherwise.
     */
    boolean exists(String keyId);

    /**
     * List keys matching a specific prefix.
     *
     * @param prefix Prefix to match (e.g. "hmac-keys").
     * @return List of Key IDs.
     * @throws IOException If an I/O error occurs.
     */
    List<String> listKeys(String prefix) throws IOException;

    /**
     * Save metadata for a key.
     *
     * @param keyId   Key ID.
     * @param metaKey Metadata key (e.g. "status.info").
     * @param content Metadata content.
     * @throws IOException If an I/O error occurs.
     */
    void saveMetadata(String keyId, String metaKey, String content) throws IOException;

    /**
     * Load metadata for a key.
     *
     * @param keyId   Key ID.
     * @param metaKey Metadata key.
     * @return Optional containing the metadata content if found.
     * @throws IOException If an I/O error occurs.
     */
    Optional<String> loadMetadata(String keyId, String metaKey) throws IOException;

    /**
     * Delete metadata for a key.
     *
     * @param keyId   Key ID.
     * @param metaKey Metadata key.
     * @throws IOException If an I/O error occurs.
     */
    void deleteMetadata(String keyId, String metaKey) throws IOException;
}
