package com.chao.keyminter.domain.port.out;

import com.chao.keyminter.domain.model.KeyVersionData;

import java.io.IOException;
import java.util.List;
import java.util.Optional;

/**
 * 密钥存储库接口 (Outbound Port)
 * 负责密钥文件的持久化、加载与删除
 * 支持文件系统、Redis、S3 等多种实现
 */
public interface KeyRepository {

    /**
     * 保存完整的密钥版本数据（原子操作）
     * 对应文件系统的目录创建和移动
     *
     * @param data 密钥版本数据
     * @throws IOException IO异常
     */
    void saveKeyVersion(KeyVersionData data) throws IOException;

    /**
     * 保存密钥文件内容
     *
     * @param keyId   密钥ID
     * @param fileName 文件名或类型标识 (如 "private.key", "public.key", "key.dat")
     * @param content 密钥内容（字节数组）
     * @throws IOException IO异常
     */
    void saveKey(String keyId, String fileName, byte[] content) throws IOException;

    /**
     * 加载密钥文件内容
     *
     * @param keyId    密钥ID
     * @param fileName 文件名或类型标识
     * @return 密钥内容，如果不存在则返回空
     * @throws IOException IO异常
     */
    Optional<byte[]> loadKey(String keyId, String fileName) throws IOException;

    /**
     * 删除整个密钥版本的所有数据
     *
     * @param keyId 密钥ID
     * @throws IOException IO异常
     */
    void delete(String keyId) throws IOException;

    /**
     * 检查密钥版本是否存在
     *
     * @param keyId 密钥ID
     * @return 是否存在
     */
    boolean exists(String keyId);

    /**
     * 列出指定前缀下的所有密钥ID
     *
     * @param prefix 前缀（用于过滤，如算法类型 "hmac-keys"）
     * @return 密钥ID列表
     * @throws IOException IO异常
     */
    List<String> listKeys(String prefix) throws IOException;

    /**
     * 保存元数据（如版本信息、状态信息）
     *
     * @param keyId   关联的密钥ID
     * @param metaKey 元数据键（如 "status.info", "expiration.info"）
     * @param content 元数据内容
     * @throws IOException IO异常
     */
    void saveMetadata(String keyId, String metaKey, String content) throws IOException;

    /**
     * 加载元数据
     *
     * @param keyId   关联的密钥ID
     * @param metaKey 元数据键
     * @return 元数据内容，不存在返回空
     * @throws IOException IO异常
     */
    Optional<String> loadMetadata(String keyId, String metaKey) throws IOException;

    /**
     * 删除元数据
     *
     * @param keyId   关联的密钥ID
     * @param metaKey 元数据键
     * @throws IOException IO异常
     */
    void deleteMetadata(String keyId, String metaKey) throws IOException;
}
