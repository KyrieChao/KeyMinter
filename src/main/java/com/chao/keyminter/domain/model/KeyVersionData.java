package com.chao.keyminter.domain.model;

import lombok.Builder;
import lombok.Data;
import java.util.Map;

/**
 * 密钥版本数据
 * 用于在存储层持久化完整的密钥版本（包含多个文件）
 */
@Data
@Builder
public class KeyVersionData {
    /**
     * 密钥ID
     */
    private String keyId;

    /**
     * 算法
     */
    private Algorithm algorithm;

    /**
     * 文件内容映射
     * Key: 文件名 (e.g. "secret.key", "status.info")
     * Value: 文件内容
     */
    private Map<String, byte[]> files;
}
