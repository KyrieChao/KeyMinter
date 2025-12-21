package key_minter.security;

import java.nio.ByteBuffer;

/**
 * 安全密钥接口 - 提供内存保护功能
 */
public interface SecureSecret extends AutoCloseable {
    
    /**
     * 获取密钥字节数组（每次调用返回新副本）
     */
    byte[] getBytes();
    
    /**
     * 获取密钥字符数组（每次调用返回新副本）
     */
    char[] getChars();
    
    /**
     * 获取ByteBuffer视图（只读）
     */
    ByteBuffer asByteBuffer();
    
    /**
     * 立即清除内存中的密钥内容
     */
    void wipe();
    
    /**
     * 获取密钥长度
     */
    int length();
    
    /**
     * 是否已被清除
     */
    boolean isWiped();
    
    @Override
    default void close() {
        wipe();
    }
}