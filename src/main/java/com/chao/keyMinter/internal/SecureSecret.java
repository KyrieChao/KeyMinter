package com.chao.keyMinter.internal;

import java.nio.ByteBuffer;

/**
 * Secure Secret Interface.
 * Abstraction for sensitive data that needs to be wiped from memory after use.
 */
public interface SecureSecret extends AutoCloseable {
    
    /**
     * Get the secret bytes.
     * NOTE: The caller is responsible for wiping the returned array after use.
     */
    byte[] getBytes();
    
    /**
     * Get the secret chars.
     * NOTE: The caller is responsible for wiping the returned array after use.
     */
    char[] getChars();
    
    /**
     * Get as read-only ByteBuffer.
     */
    ByteBuffer asByteBuffer();
    
    /**
     * Wipe the internal data.
     */
    void wipe();
    
    /**
     * Get the length of the secret.
     */
    int length();
    
    /**
     * Check if the secret has been wiped.
     */
    boolean isWiped();
    
    @Override
    default void close() {
        wipe();
    }
}
