package com.chao.keyMinter.internal;

import org.junit.jupiter.api.Test;

import java.nio.ByteBuffer;

import static org.junit.jupiter.api.Assertions.*;

class SecureSecretTest {

    @Test
    void close_should_delegate_to_wipe() {
        // Arrange
        class TestSecret implements SecureSecret {
            private boolean wiped;

            @Override
            public byte[] getBytes() {
                return new byte[]{1};
            }

            @Override
            public char[] getChars() {
                return new char[]{'a'};
            }

            @Override
            public ByteBuffer asByteBuffer() {
                return ByteBuffer.wrap(getBytes()).asReadOnlyBuffer();
            }

            @Override
            public void wipe() {
                wiped = true;
            }

            @Override
            public int length() {
                return 1;
            }

            @Override
            public boolean isWiped() {
                return wiped;
            }
        }

        TestSecret secret = new TestSecret();

        // Act
        secret.close();

        // Assert
        assertTrue(secret.isWiped());
    }
}

