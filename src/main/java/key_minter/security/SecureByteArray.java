package key_minter.security;

import lombok.extern.slf4j.Slf4j;

import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;

/**
 * 安全字节数组 - 提供内存保护
 */
@Slf4j
public final class SecureByteArray implements SecureSecret {

    private byte[] data;
    private final AtomicBoolean wiped = new AtomicBoolean(false);

    private SecureByteArray(byte[] data) {
        if (data == null) {
            throw new IllegalArgumentException("Data cannot be null");
        }
        this.data = data.clone(); // 深度拷贝
    }

    private SecureByteArray(char[] chars) {
        if (chars == null) {
            throw new IllegalArgumentException("Chars cannot be null");
        }
        // 将char[]转换为byte[]
        ByteBuffer buffer = StandardCharsets.UTF_8.encode(CharBuffer.wrap(chars));
        this.data = new byte[buffer.remaining()];
        buffer.get(this.data);

        // 清除原始char[]
        Arrays.fill(chars, '\0');
    }

    /**
     * 从byte[]创建安全实例
     */
    public static SecureByteArray fromBytes(byte[] bytes) {
        return new SecureByteArray(bytes);
    }

    /**
     * 从char[]创建安全实例
     */
    public static SecureByteArray fromChars(char[] chars) {
        return new SecureByteArray(chars);
    }

    /**
     * 从String创建安全实例
     */
    public static SecureByteArray fromString(String str) {
        if (str == null) {
            throw new IllegalArgumentException("String cannot be null");
        }
        return fromChars(str.toCharArray());
    }

    /**
     * 生成随机密钥
     */
    public static SecureByteArray random(int length) {
        byte[] randomBytes = new byte[length];
        new SecureRandom().nextBytes(randomBytes);
        return fromBytes(randomBytes);
    }

    @Override
    public byte[] getBytes() {
        checkWiped();
        return data.clone(); // 返回副本
    }

    // 添加辅助方法到SecureByteArray
    public <T> T useBytes(java.util.function.Function<byte[], T> function) {
        // 先获取当前状态的快照
        final boolean wasWiped = this.isWiped();
        final int length = this.length();

        if (wasWiped) {
            throw new IllegalStateException("Cannot use bytes from wiped secret");
        }

        byte[] bytes = null;
        try {
            // 获取字节数组
            bytes = this.getBytes();  // 如果在这之后被清理，会抛出异常

            // 验证数组
            if (bytes == null || bytes.length != length) {
                throw new IllegalStateException("Secret data corrupted");
            }

            return function.apply(bytes);
        } catch (IllegalStateException e) {
            // 密钥在获取后被清理了
            log.error("Secret was wiped during useBytes operation", e);
//            throw new IllegalStateException("Secret became unavailable during operation", e);
            return null;
        } finally {
            // 安全清理
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    @Override
    public char[] getChars() {
        checkWiped();
        CharBuffer charBuffer = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(data));
        char[] chars = new char[charBuffer.remaining()];
        charBuffer.get(chars);
        return chars;
    }

    @Override
    public ByteBuffer asByteBuffer() {
        checkWiped();
        return ByteBuffer.wrap(data).asReadOnlyBuffer();
    }

    @Override
    public void wipe() {
        if (wiped.compareAndSet(false, true) && data != null) {
            // 多次覆盖以防御冷启动攻击
            byte[] zero = new byte[data.length];
            Arrays.fill(zero, (byte) 0);
            Arrays.fill(zero, (byte) 0xFF);
            Arrays.fill(zero, (byte) 0);

            // 覆盖实际数据
            SecureRandom random = new SecureRandom();
            for (int i = 0; i < 3; i++) {
                random.nextBytes(zero);
                System.arraycopy(zero, 0, data, 0, data.length);
            }
            // 最后填充0
            Arrays.fill(data, (byte) 0);
            data = null; // 帮助GC
        }
    }

    @Override
    public int length() {
        return data != null ? data.length : 0;
    }

    @Override
    public boolean isWiped() {
        return wiped.get();
    }

    private void checkWiped() {
        if (isWiped()) {
            throw new IllegalStateException("Secret has been wiped");
        }
        if (data == null) {
            throw new IllegalStateException("Secret data is null");
        }
    }

    @Override
    protected void finalize() throws Throwable {
        try {
            wipe();
        } finally {
            super.finalize();
        }
    }

    /**
     * 比较两个安全密钥（常量时间，防止时序攻击）
     */
    public boolean constantTimeEquals(SecureByteArray other) {
        if (other == null || this.isWiped() || other.isWiped()) {
            return false;
        }
        byte[] a = this.data;
        byte[] b = other.data;

        if (a.length != b.length) {
            return false;
        }

        int result = 0;
        for (int i = 0; i < a.length; i++) {
            result |= a[i] ^ b[i];
        }
        return result == 0;
    }
}