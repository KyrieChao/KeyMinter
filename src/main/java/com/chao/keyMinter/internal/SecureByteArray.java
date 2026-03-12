package com.chao.keyMinter.internal;

import lombok.extern.slf4j.Slf4j;

import java.lang.ref.Cleaner;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.function.Function;

/**
 * Secure Byte Array Implementation.
 * Wipes data on close/finalize.
 */
@Slf4j
public final class SecureByteArray implements SecureSecret, AutoCloseable {

    private static final Cleaner CLEANER = Cleaner.create();
    private static final ThreadLocal<SecureRandom> RND = ThreadLocal.withInitial(SecureRandom::new);

    private byte[] data;
    private final AtomicBoolean wiped = new AtomicBoolean(false);
    private final Cleaner.Cleanable cleanable;

    private SecureByteArray(byte[] data) {
        if (data == null) throw new IllegalArgumentException("Data cannot be null");
        this.data = data.clone();
        this.cleanable = CLEANER.register(this, new WipeAction(this.data));
    }

    public static SecureByteArray fromBytes(byte[] bytes) {
        return new SecureByteArray(bytes);
    }

    public static SecureByteArray fromChars(char[] src) {
        if (src == null) throw new IllegalArgumentException("Chars cannot be null");
        ByteBuffer bb = StandardCharsets.UTF_8.encode(CharBuffer.wrap(src));
        byte[] tmp = new byte[bb.remaining()];
        bb.get(tmp);
        Arrays.fill(src, '\0');
        SecureByteArray sba = fromBytes(tmp);
        Arrays.fill(tmp, (byte) 0);
        return sba;
    }

    public static SecureByteArray fromString(String str) {
        if (str == null) throw new IllegalArgumentException("String cannot be null");
        return fromChars(str.toCharArray());
    }

    public static SecureByteArray random(int len) {
        byte[] tmp = new byte[len];
        RND.get().nextBytes(tmp);
        SecureByteArray sba = fromBytes(tmp);
        Arrays.fill(tmp, (byte) 0);
        return sba;
    }

    @Override
    public byte[] getBytes() {
        checkWiped();
        return data.clone();
    }

    public <T> T useBytes(Function<byte[], T> function) {
        final boolean wasWiped = this.isWiped();
        final int length = this.length();

        if (wasWiped) {
            throw new IllegalStateException("Cannot use bytes from wiped secret");
        }

        byte[] bytes = null;
        try {
            bytes = this.getBytes();
            if (bytes == null || bytes.length != length) {
                throw new IllegalStateException("Secret data corrupted");
            }
            return function.apply(bytes);
        } catch (IllegalStateException e) {
            log.error("Secret was wiped during useBytes operation", e);
            throw e;
        } finally {
            if (bytes != null) {
                Arrays.fill(bytes, (byte) 0);
            }
        }
    }

    @Override
    public char[] getChars() {
        checkWiped();
        CharBuffer cb = StandardCharsets.UTF_8.decode(ByteBuffer.wrap(data));
        char[] out = new char[cb.remaining()];
        cb.get(out);
        return out;
    }

    @Override
    public ByteBuffer asByteBuffer() {
        checkWiped();
        return ByteBuffer.wrap(data).asReadOnlyBuffer();
    }

    @Override
    public void wipe() {
        if (wiped.compareAndSet(false, true) && data != null) {
            overwrite(data);
            data = null;
            cleanable.clean();
        }
    }

    @Override
    public void close() {
        wipe();
    }

    @Override
    public int length() {
        return wiped.get() ? 0 : data.length;
    }

    @Override
    public boolean isWiped() {
        return wiped.get();
    }

    private void checkWiped() {
        if (isWiped()) throw new IllegalStateException("Secret has been wiped");
        if (data == null) throw new IllegalStateException("Secret data is null");
    }

    public boolean constantTimeEquals(SecureByteArray other) {
        if (other == null || this.wiped.get() || other.wiped.get()) return false;
        return MessageDigest.isEqual(this.data, other.data);
    }

    /* ---------- Helper Methods ---------- */
    private static void overwrite(byte[] buf) {
        SecureRandom rnd = RND.get();
        byte[] noise = new byte[buf.length];
        for (int i = 0; i < 3; i++) {
            rnd.nextBytes(noise);
            for (int j = 0; j < buf.length; j++) buf[j] ^= noise[j];
        }
        Arrays.fill(buf, (byte) 0);
        Arrays.fill(noise, (byte) 0);
    }

    /* ---------- Cleaner Action ---------- */
        private record WipeAction(byte[] target) implements Runnable {
        @Override
            public void run() {
                if (target != null) overwrite(target);
            }
        }
}
