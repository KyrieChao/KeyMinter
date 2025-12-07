package com.chao.devtoolkit.factory;

import com.chao.devtoolkit.core.*;
import com.chao.devtoolkit.crypto.EcdsaJwt;
import com.chao.devtoolkit.crypto.EddsaJwt;
import com.chao.devtoolkit.crypto.HmacJwt;
import com.chao.devtoolkit.crypto.RsaJwt;

public class JwtFactory {
    
    public enum JwtType {
        HMAC,
        RSA, 
        ECDSA,
        ED25519,
        ED448
    }
    
    public static Jwt createJwt(JwtType type) {
        return createJwt(type, null, null, null);
    }
    
    public static Jwt createJwt(JwtType type, String directory) {
        return createJwt(type, directory, null, null);
    }
    
    public static Jwt createJwt(JwtType type, String directory, String privateKeyFile, String publicKeyFile) {
        return switch (type) {
            case HMAC -> {
                if (directory != null && privateKeyFile != null) {
                    yield new HmacJwt(directory, privateKeyFile);
                } else if (directory != null) {
                    yield new HmacJwt(directory);
                } else {
                    yield new HmacJwt();
                }
            }
            case RSA -> {
                if (directory != null && privateKeyFile != null && publicKeyFile != null) {
                    yield new RsaJwt(directory, privateKeyFile, publicKeyFile);
                } else if (directory != null) {
                    yield new RsaJwt(directory);
                } else {
                    yield new RsaJwt();
                }
            }
            case ECDSA -> {
                if (directory != null) {
                    yield new EcdsaJwt(directory);
                } else {
                    yield new EcdsaJwt();
                }
            }
            case ED25519, ED448 -> {
                if (directory != null) {
                    yield new EddsaJwt(directory);
                } else {
                    yield new EddsaJwt();
                }
            }
        };
    }

    // 便捷方法
    public static Jwt createHmacJwt() {
        return new HmacJwt();
    }

    public static Jwt createHmacJwt(String directory) {
        return new HmacJwt(directory);
    }

    public static Jwt createRsaJwt() {
        return new RsaJwt();
    }

    public static Jwt createRsaJwt(String directory) {
        return new RsaJwt(directory);
    }

    public static Jwt createEcdsaJwt() {
        return new EcdsaJwt();
    }

    public static Jwt createEcdsaJwt(String directory) {
        return new EcdsaJwt(directory);
    }

    public static Jwt createEddsaJwt() {
        return new EddsaJwt();
    }

    public static Jwt createEddsaJwt(String directory) {
        return new EddsaJwt(directory);
    }
}