package com.chao.keyminter.core;

import com.chao.keyminter.adapter.in.KeyMinterProperties;
import com.chao.keyminter.domain.service.JwtAlgo;
import com.chao.keyminter.domain.model.Algorithm;
import com.chao.keyminter.domain.port.out.KeyRepository;
import com.chao.keyminter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyminter.domain.port.out.SecretDirProvider;
import com.chao.keyminter.adapter.out.fs.FileSystemKeyRepository;

import java.nio.file.Path;

/**
 * 转接
 */
public class Prep {

    /**
     * 自动加载首个密钥的核心方法
     */
    public static JwtAlgo FirstKey(Algorithm algorithm, Path path, boolean force) {
        JwtAlgo jwtAlgo = get(algorithm, path);
        if (jwtAlgo instanceof AbstractJwtAlgo abs) {
            jwtAlgo = abs.autoLoadFirstKey(algorithm, force);
        }
        return jwtAlgo;
    }

    /**
     * 自动加载指定密钥ID的核心方法
     */
    public static JwtAlgo WithKeyId(Algorithm algorithm, Path path, String keyId, boolean force) {
        JwtAlgo jwtAlgo = get(algorithm, path);

        if (jwtAlgo instanceof AbstractJwtAlgo abs) {
            jwtAlgo = abs.autoLoadFirstKey(algorithm, keyId, force);
        }
        return jwtAlgo;
    }

    /**
     * 核心构造逻辑
     */
    private static JwtAlgo get(Algorithm algorithm, Path path) {
        // Fallback or test method
        KeyMinterProperties props = new KeyMinterProperties();
        return getPre(algorithm, path, props, null);
    }

    public static JwtAlgo getPre(Algorithm algorithm, Path keyDir, KeyMinterProperties props) {
        return getPre(algorithm, keyDir, props, null);
    }

    public static JwtAlgo getPre(Algorithm algorithm, Path keyDir, KeyMinterProperties props, KeyRepositoryFactory repoFactory) {
        return switch (algorithm) {
            case HMAC256, HMAC384, HMAC512 -> new HmacJwt(props, createRepo(keyDir, "hmac-keys", repoFactory));
            case RSA256, RSA384, RSA512 -> new RsaJwt(props, createRepo(keyDir, "rsa-keys", repoFactory));
            case ES256, ES384, ES512 -> new EcdsaJwt(props, keyDir);
            case Ed25519, Ed448 -> new EddsaJwt(props, keyDir);
        };
    }
    
    private static KeyRepository createRepo(Path baseDir, String subDir, KeyRepositoryFactory factory) {
        Path path = baseDir != null ? baseDir.resolve(subDir) : SecretDirProvider.getDefaultBaseDir().resolve(subDir);
        if (factory != null) {
            return factory.create(path);
        }
        return new FileSystemKeyRepository(path);
    }
}
