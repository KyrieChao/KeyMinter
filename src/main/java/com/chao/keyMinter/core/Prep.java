package com.chao.keyMinter.core;

import com.chao.keyMinter.adapter.in.KeyMinterProperties;
import com.chao.keyMinter.domain.service.JwtAlgo;
import com.chao.keyMinter.domain.model.Algorithm;
import com.chao.keyMinter.domain.port.out.KeyRepository;
import com.chao.keyMinter.domain.port.out.KeyRepositoryFactory;
import com.chao.keyMinter.domain.port.out.SecretDirProvider;
import com.chao.keyMinter.adapter.out.fs.FileSystemKeyRepository;

import java.nio.file.Path;

/**
 * Preparation Helper
 */
public class Prep {

    /**
     * Auto-load first key
     */
    public static JwtAlgo FirstKey(Algorithm algorithm, Path path, boolean force) {
        JwtAlgo jwtAlgo = get(algorithm, path);
        if (jwtAlgo instanceof AbstractJwtAlgo abs) {
            jwtAlgo = abs.autoLoadFirstKey(algorithm, force);
        }
        return jwtAlgo;
    }

    /**
     * Auto-load with Key ID
     */
    public static JwtAlgo WithKeyId(Algorithm algorithm, Path path, String keyId, boolean force) {
        JwtAlgo jwtAlgo = get(algorithm, path);

        if (jwtAlgo instanceof AbstractJwtAlgo abs) {
            jwtAlgo = abs.autoLoadFirstKey(algorithm, keyId, force);
        }
        return jwtAlgo;
    }

    /**
     * Get or create algorithm instance
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
            case HMAC256, HMAC384, HMAC512 -> {
                if (repoFactory != null) {
                    yield new HmacJwt(props, createRepo(keyDir, "hmac-keys", repoFactory));
                }
                yield new HmacJwt(props, keyDir);
            }
            case RSA256, RSA384, RSA512 -> {
                if (repoFactory != null) {
                    yield new RsaJwt(props, createRepo(keyDir, "rsa-keys", repoFactory));
                }
                yield new RsaJwt(props, keyDir);
            }
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
