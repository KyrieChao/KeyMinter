package com.chao.key_minter_Test.service;

import jakarta.annotation.Resource;
import key_minter.auth.core.Jwt;
import key_minter.auth.decoder.JwtDecoder;
import key_minter.model.dto.Algorithm;
import key_minter.model.dto.JwtProperties;
import key_minter.model.dto.JwtStandardInfo;
import key_minter.util.KeyMinter;
import org.springframework.stereotype.Service;

@Service
public class TokenService {
    @Resource
    private KeyMinter key;

    public boolean createKey(Algorithm algorithm) {
        Jwt load = key.autoLoad(algorithm);
        return load.generateKeyPair(algorithm);
    }

    public <T> String generateToken(Algorithm algorithm, String keyId, JwtProperties properties, T t, Class<T> clazz) {
        Jwt load = key.autoLoad(algorithm, (String) null, keyId);
        return load.generateToken(properties, algorithm, t, clazz);
    }

    public boolean verify(Algorithm algorithm,String token) {
        key.switchTo(algorithm);
        return key.isValidToken(token);
    }

    public <T> T decodeCustomInfo(Algorithm algorithm, String token, Class<T> clazz) {
        Jwt load = key.autoLoad(algorithm);
        return JwtDecoder.decodeCustomClaimsSafe(token, load, clazz);
    }

    public JwtStandardInfo decodeStandardInfo(Algorithm algorithm, String token) {
        Jwt load = key.autoLoad(algorithm);
        return JwtDecoder.decodeStandardInfo(token, load);
    }

    public boolean isDecodable(Algorithm algorithm, String token) {
        Jwt load = key.autoLoad(algorithm);
        return JwtDecoder.isTokenDecodable(token, load);
    }

    public String getKeyInfo(Algorithm algorithm, String keyId) {
        Jwt load = key.autoLoad(algorithm, (String) null, keyId);
        return load.getKeyInfo();
    }

    public String getKeyVersions(Algorithm algorithm, String keyId) {
        Jwt load = key.autoLoad(algorithm, (String) null, keyId);
        return load.getKeyVersions().toString();
    }

    public int getSize() {
        return key.getCacheSize();
    }
}
