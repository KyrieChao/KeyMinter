package com.chao.keyminter.domain.model;

import lombok.Getter;

import java.util.Arrays;
import java.util.List;
import java.util.stream.Collectors;

@Getter
public enum Algorithm {
    // HMAC 算法
    HMAC256("HS256", "HMAC with SHA-256"),
    HMAC384("HS384", "HMAC with SHA-384"),
    HMAC512("HS512", "HMAC with SHA-512"),

    // RSA 算法
    RSA256("RS256", "RSA with SHA-256"),
    RSA384("RS384", "RSA with SHA-384"),
    RSA512("RS512", "RSA with SHA-512"),

    // ECDSA 算法
    ES256("ES256", "ECDSA with SHA-256"),
    ES384("ES384", "ECDSA with SHA-384"),
    ES512("ES512", "ECDSA with SHA-512"),

    // EdDSA 算法
    Ed25519("Ed25519", "EdDSA with Ed25519"),
    Ed448("Ed448", "EdDSA with Ed448");

    private final String name;
    private final String description;

    Algorithm(String name, String description) {
        this.name = name;
        this.description = description;
    }

    public boolean isHmac() {
        return this.name().startsWith("HMAC");
    }

    public boolean isRsa() {
        return this.name().startsWith("RSA");
    }

    public boolean isEcdsa() {
        return this.name().startsWith("ES");
    }

    public boolean isEddsa() {
        return this.name().startsWith("Ed");
    }

    public static Algorithm fromJwtName(String jwtName) {
        for (Algorithm algorithm : values()) {
            if (algorithm.name.equals(jwtName)) {
                return algorithm;
            }
        }
        throw new IllegalArgumentException("Unknown algorithm: " + jwtName);
    }

    public static List<Algorithm> getHmacAlgorithms() {
        return Arrays.stream(values())
                .filter(Algorithm::isHmac)
                .collect(Collectors.toList());
    }

    public static List<Algorithm> getRsaAlgorithms() {
        return Arrays.stream(values())
                .filter(Algorithm::isRsa)
                .collect(Collectors.toList());
    }

    public static List<Algorithm> getEcdsaAlgorithms() {
        return Arrays.stream(values())
                .filter(Algorithm::isEcdsa)
                .collect(Collectors.toList());
    }

    public static List<Algorithm> getEddsaAlgorithms() {
        return Arrays.stream(values())
                .filter(Algorithm::isEddsa)
                .collect(Collectors.toList());
    }
}
