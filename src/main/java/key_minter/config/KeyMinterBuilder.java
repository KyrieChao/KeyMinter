package key_minter.config;

import key_minter.model.dto.Algorithm;

public class KeyMinterBuilder {
    private Algorithm algorithm;
    private String preferredKeyId;

    public Algorithm getAlgorithm() {
        return algorithm;
    }

    public KeyMinterBuilder setAlgorithm(Algorithm algorithm) {
        this.algorithm = algorithm;
        return this;
    }

    public String getPreferredKeyId() {
        return preferredKeyId;
    }

    public KeyMinterBuilder setPreferredKeyId(String preferredKeyId) {
        this.preferredKeyId = preferredKeyId;
        return this;
    }
}

