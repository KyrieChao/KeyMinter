package key_minter.config;

import key_minter.model.dto.Algorithm;

public interface KeyMinterOverrides {
    Algorithm algorithm();
    String preferredKeyId();
}

