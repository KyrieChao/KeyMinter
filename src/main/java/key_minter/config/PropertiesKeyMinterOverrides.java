package key_minter.config;

import key_minter.model.dto.Algorithm;

public class PropertiesKeyMinterOverrides implements KeyMinterOverrides {
    private final KeyMinterProperties properties;

    public PropertiesKeyMinterOverrides(KeyMinterProperties properties) {
        this.properties = properties;
    }

    @Override
    public Algorithm algorithm() {
        return properties.getAlgorithm();
    }

    @Override
    public String preferredKeyId() {
        return properties.getPreferredKeyId();
    }
}

