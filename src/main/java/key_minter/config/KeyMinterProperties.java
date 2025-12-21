package key_minter.config;

import key_minter.model.dto.Algorithm;
import lombok.Data;
import org.springframework.boot.context.properties.ConfigurationProperties;

@Data
@ConfigurationProperties("key-minter")
public class KeyMinterProperties {
    private Algorithm algorithm = Algorithm.HMAC256;
    private String keyDir;
    private boolean enableRotation = true;
    private String preferredKeyId;
    private boolean forceLoad = false;
    private boolean exportEnabled = false;
    private boolean metricsEnabled = true;
}

