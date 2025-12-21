package key_minter.model.dto;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

import java.time.LocalDateTime;

/**
 * 密钥版本信息
 */
@Data
@AllArgsConstructor
@Builder
public class KeyVersion {
    private String keyId;
    private Algorithm algorithm;
    private LocalDateTime createdTime;
    private LocalDateTime activatedTime;
    private LocalDateTime expiredTime;
    private boolean active;
    private String keyPath;

    public KeyVersion(String keyId, Algorithm algorithm, String keyPath) {
        this.keyId = keyId;
        this.algorithm = algorithm;
        this.keyPath = keyPath;
        this.createdTime = LocalDateTime.now();
        this.active = false;
    }

    public boolean isExpired() {
        return expiredTime != null && LocalDateTime.now().isAfter(expiredTime);
    }

    public boolean isValid() {
        return !isExpired();
    }
}