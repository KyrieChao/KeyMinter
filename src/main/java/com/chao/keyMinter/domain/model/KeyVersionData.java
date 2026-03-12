package com.chao.keyMinter.domain.model;

import lombok.Builder;
import lombok.Data;
import java.util.Map;

/**
 * Key Version Data.
 * Contains the actual key material/content (e.g. secret keys, certificates).
 */
@Data
@Builder
public class KeyVersionData {
    /**
     * Key ID.
     */
    private String keyId;

    /**
     * Algorithm.
     */
    private Algorithm algorithm;

    /**
     * Key Files Content.
     * Key: Filename (e.g. "secret.key", "status.info")
     * Value: File content bytes
     */
    private Map<String, byte[]> files;
}
