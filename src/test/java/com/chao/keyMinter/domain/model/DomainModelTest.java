package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class DomainModelTest {

    @Test
    void testKeyVersionStatusLogic() {
        KeyVersion kv = KeyVersion.builder()
                .keyId("k1")
                .status(KeyStatus.CREATED)
                .build();

        // 1. Created
        assertEquals(KeyStatus.CREATED, kv.getStatus());
        assertFalse(kv.canSign());
        assertFalse(kv.canVerify());

        // 2. Active
        kv.activate();
        assertEquals(KeyStatus.ACTIVE, kv.getStatus());
        assertNotNull(kv.getActivatedTime());
        assertTrue(kv.canSign());
        assertTrue(kv.canVerify());
        assertFalse(kv.isInTransitionPeriod());

        // 3. Transitioning
        Instant transitionEnd = Instant.now().plus(1, ChronoUnit.HOURS);
        kv.startTransition(transitionEnd);
        assertEquals(KeyStatus.TRANSITIONING, kv.getStatus());
        assertTrue(kv.isInTransitionPeriod());
        assertTrue(kv.canSign()); // Transitioning key CAN sign tokens according to KeyStatus definition
        assertTrue(kv.canVerify()); // But can verify

        // 4. Inactive but in transition
        kv.deactivate();
        assertEquals(KeyStatus.INACTIVE, kv.getStatus());
        assertNotNull(kv.getDeactivatedTime());
        assertTrue(kv.isInTransitionPeriod()); // Still within transition time
        assertTrue(kv.canVerify());

        // 5. Inactive and transition ended
        kv.setTransitionEndsAt(Instant.now().minus(1, ChronoUnit.SECONDS));
        assertFalse(kv.isInTransitionPeriod());
        assertFalse(kv.canVerify());

        // 6. Expired by time
        kv.setStatus(KeyStatus.ACTIVE);
        kv.setExpiresAt(Instant.now().minus(1, ChronoUnit.SECONDS));
        assertEquals(KeyStatus.EXPIRED, kv.getStatus()); // Auto-detect expiry
        assertTrue(kv.isExpired());
        assertEquals(0, kv.getRemainingSeconds());

        // 7. Revoked
        kv.revoke();
        assertEquals(KeyStatus.REVOKED, kv.getStatus());
        assertFalse(kv.canSign());
        assertFalse(kv.canVerify());
        
        // 8. Explicit Mark Expired
        kv.setStatus(KeyStatus.ACTIVE);
        kv.markExpired();
        assertEquals(KeyStatus.EXPIRED, kv.getStatus());
        
        // 9. Remaining seconds
        kv.setExpiresAt(Instant.now().plus(1, ChronoUnit.HOURS));
        assertTrue(kv.getRemainingSeconds() > 0);
        
        // 10. Constructor
        KeyVersion kv2 = new KeyVersion("k2", Algorithm.HMAC256, "path");
        assertEquals("k2", kv2.getKeyId());
        assertEquals(Algorithm.HMAC256, kv2.getAlgorithm());
        assertEquals("path", kv2.getKeyPath());
    }

    @Test
    void testJwtFullInfo() {
        JwtFullInfo<String> info = new JwtFullInfo<>();
        assertNull(info.getCustomClaim("foo"));
        assertFalse(info.hasClaim("foo"));

        Map<String, Object> claims = new HashMap<>();
        claims.put("foo", "bar");
        info.setAllClaims(claims);

        assertEquals("bar", info.getCustomClaim("foo"));
        assertTrue(info.hasClaim("foo"));
        assertNull(info.getCustomClaim("baz"));
        
        // Lombok methods
        info.setCustomClaims("custom");
        assertEquals("custom", info.getCustomClaims());
        JwtStandardInfo std = JwtStandardInfo.builder().subject("sub").build();
        info.setStandardInfo(std);
        assertEquals(std, info.getStandardInfo());
        
        JwtFullInfo<String> info2 = new JwtFullInfo<>();
        info2.setAllClaims(claims);
        info2.setCustomClaims("custom");
        info2.setStandardInfo(std);
        
        assertEquals(info, info2);
        assertEquals(info.hashCode(), info2.hashCode());
        assertNotNull(info.toString());
    }

    @Test
    void testJwtStandardInfo() {
        JwtStandardInfo info = JwtStandardInfo.builder()
                .subject("sub")
                .issuer("iss")
                .build();

        // Expiration logic
        assertEquals(0, info.getRemainingTime()); // Null expiration
        assertTrue(info.isExpired()); // Null expiration considered expired (remaining 0)

        info.setExpiration(new java.util.Date(System.currentTimeMillis() + 10000));
        assertTrue(info.getRemainingTime() > 0);
        assertFalse(info.isExpired());

        info.setExpiration(new java.util.Date(System.currentTimeMillis() - 10000));
        assertTrue(info.getRemainingTime() <= 0);
        assertTrue(info.isExpired());
        
        // Lombok
        JwtStandardInfo info2 = JwtStandardInfo.builder().subject("sub").issuer("iss").expiration(info.getExpiration()).build();
        assertEquals(info, info2);
        assertNotNull(info.toString());
    }
    
    @Test
    void testKeyVersionData() {
        KeyVersionData data = KeyVersionData.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .files(Collections.singletonMap("f1", new byte[]{1, 2, 3}))
                .build();
        
        assertEquals("k1", data.getKeyId());
        assertEquals(Algorithm.HMAC256, data.getAlgorithm());
        assertEquals(1, data.getFiles().size());
        
        // NoArgs constructor not available with @Builder unless @NoArgsConstructor is added
        // So we test builder updates
        KeyVersionData data2 = KeyVersionData.builder()
                .keyId("k1")
                .algorithm(Algorithm.HMAC256)
                .files(Collections.singletonMap("f1", new byte[]{1, 2, 3}))
                .build();
        
        assertEquals(data.getKeyId(), data2.getKeyId());
        assertEquals(data.getAlgorithm(), data2.getAlgorithm());
        assertEquals(data.getFiles().keySet(), data2.getFiles().keySet());
        assertNotNull(data.toString());
    }
    
    @Test
    void testJwtProperties() {
        JwtProperties props = new JwtProperties("sub", "iss", Instant.now());
        assertEquals("sub", props.getSubject());
        
        JwtProperties props2 = JwtProperties.builder()
                .subject("sub")
                .issuer("iss")
                .expiration(props.getExpiration())
                .build();
        
        assertEquals(props, props2);
        
        JwtProperties props3 = new JwtProperties();
        props3.setSubject("sub");
    }
}



