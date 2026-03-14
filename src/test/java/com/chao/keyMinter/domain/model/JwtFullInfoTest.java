package com.chao.keyMinter.domain.model;

import org.junit.jupiter.api.Test;

import java.util.Date;
import java.util.HashMap;
import java.util.Map;

import static org.junit.jupiter.api.Assertions.*;

class JwtFullInfoTest {

    @Test
    void testConstructorAndGettersSetters() {
        // 创建测试数据
        JwtStandardInfo standardInfo = JwtStandardInfo.builder()
                .subject("test-subject")
                .issuer("test-issuer")
                .issuedAt(new Date())
                .expiration(new Date(System.currentTimeMillis() + 3600000))
                .build();

        CustomClaims customClaims = new CustomClaims("test-user", "admin");

        Map<String, Object> allClaims = new HashMap<>();
        allClaims.put("sub", "test-subject");
        allClaims.put("iss", "test-issuer");
        allClaims.put("username", "test-user");
        allClaims.put("role", "admin");

        // 创建JwtFullInfo实例
        JwtFullInfo<CustomClaims> jwtFullInfo = new JwtFullInfo<>();
        jwtFullInfo.setStandardInfo(standardInfo);
        jwtFullInfo.setCustomClaims(customClaims);
        jwtFullInfo.setAllClaims(allClaims);

        // 验证getter方法
        assertEquals(standardInfo, jwtFullInfo.getStandardInfo());
        assertEquals(customClaims, jwtFullInfo.getCustomClaims());
        assertEquals(allClaims, jwtFullInfo.getAllClaims());
    }

    @Test
    void testGetCustomClaimWithNonNullAllClaims() {
        // 创建测试数据
        Map<String, Object> allClaims = new HashMap<>();
        allClaims.put("username", "test-user");
        allClaims.put("role", "admin");

        JwtFullInfo<CustomClaims> jwtFullInfo = new JwtFullInfo<>();
        jwtFullInfo.setAllClaims(allClaims);

        // 测试存在的键
        assertEquals("test-user", jwtFullInfo.getCustomClaim("username"));
        assertEquals("admin", jwtFullInfo.getCustomClaim("role"));

        // 测试不存在的键
        assertNull(jwtFullInfo.getCustomClaim("non-existent"));
    }

    @Test
    void testGetCustomClaimWithNullAllClaims() {
        JwtFullInfo<CustomClaims> jwtFullInfo = new JwtFullInfo<>();
        jwtFullInfo.setAllClaims(null);

        // 测试allClaims为null的情况
        assertNull(jwtFullInfo.getCustomClaim("username"));
    }

    @Test
    void testHasClaimWithNonNullAllClaims() {
        // 创建测试数据
        Map<String, Object> allClaims = new HashMap<>();
        allClaims.put("username", "test-user");
        allClaims.put("role", "admin");

        JwtFullInfo<CustomClaims> jwtFullInfo = new JwtFullInfo<>();
        jwtFullInfo.setAllClaims(allClaims);

        // 测试存在的键
        assertTrue(jwtFullInfo.hasClaim("username"));
        assertTrue(jwtFullInfo.hasClaim("role"));

        // 测试不存在的键
        assertFalse(jwtFullInfo.hasClaim("non-existent"));
    }

    @Test
    void testHasClaimWithNullAllClaims() {
        JwtFullInfo<CustomClaims> jwtFullInfo = new JwtFullInfo<>();
        jwtFullInfo.setAllClaims(null);

        // 测试allClaims为null的情况
        assertFalse(jwtFullInfo.hasClaim("username"));
    }

    // 用于测试的自定义声明类
    private static class CustomClaims {
        private String username;
        private String role;

        public CustomClaims(String username, String role) {
            this.username = username;
            this.role = role;
        }

        public String getUsername() {
            return username;
        }

        public String getRole() {
            return role;
        }
    }
}
