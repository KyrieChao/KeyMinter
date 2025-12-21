package com.chao.key_minter_Test.controller;

import com.chao.key_minter_Test.model.KeysType;
import com.chao.key_minter_Test.model.Token;
import com.chao.key_minter_Test.model.Type;
import com.chao.key_minter_Test.model.UserInfo;
import com.chao.key_minter_Test.response.ApiResponse;
import com.chao.key_minter_Test.service.TokenService;
import jakarta.annotation.Resource;
import key_minter.model.dto.Algorithm;
import key_minter.model.dto.JwtProperties;
import key_minter.model.dto.JwtStandardInfo;
import org.springframework.web.bind.annotation.*;

import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.Map;

@RestController
@RequestMapping("/api")
public class TestController {

    @Resource
    private TokenService tokenService;

    @PostMapping("/add")
    public ApiResponse<String> add(@RequestBody Type o) {
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        boolean b = tokenService.createKey(algorithm);
        return ApiResponse.success(b + "");
    }

    @GetMapping("/get")
    public ApiResponse<Map<String, Object>> get(@RequestBody KeysType o) {
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        String keyId = (o.getKey() == null || o.getKey().isEmpty()) ? null : o.getKey();
        Map<String, Object> map = new HashMap<>();
        map.put("keyInfo", tokenService.getKeyInfo(algorithm, keyId));
        map.put("KeyVersions", tokenService.getKeyVersions(algorithm, keyId));
        return ApiResponse.success(map);
    }

    @GetMapping("/token")
    public ApiResponse<String> token(@RequestBody KeysType o) {
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        String keyId = (o.getKey() == null || o.getKey().isEmpty()) ? null : o.getKey();
        JwtProperties properties = JwtProperties.builder()
                .subject("sub")
                .issuer("issuer")
                .expiration(360000L).build();
        String token = tokenService.generateToken(algorithm, keyId, properties, toUserInfo(), UserInfo.class);
        return ApiResponse.success(token);
    }

    @GetMapping("/verify")
    public ApiResponse<String> verify(@RequestBody Token o) {
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        return ApiResponse.success(tokenService.verify(algorithm, o.getToken()) + "");
    }

    @GetMapping("/decode")
    public ApiResponse<Map<String, Object>> decode(@RequestBody Token o) {
        Algorithm algorithm = Algorithm.fromJwtName(o.getType());
        UserInfo userInfo = tokenService.decodeCustomInfo(algorithm, o.getToken(), UserInfo.class);
        JwtStandardInfo decoded = tokenService.decodeStandardInfo(algorithm, o.getToken());
        Map<String, Object> map = new LinkedHashMap<>();
        map.put("userInfo", userInfo);
        map.put("decoded", decoded);
        map.put("isDecodable", tokenService.isDecodable(algorithm, o.getToken()));
        map.put("size", tokenService.getSize());
        return ApiResponse.success(map);
    }

    private static UserInfo toUserInfo() {
        UserInfo userInfo = new UserInfo();
        userInfo.setUsername("username");
        userInfo.setRole("admin");
        userInfo.setAge(18);
        userInfo.setActive(true);
        userInfo.setPreferences(new UserInfo.Preferences("dark", "en"));
        return userInfo;
    }
}
