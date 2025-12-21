package key_minter.model.dto;

import lombok.Data;

import java.util.Map;

@Data
public class JwtFullInfo<T> {
    private JwtStandardInfo standardInfo;
    private T customClaims;
    private Map<String, Object> allClaims;
    
    // 便捷方法：获取自定义声明的特定字段
    public Object getCustomClaim(String key) {
        return allClaims != null ? allClaims.get(key) : null;
    }
    
    // 便捷方法：检查是否包含某个声明
    public boolean hasClaim(String key) {
        return allClaims != null && allClaims.containsKey(key);
    }
}