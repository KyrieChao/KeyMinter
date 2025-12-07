package com.chao.devtoolkit.model;

import lombok.AllArgsConstructor;
import lombok.Data;
import lombok.NoArgsConstructor;

// POJO类定义
@Data
@AllArgsConstructor
@NoArgsConstructor
public class UserInfo {
    private String username;
    private String role;
    private int age;
    private boolean active;
    private Preferences preferences;

    @Data
    @AllArgsConstructor
    @NoArgsConstructor
    public static class Preferences {
        private String theme;
        private String language;
    }
}