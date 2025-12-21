package com.chao.key_minter_Test.response;

import com.fasterxml.jackson.annotation.JsonInclude;
import lombok.Data;

import java.io.Serializable;
import java.time.LocalDateTime;
import java.time.format.DateTimeFormatter;

/**
 * 统一 HTTP 响应格式
 */
@Data
public class ApiResponse<T> implements Serializable {
    /**
     * 状态码
     */
    private int code;
    /**
     * 消息
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String message;
    /**
     * 数据
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private T data;
    /**
     * 时间戳
     */
    private String timestamp;
    /**
     * 描述
     */
    @JsonInclude(JsonInclude.Include.NON_NULL)
    private String description;

    private ApiResponse(int code, String message, T data, String description) {
        this.code = code;
        this.message = message;
        this.data = data;
        this.timestamp = LocalDateTime.now().format(DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss"));
        this.description = description;
    }

    // 成功 无数据
    public static <T> ApiResponse<T> success() {
        return new ApiResponse<>(HTTPResponseCode.SUCCESS.getCode(), "success", null, null);
    }

    // 成功 有数据
    public static <T> ApiResponse<T> success(T data) {
        return new ApiResponse<>(HTTPResponseCode.SUCCESS.getCode(), "success", data, null);
    }

    // 自定义消息
    public static <T> ApiResponse<T> success(String message, T data) {
        return new ApiResponse<>(HTTPResponseCode.SUCCESS.getCode(), message, data, null);
    }

    // 自定义错误消息 + 描述
    public static <T> ApiResponse<T> error(int code, String message, String description) {
        return new ApiResponse<>(code, message, null, description);
    }

    // 自定义错误消息 + 描述
    public static <T> ApiResponse<T> error(HTTPResponseCode HTTPResponseCode, String message, String description) {
        return new ApiResponse<>(HTTPResponseCode.getCode(), message, null, description);
    }

    // 错误消息 + 描述
    public static <T> ApiResponse<T> error(HTTPResponseCode HTTPResponseCode, String description) {
        return new ApiResponse<>(HTTPResponseCode.getCode(), HTTPResponseCode.getMessage(), null, description);
    }

    // 快速失败：只传枚举
    public static <T> ApiResponse<T> error(HTTPResponseCode errorCode) {
        return new ApiResponse<>(errorCode.getCode(), errorCode.getMessage(), null, errorCode.getDescription());
    }
}