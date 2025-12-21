package com.chao.key_minter_Test.response;

import lombok.Getter;

/**
 * 错误码
 *
 * @author Chao
 */
@Getter
public enum HTTPResponseCode {


    // ==================== 1xx 信息性状态码 ====================
    CONTINUE(100, "Continue", "继续请求"),
    SWITCHING_PROTOCOLS(101, "Switching Protocols", "切换协议"),

    // ==================== 2xx 成功状态码 ====================
    SUCCESS(200, "Success", "操作成功"),
    CREATED(201, "Created", "创建成功"),
    ACCEPTED(202, "Accepted", "已接受请求"),
    NO_CONTENT(204, "No Content", "无内容返回"),

    // ==================== 3xx 重定向状态码 ====================
    MOVED_PERMANENTLY(301, "Moved Permanently", "永久重定向"),
    FOUND(302, "Found", "临时重定向"),
    NOT_MODIFIED(304, "Not Modified", "资源未修改"),

    // ==================== 4xx 客户端错误状态码 ====================
    // 400 Bad Request 相关
    BAD_REQUEST(400, "Bad Request", "请求语法错误"),
    PARAM_ERROR(40000, "Parameter Error", "请求参数错误"),
    PARAM_MISSING(40001, "Parameter Missing", "必要参数缺失"),
    PARAM_INVALID(40002, "Parameter Invalid", "参数格式无效"),
    PARAM_TYPE_MISMATCH(40003, "Parameter Type Mismatch", "参数类型不匹配"),
    PARAM_LENGTH_INVALID(40004, "Parameter Length Invalid", "参数长度无效"),

    // 401 Unauthorized 相关
    UNAUTHORIZED(401, "Unauthorized", "未认证或认证失败"),
    UNAUTHORIZED_EXTENDED(40100, "Unauthorized", "用户未登录或登录已过期"),
    TOKEN_EXPIRED(40101, "Token Expired", "访问令牌已过期"),
    TOKEN_INVALID(40102, "Token Invalid", "访问令牌无效"),
    TOKEN_REFRESH_REFUSED(40103, "Token Refresh Refused", "拒绝刷新令牌"),
    TOKEN_NOT_LATEST(40104, "Token Not Latest", "访问令牌不是最新版本"),
    TOKEN_STILL_VALID(40105, "Token Still Valid", "访问令牌仍然有效"),

    // 403 Forbidden 相关
    FORBIDDEN(403, "Forbidden", "无权限访问资源"),
    FORBIDDEN_EXTENDED(40300, "Forbidden", "访问被禁止"),
    PERMISSION_DENIED(40301, "Permission Denied", "权限不足"),
    ROLE_ERROR(40302, "Role Error", "用户角色错误"),
    ACCESS_DENIED(40303, "Access Denied", "访问被拒绝"),

    // 404 Not Found 相关
    NOT_FOUND(404, "Not Found", "资源不存在"),
    DATA_NOT_FOUND(40400, "Data Not Found", "请求数据不存在"),
    USER_NOT_FOUND(40401, "User Not Found", "用户不存在"),
    RESOURCE_NOT_FOUND(40402, "Resource Not Found", "请求资源不存在"),
    API_NOT_FOUND(40403, "API Not Found", "接口不存在"),

    // 405 Method Not Allowed 相关
    METHOD_NOT_ALLOWED(405, "Method Not Allowed", "HTTP方法不允许"),
    // 危险代码
    DANGEROUS_CODE(40501, "Dangerous Code", "危险代码"),

    // 409 Conflict 相关
    CONFLICT(409, "Conflict", "资源冲突"),
    DATA_ALREADY_EXISTS(40900, "Data Already Exists", "数据已存在"),
    RESOURCE_CONFLICT(40901, "Resource Conflict", "资源状态冲突"),

    // 415 Unsupported Media Type 相关
    UNSUPPORTED_MEDIA_TYPE(415, "Unsupported Media Type", "不支持的媒体类型"),
    UNSUPPORTED_KEY_TYPE(40106, "Unsupported Key Type", "不支持的密钥类型"),
    UNSUPPORTED_LANGUAGE_TYPE(40107, "Unsupported Language Type", "不支持的编程语言类型"),
    UNSUPPORTED_OPERATION_TYPE(41501, "Unsupported Operation Type", "操作不支持类型"),

    // 422 Unprocessable Entity 相关
    UNPROCESSABLE_ENTITY(422, "Unprocessable Entity", "请求格式正确，但语义错误"),
    DATA_VALIDATION_FAILED(42200, "Data Validation Failed", "数据验证失败"),

    // 429 Too Many Requests 相关
    TOO_MANY_REQUESTS(429, "Too Many Requests", "请求过于频繁"),
    RATE_LIMIT_EXCEEDED(42900, "Rate Limit Exceeded", "请求频率超限"),

    // ==================== 5xx 服务端错误状态码 ====================
    // 500 Internal Server Error 相关
    INTERNAL_SERVER_ERROR(500, "Internal Server Error", "服务器内部错误"),
    SYSTEM_ERROR(50000, "System Error", "系统内部异常"),
    SERVICE_UNAVAILABLE(50001, "Service Unavailable", "服务暂时不可用"),
    DATABASE_ERROR(50002, "Database Error", "数据库操作异常"),
    REMOTE_SERVICE_ERROR(50003, "Remote Service Error", "上游服务调用失败"),
    THIRD_PARTY_SERVICE_ERROR(50004, "Third Party Service Error", "第三方服务异常"),

    // 501 Not Implemented 相关
    NOT_IMPLEMENTED(501, "Not Implemented", "功能未实现"),

    // 502 Bad Gateway 相关
    BAD_GATEWAY(502, "Bad Gateway", "网关错误"),

    // 503 Service Unavailable 相关
    SERVICE_UNAVAILABLE_EXTENDED(503, "Service Unavailable", "服务不可用"),

    // ==================== 业务操作错误码 ====================
    // 业务操作失败 6xxxx
    OPERATION_FAILED(60000, "Operation Failed", "操作失败"),
    CREATE_FAILED(60001, "Create Failed", "创建失败"),
    UPDATE_FAILED(60002, "Update Failed", "更新失败"),
    DELETE_FAILED(60003, "Delete Failed", "删除失败"),
    QUERY_FAILED(60004, "Query Failed", "查询失败"),
    UPLOAD_FAILED(60005, "Upload Failed", "上传失败"),
    DOWNLOAD_FAILED(60006, "Download Failed", "下载失败"),

    // 用户相关错误 7xxxx
    USER_OPERATION_ERROR(70000, "User Operation Error", "用户操作失败"),
    USER_PASSWORD_ERROR(70001, "User Password Error", "用户密码错误"),
    USER_ACCOUNT_DISABLED(70002, "User Account Disabled", "用户账户已禁用"),
    USER_ACCOUNT_LOCKED(70003, "User Account Locked", "用户账户已锁定"),
    USER_CREDENTIALS_EXPIRED(70004, "User Credentials Expired", "用户凭证已过期"),

    // 系统状态相关 8xxxx
    SYSTEM_BUSY(80000, "System Busy", "系统繁忙，请稍后再试"),
    SYSTEM_MAINTENANCE(80001, "System Maintenance", "系统维护中"),
    SYSTEM_OVERLOAD(80002, "System Overload", "系统过载"),

    // 数据相关错误 9xxxx
    DATA_TOO_LARGE(90000, "Data Too Large", "数据过大"),
    DATA_FORMAT_ERROR(90001, "Data Format Error", "数据格式错误"),
    DATA_INTEGRITY_ERROR(90002, "Data Integrity Error", "数据完整性错误");

    /**
     * 状态码
     */
    private final int code;

    /**
     * 状态码信息
     */
    private final String message;

    /**
     * 状态码描述（详情）
     */
    private final String description;

    HTTPResponseCode(int code, String message, String description) {
        this.code = code;
        this.message = message;
        this.description = description;
    }

}