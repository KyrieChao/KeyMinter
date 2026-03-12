# KeyMinter

![Build Status](https://img.shields.io/badge/build-passing-brightgreen)
![License](https://img.shields.io/badge/license-MIT-blue)
![Version](https://img.shields.io/badge/version-0.0.1--SNAPSHOT-orange)

KeyMinter 是一个功能强大的 Spring Boot Starter，专注于简化 JWT (JSON Web Token) 的密钥管理、自动轮换与全生命周期维护。它支持多种加密算法，提供开箱即用的密钥生成、存储、轮换及平滑过渡功能，特别适合构建安全、高可用的认证系统。

## ✨ 核心特性

- **多算法支持**：全面支持 HMAC (HS256/384/512), RSA (RS256/384/512), ECDSA (ES256/384/512), EdDSA (Ed25519/Ed448)。
- **密钥自动轮换**：内置密钥轮换机制，支持配置轮换周期、提前轮换时间及过渡期。
- **平滑迁移**：支持算法热切换（如从 HMAC 迁移到 RSA），在切换期间旧算法/旧密钥签发的 Token 依然有效（Graceful Period）。
- **全生命周期管理**：支持密钥的生成 (Created)、激活 (Active)、过渡 (Transitioning)、过期 (Expired) 和吊销 (Revoked) 状态管理。
- **分布式支持**：集成 Redis 支持分布式锁（防止多实例并发轮换）和 Token 黑名单管理。
- **便捷 API**：提供流畅的 Token 生成、验证、解析（支持泛型自定义 Claims）接口。
- **开箱即用**：零配置即可运行（默认 HMAC256），也可通过 `application.yml` 深度定制。

## 📦 安装

### 环境要求
- JDK 17+
- Spring Boot 3.x

### Maven 依赖

在你的 `pom.xml` 中添加依赖：

```xml
<dependency>
    <groupId>com.chao</groupId>
    <artifactId>KeyMinter</artifactId>
    <version>0.0.1-SNAPSHOT</version>
</dependency>
```

确保你的项目已经集成了 `spring-boot-starter`。如果需要使用 Redis 功能，请添加 `spring-boot-starter-data-redis`。

## 🚀 快速开始

### 1. 注入 KeyMinter

```java
@Autowired
private KeyMinter key;
```

### 2. 生成 Token

```java
// 1. 准备 Token 属性
JwtProperties props = JwtProperties.builder()
        .subject("user-123")
        .issuer("MyAuthServer")
        .expiration(Instant.now().plus(Duration.ofHours(1)))
        .build();

// 2. 生成 Token (使用默认算法)
String token = key.generateToken(props);
System.out.println("Token: " + token);
```

### 3. 验证与解析

```java
// 验证 Token 有效性
if (key.isValidToken(token)) {
    // 解析标准信息
    JwtStandardInfo info = key.getStandardInfo(token);
    System.out.println("User: " + info.getSubject());
}
```

## 💡 进阶使用

### 1. 携带自定义 Payload (支持泛型)

```java
// 定义你的用户信息类
@Data
class UserInfo {
    private Long id;
    private String role;
}

// 生成带自定义信息的 Token
UserInfo user = new UserInfo(1001L, "ADMIN");
String token = key.generateToken(props, user, UserInfo.class);

// 解析回对象
UserInfo decodedUser = key.decodeToObject(token, UserInfo.class);
```

### 2. 切换算法与密钥轮换

```java
// 切换到 RSA256 (上下文切换，此时可能尚未生成密钥)
key.switchTo(Algorithm.RSA256);

// 创建新的密钥对（触发轮换）
key.createKeyPair(Algorithm.RSA256);

// 此时，旧密钥签发的 Token 在过渡期内仍然有效
// 如果需要立即激活特定密钥：
// key.setActiveKey("key-version-id");
```

### 3. 算法平滑迁移

```java
// 假设当前是 HMAC256
key.switchTo(Algorithm.HMAC256);
String oldToken = key.generateToken(props);

// 切换到 Ed25519
key.switchTo(Algorithm.Ed25519);

// KeyMinter 会自动尝试用新算法验证，失败后尝试用旧算法验证（Graceful Period）
boolean isValid = key.isValidToken(oldToken); // true
```

## ⚙️ 配置说明

在 `application.yml` 中配置：

```yaml
key-minter:
  # 密钥存储目录 (默认为临时目录)
  key-dir: /data/keys
  
  # 默认算法 (HMAC256, RSA256, ES256, Ed25519 等)
  algorithm: HMAC256
  
  # 是否启用自动轮换
  enable-rotation: true
  
  # 密钥有效期（天）
  key-validity-days: 90
  
  # 轮换过渡期（小时）：旧密钥在此期间仍有效
  transition-period-hours: 24
  
  # Redis 配置（可选）
  lock:
    redis-enabled: true # 启用分布式锁
  blacklist:
    redis-enabled: true # 启用 Redis 黑名单
```

## 🛠️ 架构设计

- **KeyMinter**: 核心门面类，负责算法调度、生命周期管理。
- **JwtFactory**: 算法实例工厂，管理不同算法的单例与缓存。
- **JwtAlgo**: 算法抽象策略接口，实现具体的签名/验签逻辑。
- **LockProvider**: 分布式锁接口，支持本地锁和 Redis 锁。
- **KeyRepository**: 密钥存储接口，支持文件系统等多种后端。

## 🧪 测试

本项目包含完善的单元测试和集成测试。运行测试：

```bash
mvn clean test
```

## 📝 License

MIT License
