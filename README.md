# KeyMinter
[![Java CI with Maven](https://github.com/KyrieChao/KeyMinter/actions/workflows/ci.yml/badge.svg)](https://github.com/KyrieChao/KeyMinter/actions/workflows/ci.yml)
[![codecov](https://codecov.io/gh/KyrieChao/KeyMinter/branch/main/graph/badge.svg)](https://codecov.io/gh/KyrieChao/KeyMinter)
[![Java 17+](https://img.shields.io/badge/Java-17+-orange.svg)](https://www.oracle.com/java/technologies/downloads/)
[![Spring Boot 3](https://img.shields.io/badge/Spring%20Boot-3.x-brightgreen.svg)](https://spring.io/projects/spring-boot)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
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

## 🧪 测试与覆盖率

本项目采用 JUnit 5 进行单元测试，使用 Jacoco 统计代码覆盖率。

### 运行测试

```bash
mvn clean test
```

### 查看覆盖率报告

测试运行完成后，覆盖率报告将生成在 `target/site/jacoco/index.html`。
可以直接在浏览器中打开该文件查看详细的覆盖率数据。

目前核心模块覆盖率已大幅提升，关键组件（KeyMinter, KeyMinterProperties）覆盖率较高。

### 最佳实践与设计模式

- **策略模式 (Strategy Pattern)**: `JwtAlgo` 接口及其实现类 (`HmacJwt`, `RsaJwt` 等) 采用了策略模式，允许在运行时动态切换加密算法。
- **工厂模式 (Factory Pattern)**: `JwtFactory` 负责创建和管理 `JwtAlgo` 实例，确保单例复用及按需加载。
- **状态模式 (State Pattern)**: `KeyStatus` 枚举管理密钥生命周期状态，控制密钥的可用性。

### 潜在改进建议

1.  **解耦构造函数依赖**: 目前 `HmacJwt` 等实现类在构造函数中初始化 `FileSystemKeyRepository`，建议改为依赖注入或通过 Builder 模式传入，以提高可测试性。
2.  **明确权限策略**: `setRestrictiveFilePermissions` 方法目前为空实现，建议移除或重新实现以明确文件权限管理职责。
3.  **细化状态控制**: `KeyStatus.TRANSITIONING` 状态目前允许签名，建议根据业务需求评估是否应限制为只读（仅验签）。

## 🤝 贡献指南

欢迎贡献代码！请阅读 [CONTRIBUTING.md](CONTRIBUTING.md) 了解如何提交 Pull Request 和报告问题。

## 📅 更新日志

查看 [CHANGELOG.md](CHANGELOG.md) 了解版本更新详情。

## 📝 License

Apache License 2.0
---

**Author:** [KyrieChao](https://github.com/KyrieChao)