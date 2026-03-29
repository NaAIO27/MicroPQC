# MicroPQC

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Rust](https://img.shields.io/badge/rust-2021-orange.svg)](https://blog.rust-lang.org/2021/10/21/Rust-1.56.0.html)

一个为嵌入式系统设计的 `no_std` 兼容后量子密码学库。

[English](README.md) | [Deutsch](README.de.md)

## 简介

MicroPQC 是一个轻量级、安全的后量子密码学实现，专为资源受限的嵌入式设备优化。目前实现了 **Kyber**（NIST 标准化的密钥封装机制，ML-KEM）。

### 特性

- Kyber 支持：实现 Kyber512、Kyber768、Kyber1024 三种安全等级
- `no_std` 兼容：无需标准库，适用于裸机嵌入式环境
- 常量时间操作：防止时序攻击
- 敏感数据清零：使用 `zeroize` 自动清除密钥等敏感数据
- 纯安全 Rust：`#![deny(unsafe_code)]`，100% 安全代码

## 快速开始

### 依赖

在 `Cargo.toml` 中添加：

```toml
[dependencies]
micropqc = "0.1.0"
```

### 示例代码

```rust
use micropqc::{Kyber512, Kem};

// 生成密钥对
let mut rng = MyRng::new();
let (pk, sk) = Kyber512::keypair(&mut rng)?;

// 封装
let (ct, ss) = Kyber512::encapsulate(&mut rng, &pk)?;

// 解封装
let ss2 = Kyber512::decapsulate(&ct, &sk)?;
assert_eq!(ss.as_ref(), ss2.as_ref());
```

## 功能特性

| 特性 | 描述 | 默认 |
|------|------|------|
| `kyber512` | Kyber-512 安全等级 | 是 |
| `kyber768` | Kyber-768 安全等级 | 否 |
| `kyber1024` | Kyber-1024 安全等级 | 否 |
| `std` | 启用标准库支持 | 否 |

### 切换安全等级

```toml
[dependencies]
micropqc = { version = "0.1.0", default-features = false, features = ["kyber768"] }
```

## 密钥尺寸

| 参数 | 公钥大小 | 私钥大小 | 密文大小 | 共享密钥 |
|------|----------|----------|----------|----------|
| Kyber512 | 800 字节 | 768 字节 | 768 字节 | 32 字节 |
| Kyber768 | 1184 字节 | 1152 字节 | 1088 字节 | 32 字节 |
| Kyber1024 | 1568 字节 | 1536 字节 | 1568 字节 | 32 字节 |

## 安全等级

- **Kyber512**: NIST 安全等级 1（约等于 AES-128）
- **Kyber768**: NIST 安全等级 3（约等于 AES-192）
- **Kyber1024**: NIST 安全等级 5（约等于 AES-256）

## 平台支持

- x86_64
- ARM Cortex-M
- RISC-V
- WebAssembly (wasm32)

## 构建

```bash
# 标准构建
cargo build --release

# 运行测试
cargo test

# 构建文档
cargo doc --no-deps
```

## 许可证

本项目采用 [MIT License](LICENSE) 许可证。

## 贡献

欢迎提交 Issue 和 Pull Request！

## 致谢

- 基于 [Kyber](https://pq-crystals.org/kyber/) 参考实现
- 感谢 NIST 后量子密码学标准化工作

---

**注意**: 本项目处于早期开发阶段，API 可能会发生变化。在生产环境使用前请充分测试。
