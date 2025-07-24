# 🔐 jarmor-pack

**Securely pack .jar files into encrypted `.enc` archives using Rust.**  
Supports multiple modern encryption algorithms (AES-GCM, ChaCha20, AES-CBC+HMAC).

![GitHub release](https://img.shields.io/github/v/release/6pheR/jarmor-pack?include_prereleases&label=release)
![Build](https://github.com/6pheR/jarmor-pack/actions/workflows/release.yml/badge.svg)

---

## ✨ Features

- 🔐 Encrypt `.jar` files into `.enc` format
- 🧱 Algorithms:
  - `aes256gcm` (default)
  - `aes128gcm`
  - `xchacha20`
  - `aescbc_hmac` (AES-CBC + HMAC-SHA256)
- 🔑 Key derivation via HKDF (SHA-256)
- ⚡ Fast and lightweight CLI written in Rust

---

## 📦 Download

You can download prebuilt binaries from the [Releases page](https://github.com/6pheR/jarmor-pack/releases):

| Platform         | Binary                                 |
|------------------|-----------------------------------------|
| Linux x86_64     | `jarmor-pack-linux-x86_64`              |
| Linux (musl)     | `jarmor-pack-linux-musl-x86_64`         |
| macOS (Intel)    | `jarmor-pack-macos-x86_64`              |
| macOS (M1/M2)    | `jarmor-pack-macos-arm64`               |
| Windows          | `jarmor-pack-windows-x86_64.exe`        |

---

## 🚀 Usage

```bash
jarmor-pack pack -i test.jar -o output.enc -k "your-password" -a aes256gcm
```

### 📖 Full help

```bash
jarmor-pack --help
```

---

## 🔧 Build from source

```bash
cargo build --release
```

To cross-compile:

```bash
rustup target add x86_64-unknown-linux-musl
cargo build --release --target x86_64-unknown-linux-musl
```

---

## 📚 License

MIT © [6pheR](https://github.com/6pheR)
