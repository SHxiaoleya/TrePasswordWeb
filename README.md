# 🔐 The Password Web

一个轻量、可本地运行的密码管理器网站项目。  
支持主密码解锁与本地加密存储，并提供 APK 发行版本（通过 PakePlus 打包）。

> 本仓库仅包含前端源码。  
> --Android APK 请在 **GitHub Releases** 页面下载。--

---

## ✨ 项目功能

- 添加密码条目（名称、账号、密码、可选备注）
- 随机生成强密码
- 修改、删除已有条目
- 一键复制账号/密码
- 关键词搜索（名称/账号/备注）
- 主密码解锁
- 本地 AES-GCM 加密存储（`localStorage` 中为密文）
- 支持 2FA 动态密码添加

---

## 🎨 UI 风格

- 浅蓝色 + 浅粉色主题
- 卡片式布局
- 简洁、移动端友好

---

## 🔒 安全说明

- 本项目为**纯前端本地存储方案**，数据保存在用户设备浏览器存储中。
- 密码库内容通过 Web Crypto API（PBKDF2 + AES-GCM）加密后保存。
- 主密码不会明文存储，请务必牢记。若遗忘，无法解密已有数据。

> 提示：本项目适合个人轻量使用与学习用途。  
> 对于高安全场景，建议结合系统级安全存储、云端同步策略与专业审计方案。

---

## 📁 项目结构

```text
.
├── index.html
├── security.html
├── style.css
└── script.js
```

---

## 🚀 本地运行

1. 下载或克隆仓库
2. 直接用浏览器打开`index.html`即可运行。

---

## 📦 APK 发行说明

--本项目 Android 安装包由开源工具**PakePlus**打包生成。--
--源码仍以本仓库前端代码为准，APK 仅在 Releases 发布。--
- --下载地址：https://github.com/SHxiaoleya/ThePasswordWeb/releases--
由于发布时多次编译失败，本项目不再提供 APK 安装包，你可以自行下载打包。

---

## 🙏 致谢

特别感谢开源项目**PakePlus**，用于将本项目网页封装为 Android APK：
- PakePlus: https://github.com/Sjj1024/PakePlus

---

## 📄 License

本项目基于 MIT License 开源。
