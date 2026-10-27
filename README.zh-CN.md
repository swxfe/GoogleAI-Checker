# Google AI Checker

[English](README.md) · [Русский](README.ru.md) · [简体中文](README.zh-CN.md) · [فارسی](README.fa.md)

检测你的 Throne 配置能否访问 Google AI Studio。

最多同时检测 10 个配置。本地测试中，**52 个配置约 8 秒**；实际耗时取决于代理和网络。

![Google AI Checker 演示配置](assets/demo.png)

*截图使用演示配置，并非实际检测结果。*

## 使用

从 [Releases](../../releases) 下载 ZIP，并完整解压。压缩包已包含 Throne。

1. 打开检测器，选择你的 Throne 数据库。
2. 选择浏览器，点击**登录**；登录 Google 后，点击**完成**。
3. 选择分组并点击**开始**。**↻** 可重新检测单个配置，**复制**可复制配置的 JSON。

检测器通过官方 Throne 核心并行请求 AI Studio。收到模型列表才确认可用；延迟包括代理连接和 HTTPS 请求。结果及登录数据保存在程序旁的 `sandbox_data/` 中。在 Throne 中修改配置后，点击**刷新**。

## 系统

| 系统 | 构建状态 |
| --- | --- |
| Windows x64（DirectX 12） | ZIP 已构建并验证 |
| Linux x64 桌面 | CI 已配置，尚未验证构建 |
| macOS Intel / Apple Silicon | CI 已配置，尚未验证构建 |

目前仅 Windows ZIP 已构建并验证。Linux 和 macOS 仍需成功运行 CI。

## 构建

需要 Rust 1.98+（2024 edition）、C/C++ 工具链（Windows 使用 MSVC）、Git、CMake、Perl、libclang 和 curl。

```sh
cargo xtask dist
```

ZIP 和校验文件生成在 `target/dist/`。更新 Throne 时，只需修改 [`throne-version.txt`](throne-version.txt) 中的版本号。`xtask` 会找到对应的压缩包，从 GitHub 获取 SHA-256，并完成下载和打包。

GitHub Actions 已配置为在推送 `v*` 标签时构建四个发布包并上传至 GitHub Releases。翻译位于 `locales/`；所有语言均使用 `en.json` 中的英文原文作为键。

## 致谢

[Throne](https://github.com/throneproj/Throne) 提供代理核心和配置管理，其 [API](https://github.com/throneproj/Throne-api) 是本工具的基础。字体来自 [Noto](https://fonts.google.com/noto)，旗帜来自 [Twemoji](https://github.com/jdecked/twemoji)。第三方许可见 `FONT-LICENSES.txt`。
