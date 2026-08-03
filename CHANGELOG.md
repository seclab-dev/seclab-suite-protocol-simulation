# Changelog

格式遵循 [Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/)，并遵循 [Semantic Versioning](https://semver.org/lang/zh-CN/)。

## [Unreleased]

### Added

- 首次发布协议仿真套件 API/UI 镜像和 engine workload 镜像。
- 支持导入协议仿真规则包并部署仿真实例。
- 支持 HTTP、Redis、SMTP、POP3、IMAP、SSH、FTP、RDP 协议仿真。
- 支持通过 Agent suite workload API 拉起和销毁规则容器。
- 支持实例审计、PCAP 取证、空包通知和浏览器预览能力。
- 前端接入 SecLab UI、SDL Token 和套件 SDK 的主题、语言、导航能力。

### Changed

- Agent 接入改为读取 SecLab 注入的统一运行时描述，在本地 UDS 和节点 HTTPS 环境使用相同业务客户端。
- 工作负载和抓包请求改用套件实例令牌授权，PCAP 完成接口直接接收二进制数据。
- HTTP 仿真规则的首屏 HTML 改为在套件内安全预览，不再依赖主控内置浏览器应用。

### Fixed

- 修复部署确认按钮可重复提交，导致同一端口创建重复实例的问题。
- 部署前检查实例端口与目标节点宿主机端口，冲突时显示本地化通知且不保留失败实例。
