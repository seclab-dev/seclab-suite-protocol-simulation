# SecLab 协议仿真套件

本仓库维护协议仿真套件源码。套件交付包、`suite.yaml`、`compose.yaml` 和套件版本发布由 `seclab-suites` 仓库维护。

## 目录

| 路径 | 说明 |
| --- | --- |
| `crates/protocol-simulation` | 套件 API 服务，负责规则库、实例状态、PCAP 记录和 Agent suite workload API 调用。 |
| `crates/protocol-simulation-engine` | 协议仿真 workload 进程，由 Agent 按规则拉起独立容器。 |
| `crates/protocol-simulation-common` | API 与 engine 共享模型。 |
| `frontend` | 套件控制台前端。 |
| `assets` | 套件图标等源资产。 |
| `scripts` | 镜像构建脚本。 |

## 本地开发

```bash
pnpm -C frontend install
pnpm -C frontend dev
cargo run -p protocol-simulation
cargo run -p protocol-simulation-engine
```

API 服务默认监听 `8080`，数据目录为 `/data`，可通过 `SECLAB_SUITE_DATA_DIR` 覆盖。engine 默认监听 `SECLAB_SIM_PORT`。

## 镜像构建

```bash
./scripts/build-image.sh
./scripts/build-engine-image.sh
```

不传参数时，脚本分别从对应 crate 的 `Cargo.toml` 读取镜像标签：

- `scripts/build-image.sh` 读取 `crates/protocol-simulation/Cargo.toml`
- `scripts/build-engine-image.sh` 读取 `crates/protocol-simulation-engine/Cargo.toml`

也可以显式传入镜像标签：

```bash
./scripts/build-image.sh 0.1.0-alpha.1
./scripts/build-engine-image.sh 0.1.0-alpha.1
```

默认镜像名：

- `seclab-protocol-simulation`
- `seclab-protocol-simulation-engine`

## 运行边界

套件 API 容器只维护套件状态和调用 Agent。协议仿真实例由 Agent 通过 suite workload API 拉起 engine 容器，容器生命周期和 PCAP 取证归属当前节点 Agent。

规则包导入、实例部署、下线和取证接口由套件 API 提供；主控只负责安装套件、代理入口、注入运行配置和展示统一通知。

SecLab 会把 `/run/seclab-agent/runtime.json` 及实例令牌以只读方式注入套件。套件 API 根据描述自动连接本地 UDS 或节点 mTLS HTTPS，不读取 Agent mode，也不接受客户端自行指定套件实例身份。
