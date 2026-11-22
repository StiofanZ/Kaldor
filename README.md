# Kaldor

Kaldor 是 RT-AX89X 的独立用户态组件。RT-AX89X 固件提供启动、停止、防火墙重建和已登录管理页的固定入口。组件包含规则引擎、代理入口、出站适配、防火墙与进程管理和管理界面。固定入口只负责鉴权、启动通知及选择组件槽。发布目录提供 Linux ARMv7 二进制包、带依赖源码的源码包及 SHA-256 清单。组件使用 AGPLv3，协议库的版权声明和许可证随源码包 vendor 目录提供。

## 安装与单独升级

管理页、冷启动和防火墙重建需要含 Kaldor 钩子的固件。可以用 `ls -l /usr/sbin/kaldorctl` 检查固件加载器。此加载器使用 BusyBox 的 flock 和固件的 OpenSSL 校验 SHA-256。旧版 axproxyctl 依赖部分华硕 BusyBox 未提供的 command、mktemp 和 sha256sum，需使用已修复的加载器。组件的 JFFS 配置、A/B 槽位和管理页 CGI 接口可跨加载器复用。

在缺少固件入口的设备上，可将已独立核验摘要的修复加载器保存为 `/jffs/kaldor/kaldorctl`（目录及脚本权限设为 0700），用其绝对路径执行下面的命令。此安装方式提供本次开机的手动启动和停止。下次启动、重建防火墙和管理页集成由固件入口接管。安装包须通过可信渠道获取，并独立核对二进制 SHA-256。

```sh
: "${PACKAGE_DIR:?set the unpacked package directory}"
: "${KALDOR_SHA256:?set the independently verified binary digest}"
kaldorctl install "$PACKAGE_DIR/kaldor" "$KALDOR_SHA256"
kaldorctl status
```

每个版本使用同一个 install 命令。安装器在 JFFS 私有目录暂存并校验新程序，检查现有配置，启用状态下等待入口监听和透明规则就绪后切换活动槽。升级中已有代理连接会断开。进程启动或规则安装失败时重新启动原活动槽。通过 `kaldorctl rollback` 切回上一个可用槽；配置由两个槽共用。回退时同样检查兼容性。管理员可在管理页关闭服务并持久保存。正常升级不访问 MTD。

### 从 GitHub Release 升级

在 [稳定版 Release](https://github.com/StiofanZ/Kaldor/releases/latest) 取得 `kaldor-update`。首次安装升级工具时，在管理电脑核对附件的 GitHub SHA-256 摘要，通过 SSH 放入路由器的 `/jffs/kaldor/kaldor-update` 并设为 0700。以后在路由器上执行：

```sh
/jffs/kaldor/kaldor-update check
/jffs/kaldor/kaldor-update upgrade
```

`check` 显示当前版本、最新稳定版及是否可升级。`upgrade` 仅安装更高版本。更新器经系统 CA 验证 HTTPS，从最新 Release 读取版本及摘要，按固定版本下载 ARMv7 程序，核对 SHA-256 和程序自报版本后交给固件加载器。下载或校验失败时，现有代理继续运行。升级成功会短暂重新建立代理连接。若需恢复上个版本，使用 `kaldorctl rollback`。设备按管理员指令检查和升级，无需 GitHub 令牌。

发布维护者完成本地验收后，将与 Cargo 版本一致的稳定标签（如 `v0.3.1`）推送到仓库。GitHub Actions 使用固定的 Rust、Zig 工具链生成 ARMv7 程序、安装包、离线源码包、更新器、版本清单和 `SHA256SUMS`，校验构建产物后发布 Release。若标签已存在但尚未发布，可在同一工作流的「Run workflow」中指定该标签，重新构建其对应提交。测试在本地执行。

启动时，组件先读取主 LAN 地址和接口，再创建工作进程。在工作进程写入就绪标记并完成分流规则安装后，启动命令才返回成功。进程启动和就绪的开机时间、端口绑定失败及就绪超时记录在 `/tmp/axproxy/service.log`，启动命令的返回值同时写入系统日志。

安装前用 `df -k /jffs` 核对空间。保留的两个目标程序和更新暂存最多同时占用三份解压后的二进制空间，另外应为配置及已有 JFFS 数据保留余量。也可以提前为 `/jffs/axproxy` 挂载管理员专用的持久文件系统，要求文件系统在组件启动前已就绪。

## 设置

在华硕管理页「VPN → Kaldor 网络代理」添加节点，选择默认出口，再启用服务。按顺序匹配规则，同一条规则的所有条件同时生效。可组合源设备 CIDR、目的 CIDR、域名后缀、目的端口和传输协议（TCP、UDP 或两者），并选择节点、direct 或 reject。未命中时使用默认出口。HTTP 和 SOCKS5 分别监听主 LAN 地址的 TCP 7890 和 7891，绑定到主 LAN 接口。SOCKS5 的 UDP ASSOCIATE 单独分配 LAN 数据端口。允许访问主 LAN 的客户端可以使用这些入口。

例如，将某台设备的 UDP 443 交给专用节点时，在首条规则填写该设备的源 CIDR、目的端口 443、传输协议 UDP，并选择对应节点。该设备的 TCP 443 继续匹配后续规则。透明接管还需将设备加入下方说明的设备列表。规则可用「上移」「下移」调整优先级，保存并应用后生效。域名后缀按完整标签匹配自身和子域，忽略 ASCII 大小写，允许一个结尾点。IP 字面量只参与地址匹配。

已有规则省略 `network` 时匹配 TCP 和 UDP。使用协议条件的规则会保存 `"network":"tcp"` 或 `"network":"udp"`。回退到 0.2.2 前，先将协议改为「TCP 和 UDP」，对仅有协议条件的规则补上其他条件或删除，再保存。

透明设备列表支持 IPv4 CIDR。每台设备可填写 DHCP 保留地址的 /32；空列表只启用手动入口。透明 TCP/UDP 使用 iptables TPROXY、策略路由优先级 10891、表 189 和掩码 0x02000000。主 LAN 私网目的地址、路由器本机及组播等流量旁路。IPv6 流量保持系统路由。未选择设备的透明流量不进入组件。手动入口使用请求自带的域名；透明 TCP 对 80/8080 的 HTTP Host、443/8443 可见的 TLS SNI 做有限读取，始终连接原目标 IP。无可见域名的连接和透明 UDP 按源、目的 IP、端口和默认规则处理。

| 上游 | 参数 | 数据传输 |
| --- | --- | --- |
| AnyTLS | 服务器、密码、可选 TLS 服务器名；使用系统 CA 验证 | TCP，UDP-over-TCP v2 |
| SOCKS5 | 服务器、可选用户名和密码 | CONNECT，UDP ASSOCIATE |
| VLESS/REALITY | 服务器、UUID、SNI、X25519 公钥、Short ID、可选 xtls-rprx-vision | TCP，UDP；传输层为 TCP |

节点旁的「设为默认出口」会选中该节点，点击「保存并应用」后生效，已有规则仍优先。改名时默认出口与规则会跟随同一节点；删除前需先移除它的出口引用。仅改名且留空凭据时，组件沿用原节点的凭据。节点名须唯一。管理页不会回显保存的密码或 UUID。修改节点地址或认证身份时重新录入凭据。管理接口由固件的 httpd 会话鉴权，保存要求同源 POST。凭据存在权限受限的配置文件中。订阅转换可以在组件之外产生相同的节点与规则配置。

## 本地构建和验收

Kaldor 的主程序、分流、网络入口和上游适配使用 Rust。数据转发在同一进程内完成。AnyTLS 会话、SOCKS5、VLESS/Vision 和 TLS 使用协议库。REALITY 的 X25519MLKEM768 密钥交换使用 BoringSSL。管理脚本和华硕管理页面板嵌入可执行文件。

构建环境使用 Rust 1.91.1、Zig 0.14.1、Python 3、CMake、libclang、make、tar 和 sha256sum。先安装 Rust 标准库目标。若 Zig 不在 PATH，可用环境变量 `ZIG` 指定。发布包和校验清单写入 `dist/`，可用 `DIST` 指定其他目录。

```sh
rustup target add armv7-unknown-linux-musleabihf
make package
```

源码包包含 Cargo.lock 和依赖源码。解包后在同一工具链环境运行 `CARGO_NET_OFFLINE=true make build` 可离线生成 ARMv7 二进制。

互通测试在 Linux 的独立网络命名空间中运行。需要 iproute2、iptables、curl、OpenSSL、Python 3、flock、xt_TPROXY，以及同架构的 sing-box 和 Xray 测试服务端。管理页回归通过 CHROMIUM 指定的本地 Chrome 或 Chromium 可执行文件运行。以下示例使用 ARM64 Linux。最后一个参数是先前发布的、能够在该测试机运行的组件版本，用于检查双槽升级与回退。

```sh
cargo test --locked
python3 test/panel.py "$CHROMIUM"
rustup target add aarch64-unknown-linux-musl
python3 build/cross.py aarch64 build --locked --release
sudo unshare --pid --fork --mount-proc --net python3 test/startup.py target/aarch64-unknown-linux-musl/release/kaldor ./kaldorctl
sudo unshare -n python3 test/interop.py target/aarch64-unknown-linux-musl/release/kaldor ./kaldorctl "$SING_BOX" "$XRAY" "$PREVIOUS_COMPONENT"
```

设置 `KALDOR_TEST_HYBRID=1` 可让测试 TLS 目标仅接受 X25519MLKEM768。设置 `KALDOR_TEST_ARM` 和 `KALDOR_TEST_QEMU` 可额外运行 ARMv7 发布程序的手动代理入口。透明转发由原生 Linux 内核验证。
