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

每个版本使用同一个 install 命令。安装器在 JFFS 私有目录暂存并校验新程序，检查现有配置，启用状态下等待入口监听和透明规则就绪后切换活动槽。升级中已有代理连接会断开。进程启动或规则安装失败时重新启动原活动槽。通过 `kaldorctl rollback` 切回上一个可用槽；配置由两个槽共用。回退时同样检查兼容性。管理员可在管理页关闭服务并持久保存。正常升级不访问 MTD。当前发布使用管理员取得的可信摘要，不提供自动联网更新。

安装前用 `df -k /jffs` 核对空间。保留的两个目标程序和更新暂存最多同时占用三份解压后的二进制空间，另外应为配置及已有 JFFS 数据保留余量。也可以提前为 `/jffs/axproxy` 挂载管理员专用的持久文件系统，要求文件系统在组件启动前已就绪。

## 设置

在华硕管理页「VPN → Kaldor 网络代理」添加节点，选择默认出口，再启用服务。按顺序匹配规则，同一条规则的所有条件同时生效。可组合源设备 CIDR、目的 CIDR、域名后缀和目的端口，并选择节点、direct 或 reject。未命中时使用默认出口。HTTP 和 SOCKS5 分别监听主 LAN 地址的 TCP 7890 和 7891，绑定到主 LAN 接口。SOCKS5 的 UDP ASSOCIATE 单独分配 LAN 数据端口。允许访问主 LAN 的客户端可以使用这些入口。

透明设备列表支持 IPv4 CIDR。每台设备可填写 DHCP 保留地址的 /32；空列表只启用手动入口。透明 TCP/UDP 使用 iptables TPROXY、策略路由优先级 10891、表 189 和掩码 0x02000000。主 LAN 私网目的地址、路由器本机及组播等流量旁路。IPv6 流量保持系统路由。未选择设备的透明流量不进入组件。手动入口使用请求自带的域名；透明 TCP 对 80/8080 的 HTTP Host、443/8443 可见的 TLS SNI 做有限读取，始终连接原目标 IP。无可见域名的连接和透明 UDP 按源、目的 IP、端口和默认规则处理。

| 上游 | 参数 | 数据传输 |
| --- | --- | --- |
| AnyTLS | 服务器、密码、可选 TLS 服务器名；使用系统 CA 验证 | TCP，UDP-over-TCP v2 |
| SOCKS5 | 服务器、可选用户名和密码 | CONNECT，UDP ASSOCIATE |
| VLESS/REALITY | 服务器、UUID、SNI、X25519 公钥、Short ID、可选 xtls-rprx-vision | TCP，UDP；传输层为 TCP |

节点名须唯一。管理页不会回显保存的密码或 UUID。修改节点地址或认证身份时重新录入凭据。管理接口由固件的 httpd 会话鉴权，保存要求同源 POST。凭据存在权限受限的配置文件中。订阅转换可以在组件之外产生相同的节点与规则配置。

## 本地构建和验收

Kaldor 0.2.0 的主程序、分流、网络入口和上游适配使用 Rust。数据转发在同一进程内完成。AnyTLS 会话、SOCKS5、VLESS/Vision 和 TLS 使用协议库。REALITY 的 X25519MLKEM768 密钥交换使用 BoringSSL。管理脚本和华硕管理页面板嵌入可执行文件。

构建环境使用 Rust 1.91.1、Zig 0.14.1、Python 3、CMake、libclang、make、tar 和 sha256sum。先安装 Rust 标准库目标。若 Zig 不在 PATH，可用环境变量 `ZIG` 指定。发布包和校验清单写入 `dist/`，可用 `DIST` 指定其他目录。

```sh
rustup target add armv7-unknown-linux-musleabihf
make package
```

源码包包含 Cargo.lock 和依赖源码。解包后在同一工具链环境运行 `CARGO_NET_OFFLINE=true make build` 可离线生成 ARMv7 二进制。

互通测试在 Linux 的独立网络命名空间中运行。需要 iproute2、iptables、curl、OpenSSL、Python 3、flock、xt_TPROXY，以及同架构的 sing-box 和 Xray 测试服务端。以下示例使用 ARM64 Linux。最后一个参数是先前发布的、能够在该测试机运行的组件版本，用于检查双槽升级与回退。

```sh
cargo test --locked
rustup target add aarch64-unknown-linux-musl
python3 build/cross.py aarch64 build --locked --release
sudo unshare -n python3 test/interop.py target/aarch64-unknown-linux-musl/release/kaldor ./kaldorctl "$SING_BOX" "$XRAY" "$PREVIOUS_COMPONENT"
```

设置 `KALDOR_TEST_HYBRID=1` 可让测试 TLS 目标仅接受 X25519MLKEM768。设置 `KALDOR_TEST_ARM` 和 `KALDOR_TEST_QEMU` 可额外运行 ARMv7 发布程序的手动代理入口。透明转发由原生 Linux 内核验证。
