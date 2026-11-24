# Kaldor

Kaldor 是 RT-AX89X 的独立用户态组件。RT-AX89X 固件提供启动、停止、防火墙重建和已登录管理页的固定入口。组件包含规则引擎、代理入口、出站适配、防火墙与进程管理和管理界面。固定入口只负责鉴权、启动通知及选择组件槽。发布目录提供 Linux ARMv7 二进制包、带依赖源码的源码包及 SHA-256 清单。组件使用 AGPLv3，协议库的版权声明和许可证随源码包 vendor 目录提供。

## 安装与单独升级

管理页、冷启动和防火墙重建需要含 Kaldor 钩子的固件。可以用 `ls -l /usr/sbin/kaldorctl` 检查固件加载器。此加载器使用 BusyBox 的 flock 和固件的 OpenSSL 校验 SHA-256。旧版 axproxyctl 依赖部分华硕 BusyBox 未提供的 command、mktemp 和 sha256sum，需使用已修复的加载器。组件的 JFFS 配置、A/B 槽位和管理页 CGI 接口可跨加载器复用。

在缺少固件入口的设备上，可将已独立核验摘要的修复加载器保存为 `/jffs/kaldor/kaldorctl`（目录及脚本权限设为 0700），用其绝对路径执行下面的命令。当官方固件未提供内置加载器时，Release 更新器也会使用该 JFFS 加载器。此安装方式提供本次开机的手动启动和停止。下次启动、重建防火墙和管理页集成由固件入口接管。安装包须通过可信渠道获取，并独立核对二进制 SHA-256。

```sh
: "${PACKAGE_DIR:?set the unpacked package directory}"
: "${KALDOR_SHA256:?set the independently verified binary digest}"
kaldorctl install "$PACKAGE_DIR/kaldor" "$KALDOR_SHA256"
kaldorctl status
```

每个版本使用同一个 install 命令。安装器在 JFFS 私有目录暂存并校验新程序，检查现有配置，启用状态下等待入口监听和透明规则就绪后切换活动槽。升级中已有代理连接会断开。进程启动或规则安装失败时重新启动原活动槽。新槽提交且就绪后，组件在加载器锁内核对活动槽和运行进程，再删除非活动槽的程序。已停用代理时，按新槽及已验证的停用配置完成清理。本机只保留当前程序和配置。管理员可在管理页关闭服务并持久保存。正常升级不访问 MTD。

### 从 GitHub Release 升级

在带网络代理入口的固件管理页，打开左侧 VPN 下方的「网络代理 → 参数设置 → 组件更新」，点击「检查新版本」。发现更高稳定版后，点击「升级到」并确认。路由器在后台下载，页面显示进度和结果。检查后若最新标签改变，需重新检查并确认。首次从尚无组件更新按钮的版本升级，可使用下方 SSH 入口。

在 [稳定版 Release](https://github.com/StiofanZ/Kaldor/releases/latest) 取得 `kaldor-update`。首次安装升级工具时，在管理电脑核对附件的 GitHub SHA-256 摘要，通过 SSH 放入路由器的 `/jffs/kaldor/kaldor-update` 并设为 0700。以后在路由器上执行：

```sh
/jffs/kaldor/kaldor-update check
/jffs/kaldor/kaldor-update upgrade
```

`check` 显示当前版本、最新稳定版及是否可升级。`upgrade` 仅安装更高版本。更新器经系统 CA 验证 HTTPS，从最新 Release 读取版本及摘要，按固定版本下载 ARMv7 程序，核对 SHA-256 和程序自报版本后交给固件加载器。下载或校验失败时，现有代理继续运行。页面后台更新的错误详情可在本次开机的 `/tmp/axproxy/release-error.log` 中查看。升级成功会短暂重新建立代理连接。若需恢复旧版本，从对应 Release 重新取得旧版程序并校验摘要，确认当前配置兼容后使用加载器的 install 命令。设备按管理员指令检查和升级，无需 GitHub 令牌。

发布维护者完成本地验收后，将与 Cargo 版本一致的稳定标签（如 `v0.3.1`）推送到仓库。GitHub Actions 使用固定的 Rust、Zig 工具链生成 ARMv7 程序、安装包、离线源码包、更新器、版本清单和 `SHA256SUMS`，校验构建产物后发布 Release。若标签已存在但尚未发布，可在同一工作流的「Run workflow」中指定该标签，重新构建其对应提交。测试在本地执行。

启动时，组件先读取主 LAN 地址和接口，再创建工作进程。在工作进程写入就绪标记并完成分流规则安装后，启动命令才返回成功。进程启动和就绪的开机时间、端口绑定失败及就绪超时记录在 `/tmp/axproxy/service.log`，启动命令的返回值同时写入系统日志。

安装前用 `df -k /jffs` 核对空间。保留的两个目标程序和更新暂存最多同时占用三份解压后的二进制空间，另外应为配置及已有 JFFS 数据保留余量。也可以提前为 `/jffs/axproxy` 挂载管理员专用的持久文件系统，要求文件系统在组件启动前已就绪。

## 设置

在华硕管理页左侧进入「网络代理」。在「代理节点」添加节点，在「参数设置」选择出站模式并启用服务，在「分流规则」调整匹配顺序。切换标签保留当前编辑；「保存并应用」一次提交当前编辑的配置。在「参数设置」中可单独检查和升级组件。按顺序匹配规则，同一条规则的所有条件同时生效。可组合源设备 CIDR、目的 CIDR、域名后缀、目的端口和传输协议（TCP、UDP 或两者），并选择节点、代理策略、direct 或 reject。未命中时使用规则兜底出口。HTTP（含 CONNECT）和 SOCKS5 共用主 LAN 的一个 TCP 端口，默认 6000。可在管理页修改「代理端口」并保存，或设置配置字段 `listen_port`（1–65535，7893 保留给透明代理）。保存成功后旧监听关闭，客户端须改用新端口。目标端口已占用导致应用失败时，组件恢复原配置和监听。升级前使用 7890 或 7891 的客户端需改用 6000。SOCKS5 的 UDP ASSOCIATE 单独分配 LAN 数据端口。允许访问主 LAN 的客户端可以使用这些入口。

| 出站模式 | 主 LAN 的处理方式 |
|---|---|
| 直接连接 | 主 LAN 使用系统路由和 DNS。手动 HTTP（含 CONNECT）和 SOCKS5 请求通过代理端口直连目标，忽略分流规则和代理节点；活动连接及访问日志显示出口 `direct`。 |
| 全局代理 | 所有主 LAN 设备的公网 TCP、UDP、单播 DNS，以及手动代理请求，统一使用所选节点或策略。 |
| 规则判定 | 对同一范围逐请求匹配分流规则，未命中时使用「分流规则」中的兜底出口。 |

### 分流规则与规则文件

在「分流规则」中，条件规则、标准规则和远程规则集按页面顺序首次命中生效。最多可配置 512 条分流规则，配置文件上限为 64 KiB。保存并应用后切换，直接连接和全局代理模式仍按各自的模式转发。

- **标准规则**可填写 `DOMAIN,example.org` 并选择出口，也可粘贴完整规则，如 `DOMAIN-SUFFIX,example.org,DIRECT`。支持 `DOMAIN`、`DOMAIN-SUFFIX`、`DOMAIN-KEYWORD`、`IP-CIDR`、`IP-CIDR6`、`SRC-IP-CIDR`、`DST-PORT`（单端口）、`NETWORK`（TCP/UDP）与 `MATCH`。目的 CIDR 在目标 IP 已知时参与匹配，接受可选的 `no-resolve`。透明 UDP 的 QUIC 域名识别用于日志，流量选路时仍按当时可见的目标匹配。
- **添加远程规则**使用 HTTPS 地址和一个统一出口。文件支持无出口的上述匹配条件、纯 CIDR、完整域名和 `+.example.org` 后缀，也支持同样内容的 YAML `payload:` 列表。首次保存、更改地址或点击「重新下载」后保存时，由路由器下载。下载和验证成功后按内容 SHA-256 保存到组件的 `rule-files/` 目录，重启直接读取已校验的快照。失败时继续使用已保存配置。每个配置最多 8 个远程引用、单文件 1 MiB、展开后共 16,384 条。IPv4、IPv6 均使用同一组条件。二进制 MRS、GeoIP/GeoSite 数据库和其他未列出的表达式不支持。

配置字段 `outbound_mode` 取 `direct`、`global` 或 `rules`。全局出口 `global_outbound` 必须引用代理节点或策略；`default` 保存规则兜底出口。旧配置首次读取为规则判定，原有节点、策略、规则和兜底出口继续生效，先前设备列表的范围扩大到整个主 LAN，重新保存后移除该字段。切换模式会结束现有代理会话。

在「代理策略」中创建策略并勾选成员节点，随后可在全局代理出口、规则兜底出口和任意分流规则中使用策略名称。节点和策略共享名称空间。策略只接受代理节点作为成员。改名时管理页同步更新引用，被引用的节点或策略需先解除引用才能删除。

| 策略类型 | 新流量如何选节点 |
|---|---|
| 手动选择 | 使用指定成员。 |
| 自动选择 | 服务启动时经各成员连接 `1.1.1.1:443` 并校验 `cloudflare-dns.com` 的 TLS 证书，比较从建立代理连接到完成 TLS 握手的耗时。每轮结束 60 秒后重新检测，单节点超时 5 秒。首批请求等待首次结果。从最快的可用节点开始尝试，建连失败时尝试其他通过检测的成员。全部不可用时返回失败。 |
| 负载均衡 | 按成员顺序轮流分配新 TCP 连接、UDP 会话和透明 DNS 查询。已建立的流量继续使用原节点。 |

策略保存于配置的 `policies` 数组。例如 `{"name":"office","type":"manual","members":["east","west"],"selected":"west"}`。自动选择和负载均衡的 `type` 分别为 `auto` 和 `load_balance`，省略 `selected`。仅自动策略的成员参与测速，同一节点每轮只测一次。活动连接和访问日志显示实际使用的节点；自动策略无可用成员时，失败记录显示策略名称。


「活动连接」显示代理已建立且仍打开的 TCP 出站连接或 UDP 会话，包括客户端地址、目标、入口、传输协议和实际出口。透明 TCP 可从 80、8080 端口的 HTTP Host 和 443、8443 端口的 TLS ClientHello SNI 取得可见域名。缺少域名规则时，在转发过程中读取这些信息；两页同时更新目标，出口沿用实际路由结果。透明 UDP 会在已转发的 QUIC v1/v2 客户端 Initial 中识别可见 SNI，支持分片 ClientHello。仅更新本次 UDP 会话在两页中的显示，不改变目的地址或已选出口。其他 UDP、缺少可见名称或超出识别上限的连接显示目标 IP。使用 ECH 时仅能看到外层名称。总数包含全部活动连接，最多跟踪 128 条明细。「访问日志」记录最近 128 次出站建立结果（建立、规则拒绝、连接失败），其中“已建立”指建立出站成功。两个标签在打开或点击刷新时读取快照。访问记录仅存在工作进程内存中，重启服务或应用配置后清空；设备代号只在本次运行内有效。日志中只显示目标主机和端口，不保存客户端内网地址、完整 URL、请求内容或凭据。

例如，将某台设备的 UDP 443 交给专用节点时，在首条规则填写该设备的源 CIDR、目的端口 443、传输协议 UDP，并选择对应节点。该设备的 TCP 443 继续匹配后续规则。规则可用「上移」「下移」调整优先级，保存并应用后生效。域名后缀按完整标签匹配自身和子域，忽略 ASCII 大小写，允许一个结尾点。IP 字面量只参与地址匹配。

已有规则省略 `network` 时匹配 TCP 和 UDP。使用协议条件的规则会保存 `"network":"tcp"` 或 `"network":"udp"`。回退到 0.2.2 前，先将协议改为「TCP 和 UDP」，对仅有协议条件的规则补上其他条件或删除，再保存。

两种代理模式均接管整个主 LAN。设备规则可以填写 IPv4 或 IPv6 源 CIDR。对于落入 IPv4 源规则的 DHCP 保留地址，组件按入站 MAC 将同一设备的 IPv6 临时地址关联到保留地址。更改 DHCP 保留记录后重新应用配置。

IPv4 和 IPv6 透明 TCP/UDP 分别使用各自协议族的 TPROXY、策略路由优先级 10891、表 189 和掩码 0x02000000。两者遵循同一出站模式；目的地址按实际协议族匹配。除单播 DNS 外，主 LAN 直连网段、路由器本机、私网及组播等流量旁路。路由器自身发起的连接和其他入站接口沿用系统路由。IPv6 需要固件支持 IPv6 策略路由、ip6tables TPROXY，终端访问公网还需可用的 IPv6 地址与路由。先升级配套固件，再安装组件。手动入口使用请求自带的域名；透明 TCP 对 80/8080 的 HTTP Host、443/8443 可见的 TLS SNI 做有限读取，始终连接原目标 IP。无可见域名的连接和透明 UDP 按源、目的 IP、端口和默认规则处理。

主 LAN 设备通过 IPv4 或 IPv6 发往 UDP/TCP 53 的查询（含发给路由器的查询）转为 DNS over HTTPS，默认向 Cloudflare 的固定地址 `1.1.1.1:443` 连接，以 `cloudflare-dns.com` 验证 TLS 证书。全局模式使用指定代理出口，规则判定模式按下述 DNS 规则选择出口。上游不可用时返回 SERVFAIL。设备自带的 DoH/DoT 保留原协议。公共解析器无法解析仅存在于本地 DNS 的私有名称。访问日志中的「透明 DNS」记录解析器、实际出口及交换结果，不保存查询名称。两种入站协议族均支持 A、AAAA 等 DNS 查询类型。

### DNS 查询出站

在「参数设置」选择「规则判定」，然后进入「DNS 规则」。查询域名支持完整域名、域名后缀（含根域及子域）和关键词；从上到下首条命中生效，A 与 AAAA 查询适用同一配置。例如添加后缀 `example.org`、选择代理节点或策略后，查询该域及子域时，路由器会经所选节点或策略连接 Cloudflare DoH。网页和后续连接继续使用普通分流规则。

「直连加密 DNS」用于出口为 `direct` 的透明 DNS 查询。可选择 Cloudflare（默认）或阿里公共 DNS（`223.5.5.5`，TLS 主机名 `dns.alidns.com`）。经代理节点和策略转发的查询继续使用 Cloudflare。两种解析器都使用 HTTPS POST、系统 CA 和主机名校验；失败返回 SERVFAIL。访问日志显示实际选用的解析器与出口。未配置专用查询规则时，沿用解析器连接规则的匹配条件仍是 Cloudflare 的地址和 TCP 443，选定出口后再决定实际连接的解析器。

「DNS 未命中时」可选择独立出口，或选择「按查询域名匹配分流规则」，复用现有条件、标准规则和规则文件。复用时使用客户端地址、查询域名、入站 TCP/UDP 和目的端口 53，此时尚无解析结果可供目的 IP 匹配。默认的「沿用解析器连接的出站规则」保留旧配置的行为，以解析器地址、TLS 域名和 TCP 443 匹配。选择 `direct` 仍使用加密 DNS，选择 `reject` 或所选出口失败会返回 SERVFAIL。全局代理和直接连接模式维持各自的整网行为。

| 上游 | 参数 | 数据传输 |
| --- | --- | --- |
| AnyTLS | 服务器、密码、可选 TLS 服务器名；使用系统 CA 验证 | TCP，UDP-over-TCP v2 |
| SOCKS5 | 服务器、可选用户名和密码 | CONNECT，UDP ASSOCIATE |
| VLESS/REALITY | 服务器、UUID、SNI、X25519 公钥、Short ID、可选 xtls-rprx-vision | TCP，UDP；传输层为 TCP |

节点旁的「用于全局代理」会选中该节点并切换到全局模式，点击「保存并应用」后生效。改名时各出口与规则会跟随同一节点；删除前需先移除它的出口引用。仅改名且留空凭据时，组件沿用原节点的凭据。节点名须唯一。管理页不会回显保存的密码或 UUID。修改节点地址或认证身份时重新录入凭据。管理接口由固件的 httpd 会话鉴权，保存要求同源 POST。凭据存在权限受限的配置文件中。订阅转换可以在组件之外产生相同的节点与规则配置。

## 本地构建和验收

Kaldor 的主程序、分流、网络入口和上游适配使用 Rust。数据转发在同一进程内完成。AnyTLS 会话、SOCKS5、VLESS/Vision 和 TLS 使用协议库。REALITY 的 X25519MLKEM768 密钥交换使用 BoringSSL。管理脚本和华硕管理页面板嵌入可执行文件。

构建环境使用 Rust 1.91.1、Zig 0.14.1、Python 3、CMake、libclang、make、tar 和 sha256sum。先安装 Rust 标准库目标。若 Zig 不在 PATH，可用环境变量 `ZIG` 指定。发布包和校验清单写入 `dist/`，可用 `DIST` 指定其他目录。

```sh
rustup target add armv7-unknown-linux-musleabihf
make package
```

源码包包含 Cargo.lock 和依赖源码。解包后在同一工具链环境运行 `CARGO_NET_OFFLINE=true make build` 可离线生成 ARMv7 二进制。

互通测试在 Linux 的独立网络命名空间中运行。需要 iproute2、iptables、curl、OpenSSL、Python 3、flock、xt_TPROXY，以及同架构的 sing-box 和 Xray 测试服务端。管理页回归通过 CHROMIUM 指定的本地 Chrome 或 Chromium 可执行文件运行。以下示例使用 ARM64 Linux。最后一个参数是先前发布的、能够在该测试机运行的组件版本，用于检查失败恢复、成功切槽和旧程序清理。

```sh
cargo test --locked
python3 test/panel.py "$CHROMIUM"
rustup target add aarch64-unknown-linux-musl
python3 build/cross.py aarch64 build --locked --release
sudo unshare -n sh -c 'ip link set lo up && python3 test/policy.py "$1"' sh target/aarch64-unknown-linux-musl/release/kaldor
python3 test/component_update.py ./kaldor ./kaldor-next ./kaldorctl  # Linux 上两个版本递增的本地构建
sudo unshare --pid --fork --mount-proc --net python3 test/startup.py target/aarch64-unknown-linux-musl/release/kaldor ./kaldorctl
sudo unshare -n python3 test/interop.py target/aarch64-unknown-linux-musl/release/kaldor ./kaldorctl "$SING_BOX" "$XRAY" "$PREVIOUS_COMPONENT"
```

设置 `KALDOR_TEST_HYBRID=1` 可让测试 TLS 目标仅接受 X25519MLKEM768。设置 `KALDOR_TEST_ARM` 和 `KALDOR_TEST_QEMU` 可额外校验 ARMv7 发布程序的配置与内嵌管理页。透明转发由原生 Linux 内核验证。
