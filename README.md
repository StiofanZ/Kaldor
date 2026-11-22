# AXProxy

AXProxy 是 RT-AX89X 的独立用户态组件。RT-AX89X 固件提供启动、停止、防火墙重建和已登录管理页的固定入口。组件包含规则引擎、代理入口、出站适配、防火墙与进程管理和管理界面。固定入口只负责鉴权、启动通知及选择组件槽。发布目录提供 Linux ARMv7 二进制包、带依赖源码的源码包及 SHA-256 清单。组件使用 AGPLv3，协议库的版权声明和许可证随源码包 vendor 目录提供。

## 安装与单独升级

首次使用管理页和自动启动需要包含 AXProxy 入口的自编译固件。运行 `command -v axproxyctl` 可确认该入口。未安装组件时代理默认关闭。将发布包通过可信渠道传到路由器，解压到管理员专用暂存目录。通过可信渠道独立核对发布者提供的 SHA-256。以下命令只操作组件文件和自己的网络规则。

```sh
: "${PACKAGE_DIR:?set the unpacked package directory}"
: "${AXPROXY_SHA256:?set the independently verified binary digest}"
axproxyctl install "$PACKAGE_DIR/axproxy" "$AXPROXY_SHA256"
axproxyctl status
```

每个版本使用同一个 install 命令。安装器在 JFFS 私有目录暂存并校验新程序，检查现有配置，启用状态下等待入口监听和透明规则就绪后切换活动槽。升级中已有代理连接会断开。进程启动或规则安装失败时重新启动原活动槽。通过 `axproxyctl rollback` 切回上一个可用槽；配置由两个槽共用。回退时同样检查兼容性。管理员可在管理页关闭服务并持久保存。正常升级不访问 MTD。当前发布使用管理员取得的可信摘要，不提供自动联网更新。

安装前用 `df -k /jffs` 核对空间。保留的两个目标程序和更新暂存最多同时占用三份解压后的二进制空间，另外应为配置及已有 JFFS 数据保留余量。也可以提前为 `/jffs/axproxy` 挂载管理员专用的持久文件系统，要求文件系统在组件启动前已就绪。

## 设置

在华硕管理页「VPN → 网络代理」添加节点，选择默认出口，再启用服务。按顺序匹配规则，同一条规则的所有条件同时生效。可组合源设备 CIDR、目的 CIDR、域名后缀和目的端口，并选择节点、direct 或 reject。未命中时使用默认出口。HTTP 和 SOCKS5 分别监听主 LAN 地址的 TCP 7890 和 7891，绑定到主 LAN 接口。SOCKS5 的 UDP ASSOCIATE 单独分配 LAN 数据端口。允许访问主 LAN 的客户端可以使用这些入口。

透明设备列表支持 IPv4 CIDR。每台设备可填写 DHCP 保留地址的 /32；空列表只启用手动入口。透明 TCP/UDP 使用 iptables TPROXY、策略路由优先级 10891、表 189 和掩码 0x02000000。主 LAN 私网目的地址、路由器本机及组播等流量旁路。IPv6 流量保持系统路由。未选择设备的透明流量不进入组件。手动入口使用请求自带的域名；透明 TCP 对 80/8080 的 HTTP Host、443/8443 可见的 TLS SNI 做有限读取，始终连接原目标 IP。无可见域名的连接和透明 UDP 按源、目的 IP、端口和默认规则处理。

| 上游 | 参数 | 数据传输 |
| --- | --- | --- |
| AnyTLS | 服务器、密码、可选 TLS 服务器名；使用系统 CA 验证 | TCP，UDP-over-TCP v2 |
| SOCKS5 | 服务器、可选用户名和密码 | CONNECT，UDP ASSOCIATE |
| VLESS/REALITY | 服务器、UUID、SNI、X25519 公钥、Short ID、可选 xtls-rprx-vision | TCP，UDP；传输层为 TCP |

节点名须唯一。管理页不会回显保存的密码或 UUID。修改节点地址或认证身份时重新录入凭据。管理接口由固件的 httpd 会话鉴权，保存要求同源 POST。凭据存在权限受限的配置文件中。订阅转换可以在组件之外产生相同的节点与规则配置。

## 本地构建和验收

本版用 Go 1.27.4 构建。构建需要 Go、make、tar 和 sha256sum；在本目录运行。源码包带有 vendor 目录。解压后使用相同版本的 Go，在断网环境中执行 `GOPROXY=off make build` 即可重建同一 ARMv7 程序。

```sh
make package
```

对照测试在原生 Linux 的独立网络命名空间内运行，依赖 iproute2、iptables、curl、OpenSSL、Python 3、flock、xt_TPROXY 和同架构的 sing-box、Xray 测试服务端。测试在临时目录生成凭据，测试客户端和目的端分别使用隔离网络。生产运行只需要 AXProxy。

```sh
CGO_ENABLED=0 go build -ldflags="-X main.version=$(cat VERSION)" -o dist/axproxy-native .
CGO_ENABLED=0 go build -ldflags="-X main.version=upgrade-test" -o dist/axproxy-upgrade .
sudo unshare -n python3 test/interop.py dist/axproxy-native ./axproxyctl "$SING_BOX" "$XRAY" dist/axproxy-upgrade
```
