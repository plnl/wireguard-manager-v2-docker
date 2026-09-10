 # WireGuard Manager V2 Docker
 
 将 [WireGuard Manager V2](https://github.com/) 的服务端管理脚本与 Web 面板打包为 Docker 容器部署。
 
 容器内同时运行采集守护进程和 Web 管理面板，通过卷映射共享宿主机的 WireGuard 配置，实现完整的 VPN 管理能力。
 
 ## 特性
 
 - 一键 Docker 部署，无需手动安装 Python 依赖或配置 systemd 服务
 - Web 面板 + 状态采集器双进程，容器内自动管理
 - 完整 CLI 工具链：客户端管理、Site-to-Site、路由、防火墙、流量统计、备份
 - 配置文件通过卷映射挂载，修改后 restart 即生效
 - wgmgr 脚本热更新：修改宿主机脚本后重启容器即可，无需重新构建镜像
 
 ## 架构
 
 ```
 ┌──────────────────────────────────────┐
 │            宿主机 (VPS)               │
 │                                      │
 │  ┌──────────────┐  ┌────────────────┐ │
 │  │ wg-quick@wg0 │  │  Docker 容器    │ │
 │  │  (内核模块)  │  │  wg-manager   │ │
 │  │  UDP 51820  │◄─►│               │ │
 │  └──────────────┘  │  采集器 + 面板 │ │
 │                    │  TCP 8443     │ │
 │  /etc/wireguard-   │               │ │
 │  manager/ (共享)   └───────────────┘ │
 └──────────────────────────────────────┘
 ```
 
 WireGuard 内核模块在宿主机运行（不能容器化），容器通过 `network_mode: host` 共享网络命名空间访问 WireGuard netlink。
 
 ## 项目结构
 
 ```
 wg-manager-docker/
 ├── README.md
 ├── Dockerfile              # 镜像构建
 ├── docker-compose.yml      # 编排配置（卷映射 + 环境变量）
 ├── entrypoint.sh            # 容器入口（启动采集器 + 面板）
 ├── .gitignore
 ├── .dockerignore
 └── app/                    # WireGuard Manager V2 源码
     ├── wireguard-manager-v2.0.sh   # 主管理脚本 (wgmgr)
     ├── web/                        # Web 面板 Python 源码
     │   ├── wgm_web.py             # 面板服务
     │   ├── wgm_collector.py       # 状态采集器
     │   ├── wgm_common.py          # 共享基础库
     │   ├── wgm_alert.py           # 告警
     │   ├── wgm_health.py          # 健康检查
     │   ├── wgm_traffic.py         # 流量统计
     │   └── static/               # 前端静态文件
     └── systemd/                   # systemd 服务模板（参考）
         ├── wireguard-manager-web.service
         ├── wireguard-manager-collector.service
         └── wireguard-manager-web.sudoers
 ```
 
 ## 快速开始
 
 ### 1. 安装 Docker
 
 ```bash
 curl -fsSL https://get.docker.com | bash
 systemctl enable docker
 ```
 
 ### 2. 安装 WireGuard（宿主机）
 
 ```bash
 apt-get update
 apt-get install -y wireguard qrencode iproute2
 
 # 开启内核转发
 echo "net.ipv4.ip_forward=1" > /etc/sysctl.d/99-wireguard.conf
 sysctl -p /etc/sysctl.d/99-wireguard.conf
 ```
 
 ### 3. 初始化服务端
 
 ```bash
 # 创建 wgmgr 命令
 ln -sf /opt/wg-manager/wireguard-manager-v2.0.sh /usr/local/bin/wgmgr
 chmod +x /opt/wg-manager/wireguard-manager-v2.0.sh
 
 # 生成密钥
 mkdir -p /etc/wireguard-manager/server
 wg genkey | tee /etc/wireguard-manager/server/private.key | wg pubkey > /etc/wireguard-manager/server/public.key
 chmod 600 /etc/wireguard-manager/server/private.key
 
 # 写入配置（按实际环境修改）
 cat > /etc/wireguard-manager/manager.conf << 'EOF'
 WG_INTERFACE=wg0
 WG_PORT=51820
 VPN_NETWORK4=10.66.66.0/24
 SERVER_IP4=10.66.66.1/24
 DNS=1.1.1.1
 MTU=1420
 ENDPOINT=你的服务器公网IP
 WAN_INTERFACE=ens5
 USE_IPV6=no
 VPN_NETWORK6=
 SERVER_IP6=
 NAT66=no
 INTERNET_NAT=yes
 COLLECT_INTERVAL=30
 EOF
 
 # 生成 wg0.conf 并启动
 wgmgr server rebuild
 wgmgr server up
 systemctl enable wg-quick@wg0
 ```
 
 ### 4. 设置面板密码
 
 ```bash
 echo "YourStrongPassword123" | wgmgr web passwd --user admin --stdin
 ```
 
 ### 5. 启动 Docker 容器
 
 ```bash
 cd /opt/wg-manager/docker
 docker compose up -d --build
 ```
 
 ### 6. 访问面板
 
 ```
 http://服务器公网IP:8443/
 用户名: admin
 密码: YourStrongPassword123
 ```
 
 ## 卷映射
 
 | 宿主机路径 | 容器路径 | 读写 | 用途 |
 |---|---|---|---|
 | `/etc/wireguard-manager` | `/etc/wireguard-manager` | 读写 | 配置、state、日志、密钥 |
 | `/etc/wireguard` | `/etc/wireguard` | 只读 | wg0.conf |
 | `/opt/wg-manager` | `/opt/wg-manager` | 只读 | wgmgr 脚本（热更新） |
 
 ## 环境变量
 
 | 变量 | 默认值 | 说明 |
 |---|---|---|
 | `WGM_MANAGER_DIR` | `/etc/wireguard-manager` | 配置根目录 |
 | `WGM_STATE_DIR` | `/etc/wireguard-manager/state` | 状态数据 |
 | `WGM_LOG_DIR` | `/etc/wireguard-manager/logs` | 日志 |
 | `WGM_WEB_CONF` | `/etc/wireguard-manager/web.conf` | 面板配置 |
 | `WGM_MANAGER_CONF` | `/etc/wireguard-manager/manager.conf` | 服务端配置 |
 | `WGM_CLI` | `/usr/local/bin/wgmgr` | wgmgr 路径 |
 | `WGM_INTERFACE` | `wg0` | WireGuard 接口名 |
 
 ## 常用命令
 
 ### 容器管理
 
 ```bash
 docker compose up -d --build     # 构建并启动
 docker compose stop              # 停止
 docker compose restart            # 重启（配置变更后生效）
 docker compose down               # 停止并删除容器
 docker compose logs -f            # 实时日志
 docker exec -it wg-manager bash   # 进入容器
 ```
 
 ### 客户端管理（宿主机 wgmgr）
 
 ```bash
 wgmgr client add myphone                # 添加客户端
 wgmgr client add myphone --print-conf   # 添加并输出配置
 wgmgr client conf myphone --qrcode      # 生成二维码
 wgmgr client list                       # 客户端列表
 wgmgr client enable/disable myphone     # 启用/禁用
 wgmgr client delete myphone             # 删除
 wgmgr client rotate-key myphone         # 轮换密钥
 ```
 
 ### 服务端管理（宿主机 wgmgr）
 
 ```bash
 wgmgr server up / down / restart        # 启停重启
 wgmgr server rebuild                    # 重新生成 wg0.conf
 wgmgr status                             # 状态总览
 wgmgr dashboard                          # 实时仪表盘
 wgmgr diagnose                           # 系统诊断
 wgmgr health                             # 健康检查
 ```
 
 ### 修改面板绑定地址
 
 面板配置在 `/etc/wireguard-manager/web.conf`，修改后重启容器：
 
 ```bash
 # 公网可达
 sed -i 's/^WEB_BIND_SCOPE=.*/WEB_BIND_SCOPE=public/' /etc/wireguard-manager/web.conf
 sed -i 's/^WEB_LISTEN=.*/WEB_LISTEN=0.0.0.0:8443/' /etc/wireguard-manager/web.conf
 docker compose restart
 
 # 仅 VPN 内可达
 sed -i 's/^WEB_BIND_SCOPE=.*/WEB_BIND_SCOPE=vpn/' /etc/wireguard-manager/web.conf
 sed -i 's/^WEB_LISTEN=.*/WEB_LISTEN=10.66.66.1:8443/' /etc/wireguard-manager/web.conf
 docker compose restart
 
 # 仅本机（SSH 隧道）
 sed -i 's/^WEB_BIND_SCOPE=.*/WEB_BIND_SCOPE=local/' /etc/wireguard-manager/web.conf
 sed -i 's/^WEB_LISTEN=.*/WEB_LISTEN=127.0.0.1:8443/' /etc/wireguard-manager/web.conf
 docker compose restart
 ```
 
 ### 重置面板密码
 
 ```bash
 echo "NewPassword123" | wgmgr web passwd --user admin --stdin
 docker compose restart
 ```
 
 ### 其他命令
 
 ```bash
 wgmgr peer list --json                 # Peer 列表
 wgmgr route add office 192.168.10.0/24 10.66.66.2  # 添加路由
 wgmgr fw show                          # 防火墙规则
 wgmgr key rotate-server                # 轮换服务端密钥
 wgmgr traffic --range 24h              # 流量统计
 wgmgr backup create                    # 创建备份
 wgmgr site create branch-a --remote-lan 192.168.20.0/24 ...  # 站点互联
 ```
 
 ## 更新
 
 | 更新内容 | 操作 |
 |---|---|
 | wgmgr 脚本 | 修改宿主机文件 → `docker compose restart`（卷映射） |
 | Web Python 源码 | 更新 `app/web/` → `docker compose up -d --build` |
 | manager.conf | `wgmgr server rebuild` → `wgmgr server restart` |
 | web.conf | `docker compose restart` |
 
 ## 为什么需要 host 网络 + NET_ADMIN
 
 采集器通过 netlink 调用 `wg show` 查询宿主机 WireGuard 接口状态。Docker 默认 bridge 网络有独立的网络命名空间，容器内看不到宿主机的 `wg0` 接口。`network_mode: host` 让容器共享宿主机网络命名空间，`CAP_NET_ADMIN` 授权 netlink 访问，`CAP_NET_RAW` 授权 iptables/nft 防火墙快照。
 
 ## 常见问题
 
 **Q: 容器和宿主机 systemd 面板服务能同时运行吗？**
 
 不能，端口冲突。先停掉宿主机服务：`systemctl stop wireguard-manager-web wireguard-manager-collector`
 
 **Q: 容器启动后面板显示数据陈旧？**
 
 采集器可能启动失败。检查：`docker compose logs`，进入容器测试：`docker exec -it wg-manager wgmgr collect` 和 `wg show`。
 
 **Q: 面板无法公网访问？**
 
 1. 确认 `web.conf` 中 `WEB_LISTEN=0.0.0.0:8443`
 2. 确认容器运行：`docker compose ps`
 3. 确认端口监听：`ss -ltnp | grep 8443`
 4. 确认 VPS 安全组放行 TCP 8443
 
 **Q: 客户端连不上 VPN？**
 
 1. `wg show` 确认服务端运行
 2. VPS 安全组放行 UDP 51820
 3. 客户端 Endpoint 为服务器公网 IP
 4. `sysctl net.ipv4.ip_forward` 确认转发开启
 5. `wgmgr fw show` 检查 NAT 规则
 
 ## License
 
 本项目遵循原始 WireGuard Manager V2 的许可协议。
