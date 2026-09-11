#!/usr/bin/env bash

# ============================================================
# WireGuard Manager V2.0
# Debian / Ubuntu / VPS / Docker 宿主 / PVE 宿主 通用
#
# ------------------------------------------------------------
# V2.0 的定位：从"命令行脚本"升级成"管理平台"
# ------------------------------------------------------------
#
#   Bash 核心（本文件）      —— 安装 / 初始化 / 配置真相来源 / 渲染 /
#                               防火墙 / 路由 / 备份 / 非交互式 CLI
#   Python 采集层            —— 周期性把 wg + 系统状态落成 state/*.json，
#   web/wgm_collector.py        维护流量历史、跑 Health Check、发告警
#   Python Web 层            —— HTTP JSON API + Dashboard，只读 state，
#   web/wgm_web.py              写操作一律走本文件的白名单 CLI 子命令
#
# 分层原则：**Web/采集层全挂了，WireGuard 本身完全不受影响。**
# state/ 是派生数据，删掉重新采集即可；真相来源永远只有
# manager.conf、clients/*/meta.conf、sites/*/meta.conf。
#
# ------------------------------------------------------------
# V2.0 相对 V1.3 的变更
# ------------------------------------------------------------
#   - 新增 state 层：`wgmgr collect` 把接口/Peer/路由/系统事实一次性
#     渲染成 state/status.json（tmp+mv 原子写入），供 API、面板、告警
#     共用，不再各自去 grep wg 输出。
#   - 新增非交互式 CLI（`wgmgr <子命令>`，支持 --json），既是 Web 面板
#     唯一的写入通道，也能直接塞进 cron / 监控 / Telegram Bot。
#   - Peer 状态从"在线/离线"两态改成 online/idle/offline/never/disabled
#     五态，按 latest_handshake 分档（<180s / <15min / 更久 / 从未握手）。
#   - 新增流量历史（按天分片 jsonl + 降采样），面板可看今天/昨天/本周/
#     本月和趋势，不再只有 wg 的累计计数器。
#   - 新增 Health Check Engine：把系统事实和 Peer 事实转成结构化结论
#     以及"下一步该查什么"的建议，而不是一串 ✓/✗。
#   - 新增 Alert Engine：Peer/站点连续 N 次判定离线才告警，恢复后发
#     recovery，支持 Telegram / Bark / 企业微信 / 钉钉 / 通用 Webhook。
#   - 新增 Web 面板：用户名密码 + Session Cookie，写操作白名单，
#     绝不允许浏览器把任意命令传进来执行。
#   - 并发锁按操作类型区分：交互式菜单和会改配置的子命令拿排他锁；
#     只读/采集类命令不加锁（采集只写 state/，tmp+mv 原子落盘）。
#   - `--json` 模式下所有彩色提示自动改走 stderr，stdout 只有纯 JSON。
#
# 以下是 V1.3 就已经有、V2.0 完整保留的做法（不要推倒重来）：
#   - flock 单实例锁，避免并发写坏元数据
#   - 防火墙幂等重建（先清空本脚本打过标签的规则，再按当前状态全量下发）
#   - MTU 可调、Internet NAT 开关、客户端 AllowedIPs 预设菜单
#   - 状态判断优先 `ip link show` 而不是 systemctl（容器/非 systemd 更可靠）
#   - nftables 持久化只导出自己的表 + include，绝不覆盖主配置
#   - NAT66 走 ip6tables / 独立的 ip6 nat 表
#   - IPv6 全局转发风险提示 + 可选的 IPv6 转发加固
#   - 锁文件建不出来时不静默放行，必须人工确认
#
# ------------------------------------------------------------
# 设计原则（重点在"不能因为管这个脚本把网络搞挂"）
# ------------------------------------------------------------
#   1. 任何会动 wg0.conf / sysctl / 防火墙的操作，先在
#      backups/<timestamp>_<reason>/ 下打一份完整快照，
#      失败可以人工或用菜单一键回滚。
#   2. 配置永远是"先在临时文件里生成 -> 用 wg-quick strip 校验语法
#      -> 校验通过才落盘 -> 已运行的接口用 wg syncconf 热加载"，
#      不会出现"改坏了直接 restart 导致断线"的情况。
#   3. Site-to-Site 会做网段冲突检测：两端 LAN 完全相同时明确报错，
#      并且不会盲目生成会产生路由歧义的 AllowedIPs。
#   4. Site-to-Site 区分"纯路由模式"和"NAT 模式"，默认推荐纯路由——
#      站点之间不对 WireGuard 内部流量做 MASQUERADE，前提是两边网段
#      不重叠且双方网关都能加静态路由。
#   5. Web 层只能调用本文件里显式列出的白名单子命令，参数由本文件自己
#      校验；任何情况下都不把 HTTP 传进来的字符串拼进 shell 命令。
#
# ------------------------------------------------------------
# 模块地图
# ------------------------------------------------------------
#   Server        —— server_setup / wg_up / wg_down / show_server_info
#   Client        —— add_client / list_clients / toggle_client / delete_client
#   Site-to-Site  —— create_site / list_sites / toggle_site / delete_site / test_site
#   Peer 状态     —— peer_status_menu / show_peer_detail / peer_status_class
#   路由管理      —— add_route / delete_route / list_routes（写入 PostUp/PostDown）
#   防火墙        —— fw_* 系列（UFW / nftables / iptables 三选一抽象层）
#   密钥管理      —— key_management_menu（服务端/客户端密钥查看与轮换）
#   备份/恢复     —— backup_snapshot / restore_snapshot / backup_config / restore_backup
#   诊断          —— diagnostic
#   高级设置      —— advanced_menu（DNS / Keepalive / NAT / IPv6 加固 / 卸载）
#   State 层      —— json_str / wg_dump_load / state_collect            (V2.0)
#   Dashboard     —— dash_render / dashboard_menu                       (V2.0)
#   流量/健康/告警 —— traffic_menu / health_menu / alert_menu            (V2.0)
#   Web 面板      —— web_install / web_ctl / web_passwd / web_menu      (V2.0)
#   非交互 CLI    —— cli_usage / cli_* / cli_dispatch                   (V2.0)
#
# 作者：WireGuard Manager
# ============================================================

set -u

VERSION="2.0.0"
# state/status.json 的结构版本。Python 采集层和前端都按这个号做兼容判断，
# 改动 peers/interface 字段语义时必须 +1。
STATE_SCHEMA=2

# ------------------------------------------------------------
# 路径
# ------------------------------------------------------------

# 自解析脚本所在目录：V2.0 不再是单文件，web/ 与 systemd/ 跟脚本放在一起，
# `wgmgr web install` 从 $SCRIPT_DIR 取源码安装到 /opt/wireguard-manager。
SCRIPT_PATH="$(readlink -f "${BASH_SOURCE[0]}" 2>/dev/null || echo "${BASH_SOURCE[0]}")"
SCRIPT_DIR="$(cd "$(dirname "$SCRIPT_PATH")" && pwd)"

WG_INTERFACE="wg0"
WG_DIR="/etc/wireguard"
WG_CONFIG="${WG_DIR}/${WG_INTERFACE}.conf"

MANAGER_DIR="/etc/wireguard-manager"
SERVER_DIR="${MANAGER_DIR}/server"
CLIENTS_DIR="${MANAGER_DIR}/clients"
SITES_DIR="${MANAGER_DIR}/sites"
BACKUP_DIR="${MANAGER_DIR}/backups"
LOG_DIR="${MANAGER_DIR}/logs"
STATE_DIR="${MANAGER_DIR}/state"
TRAFFIC_DIR="${STATE_DIR}/traffic"
MANAGER_CONF="${MANAGER_DIR}/manager.conf"
ROUTES_CONF="${MANAGER_DIR}/routes.conf"
WEB_CONF="${MANAGER_DIR}/web.conf"

SERVER_PRIVATE_KEY="${SERVER_DIR}/private.key"
SERVER_PUBLIC_KEY="${SERVER_DIR}/public.key"

STATE_STATUS_JSON="${STATE_DIR}/status.json"
STATE_HEALTH_JSON="${STATE_DIR}/health.json"
STATE_ALERTS_JSON="${STATE_DIR}/alerts.json"
STATE_TRAFFIC_JSON="${STATE_DIR}/traffic.json"

# Web 层：源码随脚本分发，安装后落到 /opt/wireguard-manager
WEB_SRC_DIR="${SCRIPT_DIR}/web"
SYSTEMD_SRC_DIR="${SCRIPT_DIR}/systemd"
WEB_INSTALL_DIR="/opt/wireguard-manager"
WEB_APP_DIR="${WEB_INSTALL_DIR}/web"
WEB_BIN="/usr/local/bin/wgmgr"

COLLECTOR_SERVICE="wireguard-manager-collector"
WEB_SERVICE="wireguard-manager-web"
# 降权面板经此 sudoers 规则免密 sudo 调用 root 的 wgmgr（白名单子命令）。
WEB_SUDOERS_FILE="/etc/sudoers.d/wireguard-manager-web"

# 防并发：两个人/两个终端同时跑本脚本，同时改 wg0.conf 是常见的翻车原因
LOCK_FILE="/run/wireguard-manager.lock"

# 旧版本 (V1.0) 遗留文件，用于一次性迁移
LEGACY_CONFIG_DB="${MANAGER_DIR}/config.db"
LEGACY_CLIENT_DB="${MANAGER_DIR}/clients.db"
LEGACY_SITE_DB="${MANAGER_DIR}/sites.db"
LEGACY_SERVER_PRIVATE_KEY="${MANAGER_DIR}/server_private.key"
LEGACY_SERVER_PUBLIC_KEY="${MANAGER_DIR}/server_public.key"

FW_TAG="wg-manager"
NFT_INCLUDE_FILE="${MANAGER_DIR}/nftables-wg-manager.conf"
NFT_MAIN_CONF="/etc/nftables.conf"

# 运行模式：interactive（菜单）/ cli（非交互子命令）
RUN_MODE="interactive"
# --json 时置 yes，所有彩色提示改走 stderr，保证 stdout 是纯 JSON
JSON_MODE="no"

# Peer 状态分档阈值（秒），与 Web 面板/告警引擎保持一致
PEER_ONLINE_SECS=180
PEER_IDLE_SECS=900

export DEBIAN_FRONTEND=noninteractive

# ------------------------------------------------------------
# 基础函数
# ------------------------------------------------------------

# 所有人类可读提示的统一出口。--json 模式下改走 stderr，
# 这样 `wgmgr peer list --json | jq` 拿到的一定是纯 JSON，
# 不会混进 rebuild_server_config 之类函数里的绿色成功提示。
_msg() {
    if [[ "$JSON_MODE" == "yes" ]]; then
        echo -e "$*" >&2
    else
        echo -e "$*"
    fi
}

red()    { _msg "\033[31m$*\033[0m"; }
green()  { _msg "\033[32m$*\033[0m"; }
yellow() { _msg "\033[33m$*\033[0m"; }
blue()   { _msg "\033[34m$*\033[0m"; }
cyan()   { _msg "\033[36m$*\033[0m"; }
bold()   { _msg "\033[1m$*\033[0m"; }

pause() {
    [[ "$RUN_MODE" == "interactive" ]] || return 0
    echo
   read -rp "按 Enter 返回..." _
}
print_existing_clients() {
    local count=0
    for mdir in "$CLIENTS_DIR"/*/; do
        [[ -f "${mdir}meta.conf" ]] || continue
        local cname cip cstat
        cname=$(get_kv "${mdir}meta.conf" NAME)
        cip=$(get_kv "${mdir}meta.conf" IP4)
        cstat=$(get_kv "${mdir}meta.conf" ENABLED)
        [[ "$cstat" == "yes" ]] && cstat="启用" || cstat="禁用"
        printf "  %-16s %-18s [%s]\n" "$cname" "$cip" "$cstat"
        ((count++))
    done
    return $count
}

print_existing_sites() {
    local count=0
    for sdir in "$SITES_DIR"/*/; do
        [[ -f "${sdir}meta.conf" ]] || continue
        local sname slitpep sstat
        sname=$(get_kv "${sdir}meta.conf" NAME)
        slitpep=$(get_kv "${sdir}meta.conf" REMOTE_LAN)
        sstat=$(get_kv "${sdir}meta.conf" ENABLED)
        [[ "$sstat" == "yes" ]] && sstat="启用" || sstat="禁用"
        printf "  %-16s 对端LAN: %-20s [%s]\n" "$sname" "$slitpep" "$sstat"
        ((count++))
    done
    return $count
}

prompt_client_name() {
    local prompt_msg="$1"
    print_existing_clients
    local cnt=$?
    (( cnt == 0 )) && { yellow "暂无客户端。"; return 1; }
    echo
    read -rp "$prompt_msg" name
    [[ -z "$name" ]] && return 1
    return 0
}

prompt_site_name() {
    local prompt_msg="$1"
    print_existing_sites
    local cnt=$?
    (( cnt == 0 )) && { yellow "暂无站点。"; return 1; }
    echo
    read -rp "$prompt_msg" name
    [[ -z "$name" ]] && return 1
    return 0
}

die() {
    red "错误：$*"
    exit 1
}

command_exists() {
    command -v "$1" >/dev/null 2>&1
}

require_root() {
    if [[ "${EUID}" -ne 0 ]]; then
        die "请使用 root 运行，例如：sudo ./wireguard-manager-v2.0.sh"
    fi
}

# 拿不到锁说明另一个实例正在跑，直接退出，避免两边同时改 wg0.conf/meta。
# 如果连锁文件本身都建不了（权限异常、/run 只读等），绝不能悄悄放行——
# 那样并发保护形同虚设——必须让用户明确知情并手动确认后才继续。
#
# V2.0：$1 = exclusive（默认，会改配置的操作/交互式菜单）
#          shared   （只读操作，允许和别的只读操作并行）
# 采集守护进程走的是第三条路：完全不加锁，因为它只写 state/ 且用
# tmp+mv 原子落盘，读 meta.conf 时即使撞上 set_kv 的 mv 也只会读到
# 旧文件或新文件，不会读到半个文件。
acquire_lock() {
    local mode="${1:-exclusive}"
    local flock_flag="-x"
    [[ "$mode" == "shared" ]] && flock_flag="-s"

    if ! exec 9>"$LOCK_FILE" 2>/dev/null; then
        # 只读操作拿不到锁文件不值得打断用户，直接无锁继续；
        # 会改配置的操作必须让人明确知情。
        if [[ "$mode" == "shared" ]]; then
            return 0
        fi
        yellow "警告：无法创建锁文件 ${LOCK_FILE}（可能是权限问题或文件系统异常）。"
        yellow "这意味着本次运行不受并发保护，如果同时有另一个实例在跑，"
        yellow "可能会互相踩踏配置文件。"
        confirm "确认目前没有其他 WireGuard Manager 实例在运行，仍要继续？" "N" || exit 1
        return 0
    fi

    if ! flock -n $flock_flag 9; then
        if [[ "$mode" == "shared" ]]; then
            # 有排他操作正在改配置，只读命令安静退出而不是报错刷屏
            return 1
        fi
        die "检测到另一个 WireGuard Manager 实例正在运行（锁文件：${LOCK_FILE}）。"
    fi
    return 0
}

wg_is_up() {
    ip link show "$WG_INTERFACE" >/dev/null 2>&1
}

log_action() {
    [[ -d "$LOG_DIR" ]] || return 0
    echo "$(date '+%Y-%m-%d %H:%M:%S') $*" >> "${LOG_DIR}/manager.log" 2>/dev/null || true
}

confirm() {
    local prompt="$1"
    local default="${2:-N}"
    local answer

    # 非交互模式（CLI 子命令、采集守护进程、Web 层调用）一律取默认值，
    # 绝不去读 stdin：那时 stdin 可能是管道或空设备，read 要么读到垃圾
    # 要么直接挂住，而在这种上下文里"意外按了 Y"的后果比"什么都没做"严重得多。
    if [[ "$RUN_MODE" != "interactive" ]]; then
        [[ "$default" == "Y" ]]
        return
    fi

    if [[ "$default" == "Y" ]]; then
        read -rp "${prompt} [Y/n]: " answer
        answer="${answer:-Y}"
    else
        read -rp "${prompt} [y/N]: " answer
        answer="${answer:-N}"
    fi

    [[ "$answer" =~ ^[Yy]$ ]]
}

# ============================================================
# 初始化目录 + 迁移旧版本
# ============================================================

init_directories() {

    mkdir -p "$WG_DIR" "$MANAGER_DIR" "$SERVER_DIR" "$CLIENTS_DIR" "$SITES_DIR" \
             "$BACKUP_DIR" "$LOG_DIR" "$STATE_DIR" "$TRAFFIC_DIR"

    chmod 700 "$MANAGER_DIR" "$SERVER_DIR" "$CLIENTS_DIR" "$SITES_DIR" "$BACKUP_DIR" "$LOG_DIR"
    # state/ 里没有任何密钥，只有运行状态；采集进程和 Web 服务都要读，
    # 所以比 700 稍宽，但仍然不对 other 开放。
    chmod 750 "$STATE_DIR" "$TRAFFIC_DIR"

    touch "$MANAGER_CONF"
    touch "$ROUTES_CONF"
    touch "${LOG_DIR}/manager.log"
    chmod 600 "$MANAGER_CONF" "$ROUTES_CONF" "${LOG_DIR}/manager.log"

    # web.conf 存的是面板监听地址和口令哈希（scrypt），必须 600
    if [[ ! -f "$WEB_CONF" ]]; then
        touch "$WEB_CONF"
        chmod 600 "$WEB_CONF"
    fi

    # ---- 面板降权所需的最小放权（幂等，且必须放在这里）----
    # 上面几行每次调用都会把 MANAGER_DIR 设回 700、state/ 设回 750、conf 设回
    # 600 root:root。而采集守护进程每 30 秒就以 root 跑一次 `wgmgr collect`、
    # 面板每个写操作也都会 sudo 跑一次本脚本——也就是说本函数会被高频重入。
    # 如果只在 `web install` 里一次性放权，30 秒后就会被这里重置，降权到
    # wgmgr-web 的面板进程随即读不到 state/ 和 web.conf 而被锁死。所以放权
    # 逻辑必须落在这里：仅当面板已启用且 wgmgr-web 组存在时，重新放开面板
    # 运行所需的最小权限，其余目录（server/clients/sites/backups/logs）一律
    # 维持 700/600 root:root，密钥永远不对面板账号开放。
    if [[ "$(get_kv "$WEB_CONF" WEB_ENABLED 2>/dev/null)" == "yes" ]] \
       && getent group wgmgr-web >/dev/null 2>&1; then
        # 710：组只能 traverse 进目录按已知路径取文件，不能列目录内容；
        # 里面的 server/ 等仍是 700 root:root，面板账号进不去、读不到私钥。
        chgrp wgmgr-web "$MANAGER_DIR" 2>/dev/null || true
        chmod 710 "$MANAGER_DIR" 2>/dev/null || true
        # 2750：setgid 位让采集进程（root）之后在 state/ 里新建的 JSON /
        # jsonl 自动继承 wgmgr-web 属组，配合写入时的 640 即可被面板读取，
        # 不需要每次都 chgrp -R 整个目录。
        chgrp wgmgr-web "$STATE_DIR" "$TRAFFIC_DIR" 2>/dev/null || true
        chmod 2750 "$STATE_DIR" "$TRAFFIC_DIR" 2>/dev/null || true
        # 面板每次请求都重读 web.conf（口令哈希/监听）和 manager.conf（接口等），
        # 所以这两个要对 wgmgr-web 组可读；set_kv 已改成保留属组/权限位。
        chgrp wgmgr-web "$WEB_CONF" "$MANAGER_CONF" 2>/dev/null || true
        chmod 640 "$WEB_CONF" "$MANAGER_CONF" 2>/dev/null || true
    fi
}

# ============================================================
# 基础校验（避免把明显错误的数据写进 wg0.conf）
# ============================================================

is_valid_wg_key() {
    # WireGuard base64 密钥固定 44 字符，以 = 结尾
    [[ "$1" =~ ^[A-Za-z0-9+/]{43}=$ ]]
}

is_valid_ipv4() {
    local ip="${1%%/*}"
    [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]] || return 1
    local IFS=.
    local -a parts=($ip)
    local p
    for p in "${parts[@]}"; do
        [[ "$p" -ge 0 && "$p" -le 255 ]] || return 1
    done
    return 0
}

migrate_legacy_v1() {

    # 只有存在旧文件且新版尚未初始化过时才迁移
    [[ -f "$LEGACY_CONFIG_DB" || -f "$LEGACY_CLIENT_DB" ]] || return 0
    [[ -f "$MANAGER_CONF" && -s "$MANAGER_CONF" ]] && return 0

    yellow "检测到 V1.0 遗留数据，正在迁移到新的目录结构..."

    if [[ -f "$LEGACY_CONFIG_DB" ]]; then
        while IFS='=' read -r k v; do
            [[ -z "$k" ]] && continue
            set_kv "$MANAGER_CONF" "$k" "$v"
        done < "$LEGACY_CONFIG_DB"
    fi

    if [[ -f "$LEGACY_SERVER_PRIVATE_KEY" && ! -f "$SERVER_PRIVATE_KEY" ]]; then
        cp -a "$LEGACY_SERVER_PRIVATE_KEY" "$SERVER_PRIVATE_KEY"
        cp -a "$LEGACY_SERVER_PUBLIC_KEY" "$SERVER_PUBLIC_KEY"
        chmod 600 "$SERVER_PRIVATE_KEY" "$SERVER_PUBLIC_KEY"
    fi

    if [[ -f "$LEGACY_CLIENT_DB" ]]; then
        while IFS='|' read -r name ip pubkey dir; do
            [[ -z "$name" ]] && continue

            local cdir="${CLIENTS_DIR}/${name}"
            mkdir -p "$cdir"
            chmod 700 "$cdir"

            set_kv "${cdir}/meta.conf" "NAME" "$name"
            set_kv "${cdir}/meta.conf" "IP4" "$ip"
            set_kv "${cdir}/meta.conf" "PUBLIC_KEY" "$pubkey"
            set_kv "${cdir}/meta.conf" "ALLOWED_IPS" "0.0.0.0/0"
            set_kv "${cdir}/meta.conf" "ENABLED" "yes"
            set_kv "${cdir}/meta.conf" "CREATED" "$(date '+%Y-%m-%d %H:%M:%S')"

            if [[ -n "${dir:-}" && -f "${dir}/private.key" ]]; then
                cp -a "${dir}/private.key" "${cdir}/private.key"
                cp -a "${dir}/public.key" "${cdir}/public.key" 2>/dev/null || echo "$pubkey" > "${cdir}/public.key"
                chmod 600 "${cdir}/private.key" "${cdir}/public.key"
            fi
        done < "$LEGACY_CLIENT_DB"
    fi

    if [[ -f "$LEGACY_SITE_DB" ]]; then
        while IFS='|' read -r name network wgip endpoint; do
            [[ -z "$name" ]] && continue

            local sdir="${SITES_DIR}/${name}"
            mkdir -p "$sdir"
            chmod 700 "$sdir"

            set_kv "${sdir}/meta.conf" "NAME" "$name"
            set_kv "${sdir}/meta.conf" "REMOTE_LAN" "$network"
            set_kv "${sdir}/meta.conf" "REMOTE_WG_IP" "$wgip"
            set_kv "${sdir}/meta.conf" "REMOTE_ENDPOINT" "$endpoint"
            set_kv "${sdir}/meta.conf" "ENABLED" "no"
            yellow "  站点 ${name} 缺少公钥等信息，已标记为禁用，请到"
            yellow "  站点管理 -> 编辑站点 中补全后启用。"
        done < "$LEGACY_SITE_DB"
    fi

    green "迁移完成。旧文件保留在原位置，未自动删除。"
    pause
}

# ============================================================
# 系统检测
# ============================================================

check_os() {

    [[ -f /etc/os-release ]] || die "无法识别操作系统"

    # shellcheck disable=SC1091
    source /etc/os-release

    case "${ID:-}" in
        debian|ubuntu) ;;
        *) die "当前脚本仅支持 Debian / Ubuntu" ;;
    esac

    OS_NAME="${PRETTY_NAME:-$ID}"
}

check_dependencies() {

    local packages=()

    command_exists wg        || packages+=("wireguard")
    command_exists wg-quick  || packages+=("wireguard")
    command_exists qrencode  || packages+=("qrencode")
    command_exists curl      || packages+=("curl")
    command_exists ip        || packages+=("iproute2")

    if [[ ${#packages[@]} -gt 0 ]]; then

        yellow "发现缺少依赖："
        printf '  %s\n' "${packages[@]}"

        if confirm "是否自动安装？" "Y"; then
            apt-get update
            apt-get install -y "${packages[@]}"
        else
            yellow "未安装依赖，部分功能可能无法使用。"
        fi
    fi
}

# ============================================================
# 网络检测
# ============================================================

get_default_interface() {
    ip route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

get_default_interface6() {
    ip -6 route show default 2>/dev/null | awk '/default/ {print $5; exit}'
}

get_default_gateway() {
    ip route show default 2>/dev/null | awk '/default/ {print $3; exit}'
}

get_local_ipv4() {
    local iface="$1"
    ip -4 addr show dev "$iface" 2>/dev/null | awk '/inet / {print $2; exit}'
}

get_public_ipv4() {
    local ipaddr=""
    ipaddr=$(curl -4 -fsS --max-time 5 https://api.ipify.org 2>/dev/null || true)
    [[ -z "$ipaddr" ]] && ipaddr=$(curl -4 -fsS --max-time 5 https://ifconfig.me 2>/dev/null || true)
    echo "$ipaddr"
}

get_public_ipv6() {
    curl -6 -fsS --max-time 5 https://api64.ipify.org 2>/dev/null || true
}

# ============================================================
# 通用 key=value 读写（用于 manager.conf / meta.conf）
# ============================================================

set_kv() {
    local file="$1" key="$2" value="$3"
    local mode="" gid=""

    # 记住既有的权限位和属组：web.conf / manager.conf 被 init_directories
    # 放成 640 root:wgmgr-web，好让降权的面板进程能读。面板通过 sudo 调
    # `wgmgr web passwd` 改口令时会再次走到这里——如果一律 chmod 600、再
    # 让 mv 把属组冲掉，面板会在改完口令的瞬间读不到 web.conf 而把自己锁死。
    # 所以这里"保留原状"：原本 600 的（meta.conf 等）继续 600，原本对
    # wgmgr-web 组可读的继续可读。文件第一次创建时仍走 600 的安全默认。
    if [[ -e "$file" ]]; then
        mode="$(stat -c '%a' "$file" 2>/dev/null)"
        gid="$(stat -c '%g' "$file" 2>/dev/null)"
    fi

    touch "$file"
    grep -v "^${key}=" "$file" > "${file}.tmp" 2>/dev/null || true
    echo "${key}=${value}" >> "${file}.tmp"
    if [[ -n "$gid" ]]; then
        chgrp "$gid" "${file}.tmp" 2>/dev/null || true
    fi
    mv "${file}.tmp" "$file"
    chmod "${mode:-600}" "$file"
}

get_kv() {
    local file="$1" key="$2"
    [[ -f "$file" ]] || return
    grep "^${key}=" "$file" 2>/dev/null | tail -n 1 | cut -d '=' -f 2-
}

set_config()  { set_kv "$MANAGER_CONF" "$1" "$2"; }
get_config()  { get_kv "$MANAGER_CONF" "$1"; }

# ============================================================
# CIDR 工具
# ============================================================

ip_to_int() {
    local ip="$1" a b c d
    IFS=. read -r a b c d <<< "$ip"
    echo $((a * 256**3 + b * 256**2 + c * 256 + d))
}

int_to_ip() {
    local ip="$1"
    echo "$((ip >> 24 & 255)).$((ip >> 16 & 255)).$((ip >> 8 & 255)).$((ip & 255))"
}

# 粗略判断两个 IPv4 CIDR 是否有交集
cidr4_overlap() {
    local net1="$1" net2="$2"
    local ip1="${net1%%/*}" bits1="${net1##*/}"
    local ip2="${net2%%/*}" bits2="${net2##*/}"

    local mask1=$(( 0xFFFFFFFF << (32 - bits1) & 0xFFFFFFFF ))
    local mask2=$(( 0xFFFFFFFF << (32 - bits2) & 0xFFFFFFFF ))

    local i1 i2
    i1=$(ip_to_int "$ip1")
    i2=$(ip_to_int "$ip2")

    local net1_base=$(( i1 & mask1 ))
    local net2_base=$(( i2 & mask2 ))

    local common_mask=$(( mask1 < mask2 ? mask1 : mask2 ))

    [[ $(( net1_base & common_mask )) -eq $(( net2_base & common_mask )) ]]
}

# ============================================================
# 密钥
# ============================================================

generate_server_keys() {

    init_directories

    if [[ ! -f "$SERVER_PRIVATE_KEY" ]]; then

        umask 077
        wg genkey > "$SERVER_PRIVATE_KEY"
        wg pubkey < "$SERVER_PRIVATE_KEY" > "$SERVER_PUBLIC_KEY"
        chmod 600 "$SERVER_PRIVATE_KEY" "$SERVER_PUBLIC_KEY"

        green "服务器密钥已生成。"
    fi
}

get_server_private_key() { cat "$SERVER_PRIVATE_KEY" 2>/dev/null; }
get_server_public_key()  { cat "$SERVER_PUBLIC_KEY" 2>/dev/null; }

# ============================================================
# IP 地址分配（扫描所有 client / site 元数据，避免冲突）
# ============================================================

all_used_ip4() {
    {
        get_config SERVER_IP4 | cut -d/ -f1
        for f in "$CLIENTS_DIR"/*/meta.conf "$SITES_DIR"/*/meta.conf; do
            [[ -f "$f" ]] || continue
            get_kv "$f" IP4
            get_kv "$f" REMOTE_WG_IP
        done
    } 2>/dev/null
}

get_next_client_ip4() {
    local network prefix base_int host_bits max_host mask network_int i candidate used

    network=$(get_config VPN_NETWORK4)
    [[ -z "$network" ]] && network="10.66.66.0/24"

    prefix="${network##*/}"
    [[ "$prefix" =~ ^[0-9]+$ ]] || prefix=24
    (( prefix < 1 )) && prefix=1
    (( prefix > 30 )) && { red "VPN 网段掩码 /${prefix} 太小，分不出可用的客户端 IP。"; return 1; }

    host_bits=$((32 - prefix))

    # /16 以上（超过 65534 台主机）线性扫描会很慢，这个规模也完全没必要
    # 用来发 WireGuard 客户端 IP，直接限制掉，避免脚本卡死在这里。
    if (( host_bits > 16 )); then
        red "VPN 网段 ${network} 太大（超过 /16），出于性能考虑本脚本不支持"
        red "在这么大的网段里自动分配 IP，请把 VPN 网段收窄到 /16 或更小。"
        return 1
    fi

    max_host=$(( (1 << host_bits) - 2 ))   # 去掉网络地址和广播地址
    (( max_host < 1 )) && return 1

    local base="${network%%/*}"
    base_int=$(ip_to_int "$base")
    mask=$(( host_bits >= 32 ? 0 : (0xFFFFFFFF << host_bits) & 0xFFFFFFFF ))
    network_int=$(( base_int & mask ))

    used=$(all_used_ip4)

    for ((i=1; i<=max_host; i++)); do
        candidate=$(int_to_ip $((network_int + i)))
        if ! grep -qx "$candidate" <<< "$used"; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

get_next_client_ip6() {
    local network prefix i candidate used

    network=$(get_config VPN_NETWORK6)
    [[ -z "$network" ]] && return 1

    used=$(
        for f in "$CLIENTS_DIR"/*/meta.conf; do
            [[ -f "$f" ]] || continue
            get_kv "$f" IP6
        done
    )

    prefix="${network%%/*}"
    # 去掉结尾的 :: 或 :0 之类，按十六进制最后一段递增
    local head="${prefix%::*}"

    for i in $(seq 2 254); do
        candidate=$(printf "%s::%x" "$head" "$i")
        if ! grep -qx "$candidate" <<< "$used"; then
            echo "$candidate"
            return 0
        fi
    done

    return 1
}

# ============================================================
# 防火墙抽象层
#   所有由本脚本添加的规则统一打注释标签 $FW_TAG，方便精确回收。
# ============================================================

fw_detect_backend() {

    local backend

    backend=$(get_config FW_BACKEND)

    if [[ -n "$backend" ]]; then
        echo "$backend"
        return
    fi

    if command_exists ufw && ufw status 2>/dev/null | grep -q "Status: active"; then
        echo "ufw"
    elif command_exists nft && systemctl is-active --quiet nftables 2>/dev/null; then
        echo "nftables"
    elif command_exists iptables; then
        echo "iptables"
    else
        echo "none"
    fi
}

fw_persist() {
    local backend="$1"

    case "$backend" in
        iptables)
            if command_exists netfilter-persistent; then
                netfilter-persistent save >/dev/null 2>&1 || true
            elif command_exists iptables-save; then
                mkdir -p /etc/iptables
                iptables-save > /etc/iptables/rules.v4 2>/dev/null || true
                command_exists ip6tables-save && ip6tables-save > /etc/iptables/rules.v6 2>/dev/null || true
            fi
            ;;
        nftables)
            # 安全提示：这里绝对不能再用 `nft list ruleset > /etc/nftables.conf`。
            # 那样会把当前内存里的整份 nftables 规则（包括 Docker/PVE 自己动态
            # 建的隔离规则）原样冻结成"静态僵尸规则"写进主配置，重启后 Docker/PVE
            # 重新建立自己的规则时很容易和这份旧快照冲突，甚至整个宿主机网络
            # 起不来。所以只把本脚本自己的两张表导出到独立文件，再往主配置里
            # 追加一行 include，绝不覆盖/触碰主配置文件本身已有的任何内容。
            if command_exists nft && nft list table inet wg_manager >/dev/null 2>&1; then
                {
                    nft -s list table inet wg_manager 2>/dev/null
                    echo
                    nft -s list table ip wg_manager_nat 2>/dev/null
                    echo
                    nft -s list table ip6 wg_manager_nat6 2>/dev/null
                } > "$NFT_INCLUDE_FILE" 2>/dev/null
                chmod 600 "$NFT_INCLUDE_FILE"

                if [[ -f "$NFT_MAIN_CONF" ]] && ! grep -qF "$NFT_INCLUDE_FILE" "$NFT_MAIN_CONF" 2>/dev/null; then
                    echo "include \"${NFT_INCLUDE_FILE}\"" >> "$NFT_MAIN_CONF"
                fi
            else
                # 我们自己的表已经不存在了（比如刚清理过），保持整洁，
                # 不要留一条指向空文件的 include。
                rm -f "$NFT_INCLUDE_FILE"
                [[ -f "$NFT_MAIN_CONF" ]] && sed -i "\|include \"${NFT_INCLUDE_FILE}\"|d" "$NFT_MAIN_CONF" 2>/dev/null || true
            fi
            systemctl enable nftables >/dev/null 2>&1 || true
            ;;
        ufw)
            : # ufw 规则本身即持久
            ;;
    esac
}

# --- nftables：使用独立的表 inet wg_manager，避免碰用户现有 ruleset ---
# 注意：forward 链的默认策略必须留 accept，不能改成 drop——这张表挂在
# 全局 forward 钩子上，会拦到这台机器上所有转发流量，如果改成默认拒绝，
# 会连 Docker/PVE 自己的容器间转发、其他网桥流量一起误伤。真正需要收紧
# 的是"IPv6 全局转发"这个开关本身的风险，见 fw_ipv6_forward_guard()。
fw_nft_ensure_table() {
    nft list table inet wg_manager >/dev/null 2>&1 && return
    nft add table inet wg_manager
    nft add chain inet wg_manager input '{ type filter hook input priority 0 ; policy accept ; }'
    nft add chain inet wg_manager forward '{ type filter hook forward priority 0 ; policy accept ; }'
    nft add table ip wg_manager_nat 2>/dev/null || true
    nft add chain ip wg_manager_nat postrouting '{ type nat hook postrouting priority 100 ; }' 2>/dev/null || true
}

# nftables 的 nat 类型表必须按地址族分开建（ip / ip6），不能像 input/forward
# 那样共用一张 inet 表，所以 IPv6 的 NAT 单独开一张 ip6 wg_manager_nat6。
fw_nft_ensure_table6() {
    nft list table ip6 wg_manager_nat6 >/dev/null 2>&1 && return
    nft add table ip6 wg_manager_nat6 2>/dev/null || true
    nft add chain ip6 wg_manager_nat6 postrouting '{ type nat hook postrouting priority 100 ; }' 2>/dev/null || true
}

# 放行 WireGuard 监听端口
fw_add_input_port() {
    local proto="$1" port="$2"
    local backend
    backend=$(fw_detect_backend)

    case "$backend" in
        ufw)
            ufw allow "${port}/${proto}" comment "$FW_TAG" >/dev/null
            ;;
        nftables)
            fw_nft_ensure_table
            nft add rule inet wg_manager input "${proto}" dport "${port}" accept comment \"${FW_TAG}\" 2>/dev/null || \
            nft add rule inet wg_manager input "${proto}" dport "${port}" accept
            ;;
        iptables)
            iptables -C INPUT -p "$proto" --dport "$port" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -p "$proto" --dport "$port" -m comment --comment "$FW_TAG" -j ACCEPT
            ;;
        none)
            yellow "未检测到受支持的防火墙，跳过端口放行（请确认 ${proto}/${port} 未被拦截）。"
            ;;
    esac

    fw_persist "$backend"
}

# 允许两个网卡之间转发（用于 wg <-> WAN，或 wg <-> LAN）
fw_add_forward() {
    local in_if="$1" out_if="$2"
    local backend
    backend=$(fw_detect_backend)

    case "$backend" in
        ufw)
            # ufw route 规则
            ufw route allow in on "$in_if" out on "$out_if" comment "$FW_TAG" >/dev/null 2>&1 || true
            ufw route allow in on "$out_if" out on "$in_if" comment "$FW_TAG" >/dev/null 2>&1 || true
            ;;
        nftables)
            fw_nft_ensure_table
            nft add rule inet wg_manager forward iifname "$in_if" oifname "$out_if" accept 2>/dev/null || true
            nft add rule inet wg_manager forward iifname "$out_if" oifname "$in_if" ct state established,related accept 2>/dev/null || true
            ;;
        iptables)
            iptables -C FORWARD -i "$in_if" -o "$out_if" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "$in_if" -o "$out_if" -m comment --comment "$FW_TAG" -j ACCEPT

            iptables -C FORWARD -i "$out_if" -o "$in_if" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null || \
            iptables -A FORWARD -i "$out_if" -o "$in_if" -m conntrack --ctstate RELATED,ESTABLISHED -m comment --comment "$FW_TAG" -j ACCEPT
            ;;
        none) : ;;
    esac

    fw_persist "$backend"
}

# NAT（MASQUERADE）某个网段经由某网卡出网。传入的 network 可能是 IPv4
# 也可能是 IPv6（NAT66），两者在 nftables/iptables 里都必须走各自专属的
# 表/命令，不能混用——之前这里直接把 IPv6 网段传给 IPv4 专属的
# `ip wg_manager_nat` 表和 `iptables`，规则语法错误但被 `2>/dev/null`
# 吞掉了，NAT66 实际上从来没有生效过。
fw_add_nat() {
    local network="$1" out_if="$2"
    local backend
    backend=$(fw_detect_backend)

    local is_v6=0
    [[ "$network" == *:* ]] && is_v6=1

    case "$backend" in
        ufw|iptables)
            if [[ $is_v6 -eq 1 ]]; then
                if command_exists ip6tables; then
                    ip6tables -t nat -C POSTROUTING -s "$network" -o "$out_if" -m comment --comment "$FW_TAG" -j MASQUERADE 2>/dev/null || \
                    ip6tables -t nat -A POSTROUTING -s "$network" -o "$out_if" -m comment --comment "$FW_TAG" -j MASQUERADE
                else
                    yellow "系统没有 ip6tables，无法下发 NAT66 规则（${network}）。"
                fi
            else
                iptables -t nat -C POSTROUTING -s "$network" -o "$out_if" -m comment --comment "$FW_TAG" -j MASQUERADE 2>/dev/null || \
                iptables -t nat -A POSTROUTING -s "$network" -o "$out_if" -m comment --comment "$FW_TAG" -j MASQUERADE
            fi
            ;;
        nftables)
            if [[ $is_v6 -eq 1 ]]; then
                fw_nft_ensure_table6
                nft add rule ip6 wg_manager_nat6 postrouting ip6 saddr "$network" oifname "$out_if" masquerade 2>/dev/null || \
                    yellow "nftables 下发 NAT66 规则失败（${network} via ${out_if}），请到「防火墙 -> 查看规则概览」核对。"
            else
                fw_nft_ensure_table
                nft add rule ip wg_manager_nat postrouting ip saddr "$network" oifname "$out_if" masquerade 2>/dev/null || \
                    yellow "nftables 下发 NAT 规则失败（${network} via ${out_if}），请到「防火墙 -> 查看规则概览」核对。"
            fi
            ;;
        none) : ;;
    esac

    fw_persist "$backend"
}

fw_clear_tagged() {

    if command_exists ufw; then
        # ufw 没有按注释批量删除的命令，逐条匹配删除
        while ufw status numbered 2>/dev/null | grep "$FW_TAG" | head -n1 | grep -qE '^\['; do
            local num
            num=$(ufw status numbered 2>/dev/null | grep "$FW_TAG" | head -n1 | grep -oE '^\[[0-9]+\]' | tr -d '[]')
            [[ -z "$num" ]] && break
            yes | ufw delete "$num" >/dev/null 2>&1 || break
        done
    fi

    if command_exists nft; then
        nft delete table inet wg_manager 2>/dev/null || true
        nft delete table ip wg_manager_nat 2>/dev/null || true
        nft delete table ip6 wg_manager_nat6 2>/dev/null || true
    fi

    if command_exists iptables; then
        while iptables -L INPUT --line-numbers -n 2>/dev/null | grep -q "$FW_TAG"; do
            local line
            line=$(iptables -L INPUT --line-numbers -n 2>/dev/null | grep "$FW_TAG" | head -n1 | awk '{print $1}')
            [[ -z "$line" ]] && break
            iptables -D INPUT "$line"
        done

        while iptables -L FORWARD --line-numbers -n 2>/dev/null | grep -q "$FW_TAG"; do
            local line
            line=$(iptables -L FORWARD --line-numbers -n 2>/dev/null | grep "$FW_TAG" | head -n1 | awk '{print $1}')
            [[ -z "$line" ]] && break
            iptables -D FORWARD "$line"
        done

        while iptables -t nat -L POSTROUTING --line-numbers -n 2>/dev/null | grep -q "$FW_TAG"; do
            local line
            line=$(iptables -t nat -L POSTROUTING --line-numbers -n 2>/dev/null | grep "$FW_TAG" | head -n1 | awk '{print $1}')
            [[ -z "$line" ]] && break
            iptables -t nat -D POSTROUTING "$line"
        done
    fi

    if command_exists ip6tables; then
        while ip6tables -L FORWARD --line-numbers -n 2>/dev/null | grep -q "$FW_TAG"; do
            local line
            line=$(ip6tables -L FORWARD --line-numbers -n 2>/dev/null | grep "$FW_TAG" | head -n1 | awk '{print $1}')
            [[ -z "$line" ]] && break
            ip6tables -D FORWARD "$line"
        done

        while ip6tables -t nat -L POSTROUTING --line-numbers -n 2>/dev/null | grep -q "$FW_TAG"; do
            local line
            line=$(ip6tables -t nat -L POSTROUTING --line-numbers -n 2>/dev/null | grep "$FW_TAG" | head -n1 | awk '{print $1}')
            [[ -z "$line" ]] && break
            ip6tables -t nat -D POSTROUTING "$line"
        done
    fi
}

fw_cleanup_all() {

    yellow "正在清理本脚本添加的防火墙规则（仅清理带 ${FW_TAG} 标签的规则）..."

    fw_clear_tagged

    local backend
    backend=$(fw_detect_backend)
    fw_persist "$backend"   # nftables 分支里，表已经不存在时会自动把 include 一起清掉

    green "防火墙规则清理完成。"
}

# 幂等的"声明式"防火墙同步：先清空本脚本打过标签的规则，再根据当前
# manager.conf + 已启用的 client/site 元数据完整重新下发一遍。
# 好处：禁用/删除一个 Site 之后，它对应的 LAN 转发/NAT 规则会在下一次
# rebuild_server_config() 时自动跟着消失，不需要用户记得去手动清理
# （这是很多"一键脚本"最容易留坑的地方）。
fw_sync_state() {

    local port wan vpn4 vpn6 nat66 internet_nat

    port=$(get_config WG_PORT)
    wan=$(get_config WAN_INTERFACE)

    # 服务端还没初始化，没什么好同步的
    [[ -z "$port" || -z "$wan" ]] && return 0

    fw_clear_tagged

    vpn4=$(get_config VPN_NETWORK4)
    vpn6=$(get_config VPN_NETWORK6)
    nat66=$(get_config NAT66)
    internet_nat=$(get_config INTERNET_NAT)
    internet_nat="${internet_nat:-yes}"   # 兼容老版本升级上来、没这个字段的情况

    fw_add_input_port "udp" "$port"
    fw_add_forward "$WG_INTERFACE" "$wan"

    if [[ "$internet_nat" == "yes" ]]; then
        [[ -n "$vpn4" ]] && fw_add_nat "$vpn4" "$wan"
        [[ "$nat66" == "yes" && -n "$vpn6" ]] && fw_add_nat "$vpn6" "$wan"
    fi

    local sdir mode local_lan senabled lan_iface
    for sdir in "$SITES_DIR"/*/; do
        [[ -f "${sdir}meta.conf" ]] || continue

        senabled=$(get_kv "${sdir}meta.conf" ENABLED)
        [[ "$senabled" == "yes" ]] || continue

        mode=$(get_kv "${sdir}meta.conf" MODE)
        [[ "$mode" == "conflict" ]] && continue   # 仅 VPN IP 互通，不动 LAN 转发

        local_lan=$(get_kv "${sdir}meta.conf" LOCAL_LAN)
        [[ -z "$local_lan" ]] && continue

        lan_iface=$(ip route | awk -v net="$local_lan" '$0 ~ net {print $3; exit}')
        [[ -z "$lan_iface" ]] && continue

        fw_add_forward "$lan_iface" "$WG_INTERFACE"
        [[ "$mode" == "nat" ]] && fw_add_nat "$local_lan" "$WG_INTERFACE"
    done

    if [[ "$(get_config USE_IPV6)" == "yes" && "$(get_config IPV6_FORWARD_HARDEN)" == "yes" ]]; then
        fw_ipv6_forward_guard_apply
    fi

    # ---- Web 面板端口 ----
    # 必须写在这里而不是安装时单独下发一次：上面 fw_clear_tagged 每次都会
    # 把所有带标签的规则清空重建，面板端口如果游离在这个循环之外，那么任何
    # 一次"加客户端 / 改 NAT 开关"都会顺手把它关掉，你会突然发现浏览器连不上
    # 了——而这恰好是你最想打开面板看一眼的时候。
    fw_sync_web_port

    local backend
    backend=$(fw_detect_backend)
    fw_persist "$backend"
}

# 按 web.conf 里的 WEB_BIND_SCOPE 决定放行方式：
#   vpn    —— 只接受从 $WG_INTERFACE 进来的连接（面板只能从隧道内部访问，推荐）
#   public —— 接受任意来源的入站连接（等于把面板暴露到公网，仅在你自己
#             已经用反代 / Cloudflare Access 挡了一层时才建议这么选）
#   local  —— 只绑 127.0.0.1，防火墙层不需要放行任何入站规则，靠 ssh -L 访问
fw_sync_web_port() {
    [[ -f "$WEB_CONF" ]] || return 0
    [[ "$(get_kv "$WEB_CONF" WEB_ENABLED)" == "yes" ]] || return 0

    local scope listen web_port
    scope=$(get_kv "$WEB_CONF" WEB_BIND_SCOPE); scope="${scope:-local}"
    listen=$(get_kv "$WEB_CONF" WEB_LISTEN);    listen="${listen:-127.0.0.1:8443}"
    web_port="${listen##*:}"

    # WEB_LISTEN 是脚本自己写的，但万一被手改成畸形值，这里必须挡住：
    # 把空字符串或非数字传给 nft / iptables 会生成一条语法错误甚至过宽的规则。
    [[ "$web_port" =~ ^[0-9]{1,5}$ ]] || return 0

    case "$scope" in
        vpn)    fw_add_web_port_vpn "$web_port" ;;
        public) fw_add_input_port "tcp" "$web_port" ;;
        *)      : ;;   # local：只绑回环，不放行任何入站
    esac
}

# 可选加固（默认关闭，需要在高级设置里手动开启）：只放行经过 $WG_INTERFACE
# 的 IPv6 转发流量，其余 IPv6 转发一律丢弃。刻意只匹配 nfproto ipv6 /
# ip6tables，不碰 IPv4 的 FORWARD 链——这样即使这台机器上还跑着 Docker/PVE
# 自己的 IPv4 转发，也完全不受影响；代价是如果你在这台机器上还有其他
# 用途的 IPv6 转发（不经过 WireGuard），也会被一起挡掉，所以默认不开启，
# 由用户自己判断是否适用。
fw_ipv6_forward_guard_apply() {
    local backend
    backend=$(fw_detect_backend)

    case "$backend" in
        nftables)
            fw_nft_ensure_table
            nft add rule inet wg_manager forward meta nfproto ipv6 iifname != "$WG_INTERFACE" oifname != "$WG_INTERFACE" drop 2>/dev/null || true
            ;;
        iptables|ufw)
            if command_exists ip6tables; then
                ip6tables -C FORWARD ! -i "$WG_INTERFACE" ! -o "$WG_INTERFACE" -m comment --comment "$FW_TAG" -j DROP 2>/dev/null || \
                ip6tables -A FORWARD ! -i "$WG_INTERFACE" ! -o "$WG_INTERFACE" -m comment --comment "$FW_TAG" -j DROP 2>/dev/null || true
            fi
            ;;
    esac
}

# ============================================================
# IP Forward
# ============================================================

configure_ip_forward() {

    local enable_v6="${1:-no}"

    {
        echo "net.ipv4.ip_forward=1"
        [[ "$enable_v6" == "yes" ]] && echo "net.ipv6.conf.all.forwarding=1"
    } > /etc/sysctl.d/99-wireguard.conf

    sysctl --system >/dev/null 2>&1 || true

    green "IP forwarding 已开启（IPv4$( [[ "$enable_v6" == "yes" ]] && echo " + IPv6")）。"
}

# ============================================================
# 服务端：配置生成 / 校验 / 应用
# ============================================================

# 在任何会动网络的操作前调用：对 wg0.conf / sysctl / 防火墙规则
# 打一份完整的时间戳快照，失败了可以用 restore_snapshot 精确回滚。
# 这是"自动安全网"，和用户手动触发的完整 tar.gz 备份（backup_config）是两回事。
backup_snapshot() {
    local reason="${1:-change}"
    local ts dir backend

    ts=$(date '+%Y%m%d_%H%M%S')
    dir="${BACKUP_DIR}/${ts}_${reason}"
    mkdir -p "$dir"
    chmod 700 "$dir"

    [[ -f "$WG_CONFIG" ]] && cp -a "$WG_CONFIG" "${dir}/$(basename "$WG_CONFIG")" 2>/dev/null || true
    [[ -f /etc/sysctl.d/99-wireguard.conf ]] && cp -a /etc/sysctl.d/99-wireguard.conf "${dir}/99-wireguard.conf" 2>/dev/null || true

    backend=$(fw_detect_backend 2>/dev/null || echo none)
    echo "$backend" > "${dir}/fw_backend.txt"

    case "$backend" in
        iptables)
            command_exists iptables-save && iptables-save > "${dir}/iptables.rules" 2>/dev/null || true
            command_exists ip6tables-save && ip6tables-save > "${dir}/ip6tables.rules" 2>/dev/null || true
            ;;
        nftables)
            command_exists nft && nft list ruleset > "${dir}/nftables.rules" 2>/dev/null || true
            ;;
        ufw)
            command_exists ufw && ufw status verbose > "${dir}/ufw_status.txt" 2>/dev/null || true
            ;;
    esac

    echo "$reason" > "${dir}/reason.txt"

    # 只保留最近 30 份自动快照，避免无限增长
    ls -1dt "${BACKUP_DIR}"/*_* 2>/dev/null | tail -n +31 | xargs -r rm -rf

    echo "$dir"
}

list_snapshots() {
    ls -1dt "${BACKUP_DIR}"/*_* 2>/dev/null
}

restore_snapshot() {

    clear
    bold "=========================================="
    bold "         从自动快照回滚"
    bold "=========================================="
    echo
    yellow "这里恢复的是 wg0.conf / sysctl 转发设置 / 防火墙规则的某个历史状态，"
    yellow "用于「改配置改挂了、赶紧回到上一次能用的状态」这种场景。"
    echo

    local snaps
    mapfile -t snaps < <(list_snapshots)

    if [[ ${#snaps[@]} -eq 0 ]]; then
        yellow "暂无自动快照。"
        pause
        return
    fi

    local i
    for i in "${!snaps[@]}"; do
        local reason
        reason=$(cat "${snaps[$i]}/reason.txt" 2>/dev/null || echo "?")
        echo "  $((i+1)). $(basename "${snaps[$i]}")  (${reason})"
    done
    echo

    read -rp "选择要恢复的快照编号（0 取消）: " choice
    [[ "$choice" == "0" || -z "$choice" ]] && return

    local idx=$((choice - 1))
    [[ -z "${snaps[$idx]:-}" ]] && { red "无效编号。"; pause; return; }

    local dir="${snaps[$idx]}"

    yellow "即将恢复："
    echo "  wg0.conf     : $( [[ -f "${dir}/$(basename "$WG_CONFIG")" ]] && echo 有 || echo 无 )"
    echo "  sysctl 设置  : $( [[ -f "${dir}/99-wireguard.conf" ]] && echo 有 || echo 无 )"
    echo "  防火墙规则   : $(cat "${dir}/fw_backend.txt" 2>/dev/null || echo 未记录)"
    echo
    yellow "防火墙规则的恢复只对 iptables/nftables 生效（会整体覆盖当前 ruleset，"
    yellow "如果你在这之后手动加过别的规则也会被覆盖，请谨慎）；UFW 不做自动恢复。"
    echo

    read -rp "确认恢复？输入 RESTORE: " confirm_text
    [[ "$confirm_text" != "RESTORE" ]] && { yellow "已取消。"; pause; return; }

    if [[ -f "${dir}/$(basename "$WG_CONFIG")" ]]; then
        install -m 600 "${dir}/$(basename "$WG_CONFIG")" "$WG_CONFIG"
    fi

    if [[ -f "${dir}/99-wireguard.conf" ]]; then
        install -m 644 "${dir}/99-wireguard.conf" /etc/sysctl.d/99-wireguard.conf
        sysctl --system >/dev/null 2>&1 || true
    fi

    local backend
    backend=$(cat "${dir}/fw_backend.txt" 2>/dev/null || echo none)
    case "$backend" in
        iptables)
            [[ -f "${dir}/iptables.rules" ]] && command_exists iptables-restore && iptables-restore < "${dir}/iptables.rules"
            [[ -f "${dir}/ip6tables.rules" ]] && command_exists ip6tables-restore && ip6tables-restore < "${dir}/ip6tables.rules"
            ;;
        nftables)
            [[ -f "${dir}/nftables.rules" ]] && command_exists nft && nft -f "${dir}/nftables.rules"
            ;;
    esac

    if wg_is_up; then
        if ! wg syncconf "$WG_INTERFACE" <(wg-quick strip "$WG_CONFIG") 2>/dev/null; then
            wg_restart
        fi
    fi

    green "已恢复到快照：$(basename "$dir")"
    pause
}

# 由 server 元数据 + client 元数据 + site 元数据，重新生成完整 wg0.conf
rebuild_server_config() {

    local iface="$WG_INTERFACE"
    local port network4 network6 server_ip4 server_ip6 dns private_key mtu
    local tmpfile

    port=$(get_config WG_PORT)
    server_ip4=$(get_config SERVER_IP4)
    server_ip6=$(get_config SERVER_IP6)
    dns=$(get_config DNS)
    mtu=$(get_config MTU)
    mtu="${mtu:-1420}"
    private_key=$(get_server_private_key)

    if [[ -z "$port" || -z "$server_ip4" || -z "$private_key" ]]; then
        red "服务端尚未初始化，无法生成配置。"
       return 1
   fi

    tmpfile=$(mktemp /tmp/wgmgr_XXXXXX.conf)

   {
       echo "[Interface]"
        if [[ -n "$server_ip6" ]]; then
            echo "Address = ${server_ip4}, ${server_ip6}"
        else
            echo "Address = ${server_ip4}"
        fi
        echo "ListenPort = ${port}"
        echo "PrivateKey = ${private_key}"
        echo "MTU = ${mtu}"
        echo "SaveConfig = false"

        # 路由管理里加的额外静态路由，写成 PostUp/PostDown，
        # 这样 reboot / wg-quick up 之后会自动生效，不用每次手动 ip route add。
        if [[ -f "$ROUTES_CONF" && -s "$ROUTES_CONF" ]]; then
            local rline rsubnet rvia
            while IFS='|' read -r _ rsubnet rvia _; do
                [[ -z "$rsubnet" || -z "$rvia" ]] && continue
                echo "PostUp = ip route replace ${rsubnet} via ${rvia} dev ${iface} 2>/dev/null || true"
                echo "PostDown = ip route del ${rsubnet} via ${rvia} dev ${iface} 2>/dev/null || true"
            done < "$ROUTES_CONF"
        fi
    } > "$tmpfile"

    # --- 客户端 Peer ---
    local mdir mname mip4 mip6 mpub mallowed menabled
    for mdir in "$CLIENTS_DIR"/*/; do
        [[ -f "${mdir}meta.conf" ]] || continue

        menabled=$(get_kv "${mdir}meta.conf" ENABLED)
        [[ "$menabled" != "yes" ]] && continue

        mname=$(get_kv "${mdir}meta.conf" NAME)
        mip4=$(get_kv "${mdir}meta.conf" IP4)
        mip6=$(get_kv "${mdir}meta.conf" IP6)
        mpub=$(get_kv "${mdir}meta.conf" PUBLIC_KEY)

        if [[ -z "$mpub" ]] || ! is_valid_wg_key "$mpub" || ! is_valid_ipv4 "$mip4"; then
            yellow "  跳过客户端 ${mname:-?}：公钥或 IPv4 地址格式异常，未写入配置（不影响其他客户端）。" >&2
            continue
        fi

        local allowed="${mip4}/32"
        [[ -n "$mip6" ]] && allowed="${allowed},${mip6}/128"

        {
            echo
            echo "# Client: ${mname}"
            echo "[Peer]"
            echo "PublicKey = ${mpub}"
            echo "AllowedIPs = ${allowed}"
        } >> "$tmpfile"
    done

    # --- Site-to-Site Peer ---
    local sdir sname spub sendpoint sremote_lan sremote_wg_ip skeepalive senabled smode
    for sdir in "$SITES_DIR"/*/; do
        [[ -f "${sdir}meta.conf" ]] || continue

        senabled=$(get_kv "${sdir}meta.conf" ENABLED)
        [[ "$senabled" != "yes" ]] && continue

        sname=$(get_kv "${sdir}meta.conf" NAME)
        spub=$(get_kv "${sdir}meta.conf" REMOTE_PUBLIC_KEY)
        sendpoint=$(get_kv "${sdir}meta.conf" REMOTE_ENDPOINT)
        sremote_lan=$(get_kv "${sdir}meta.conf" REMOTE_LAN)
        sremote_wg_ip=$(get_kv "${sdir}meta.conf" REMOTE_WG_IP)
        skeepalive=$(get_kv "${sdir}meta.conf" KEEPALIVE)
        skeepalive="${skeepalive:-25}"
        smode=$(get_kv "${sdir}meta.conf" MODE)   # routing / nat / conflict

        if [[ -z "$spub" ]] || ! is_valid_wg_key "$spub"; then
            yellow "  跳过站点 ${sname:-?}：对端公钥缺失或格式异常，未写入配置。" >&2
            continue
        fi

        local allowed="${sremote_wg_ip}/32"

        # conflict 模式：两端 LAN 网段冲突，只允许到对端 VPN IP 本身，
        # 不把 REMOTE_LAN 塞进 AllowedIPs，避免产生有歧义/错误的路由。
        if [[ "$smode" != "conflict" && -n "$sremote_lan" ]]; then
            allowed="${sremote_lan},${allowed}"
        fi

        {
            echo
            echo "# Site: ${sname} (mode: ${smode:-routing})"
            echo "[Peer]"
            echo "PublicKey = ${spub}"
            [[ -n "$sendpoint" ]] && echo "Endpoint = ${sendpoint}"
            echo "AllowedIPs = ${allowed}"
            echo "PersistentKeepalive = ${skeepalive}"
        } >> "$tmpfile"
    done

    # --- 语法校验：wg-quick strip 能正确解析即视为有效 ---
    if ! wg-quick strip "$tmpfile" >/dev/null 2>/tmp/wgmgr_strip_err; then
        red "生成的配置未通过校验，已放弃写入，原配置保持不变："
        cat /tmp/wgmgr_strip_err
        rm -f "$tmpfile"
        return 1
    fi

    local snapshot_dir
    snapshot_dir=$(backup_snapshot "rebuild")
    install -m 600 "$tmpfile" "$WG_CONFIG"
    rm -f "$tmpfile"

    # --- 防火墙：每次都做一次"清空本脚本规则 -> 按当前元数据全量重建"，
    #     这样禁用/删除站点时旧的 LAN 转发/NAT 规则不会遗留，不用用户
    #     自己记得去手动清理 ---
    fw_sync_state

    # --- 应用：接口已启动则热同步，同步失败就回滚到刚才的快照重试一次 ---
    if wg_is_up; then
        if wg syncconf "$iface" <(wg-quick strip "$WG_CONFIG") 2>/tmp/wgmgr_sync_err; then
            green "配置已生成并热同步（无需断开现有连接）。"
        else
            yellow "热同步失败，正在回滚到改动前的配置重试："
            cat /tmp/wgmgr_sync_err
            if [[ -n "$snapshot_dir" && -f "${snapshot_dir}/$(basename "$WG_CONFIG")" ]]; then
                install -m 600 "${snapshot_dir}/$(basename "$WG_CONFIG")" "$WG_CONFIG"
                fw_sync_state
                if wg syncconf "$iface" <(wg-quick strip "$WG_CONFIG") 2>/dev/null; then
                    yellow "已回滚成功，本次改动未生效，请检查输入后重试。"
                else
                    red "回滚后仍同步失败，请手动检查：systemctl status wg-quick@${iface}"
                fi
            fi
            return 1
        fi
    fi

    return 0
}

# ============================================================
# 服务端初始化
# ============================================================

server_setup() {

    clear
    bold "=========================================="
    bold "       WireGuard 服务端初始化"
    bold "=========================================="

    generate_server_keys

    local default_iface default_iface6 public_ip public_ip6
    default_iface=$(get_default_interface)
    default_iface6=$(get_default_interface6)
    public_ip=$(get_public_ipv4)

    echo
    cyan "检测到默认网卡（IPv4）：${default_iface:-未知}"
    [[ -n "$default_iface6" ]] && cyan "检测到默认网卡（IPv6）：${default_iface6}"
    cyan "检测到公网 IPv4：${public_ip:-未检测到}"
    echo

    local input listen_port vpn_network4 server_ip4 dns endpoint use_ipv6 vpn_network6 server_ip6 nat66

    read -rp "WireGuard 接口 [wg0]: " input
    WG_INTERFACE="${input:-wg0}"
    WG_CONFIG="${WG_DIR}/${WG_INTERFACE}.conf"

    read -rp "WireGuard 端口 [51820]: " listen_port
    listen_port="${listen_port:-51820}"

    read -rp "VPN IPv4 网段 [10.66.66.0/24]: " vpn_network4
    vpn_network4="${vpn_network4:-10.66.66.0/24}"

    read -rp "服务器 VPN IPv4 地址 [10.66.66.1/24]: " server_ip4
    server_ip4="${server_ip4:-10.66.66.1/24}"

    read -rp "DNS [1.1.1.1]: " dns
    dns="${dns:-1.1.1.1}"

    local mtu
    read -rp "MTU [1420]: " mtu
    mtu="${mtu:-1420}"
    if ! [[ "$mtu" =~ ^[0-9]+$ ]] || (( mtu < 1280 || mtu > 9000 )); then
        yellow "MTU 不合法，已使用默认值 1420（Docker/PVE 虚拟网卡、有额外隧道封装的场景，"
        yellow "出现丢包/连不上时可以回来这里调低，比如改成 1380）。"
        mtu=1420
    fi

    read -rp "服务器 Endpoint [${public_ip:-自动检测}]: " endpoint
    endpoint="${endpoint:-$public_ip}"
    [[ -z "$endpoint" ]] && read -rp "请输入服务器公网 IP 或域名: " endpoint

    local internet_nat
    if confirm "是否允许客户端通过这台机器访问公网（Internet NAT）？" "Y"; then
        internet_nat="yes"
    else
        internet_nat="no"
        yellow "已选择不做 Internet NAT：客户端只能访问 VPN 网段和你后面配的"
        yellow "Site-to-Site LAN，访问不了外网，适合「只做内网穿透，不当出口」的场景。"
    fi

    if confirm "是否启用 IPv6？" "N"; then
        use_ipv6="yes"
        read -rp "VPN IPv6 网段 [fd66:66:66::/64]: " vpn_network6
        vpn_network6="${vpn_network6:-fd66:66:66::/64}"

        read -rp "服务器 VPN IPv6 地址 [fd66:66:66::1/64]: " server_ip6
        server_ip6="${server_ip6:-fd66:66:66::1/64}"

        if confirm "对 IPv6 也做 NAT（NAT66，没有公网 IPv6 路由时选是）？" "N"; then
            nat66="yes"
        else
            nat66="no"
        fi

        yellow
        yellow "⚠️  重要提示：开启 IPv6 会打开这台机器的全局 IPv6 转发开关"
        yellow "    （net.ipv6.conf.all.forwarding=1）。这个开关是系统级的，不区分"
        yellow "    接口——如果这台机器自己的 ip6tables/nftables 对 FORWARD 链没有"
        yellow "    设置默认拒绝策略（很多全新 VPS / 云厂商镜像默认就是全部放行），"
        yellow "    开了这个开关之后，这台机器可能变成一个谁都能借用的公网 IPv6"
        yellow "    路由器，被用来绕过限制或者盗刷流量。"
        yellow "    本脚本自己新建的防火墙规则只负责\"放行\"该放行的流量，不会去改"
        yellow "    你机器上其他转发路径的默认策略（改了可能连累 Docker/PVE 自己的"
        yellow "    容器转发）。如果你确认这台机器目前没有为 IPv6 配置任何转发限制，"
        yellow "    强烈建议去 \"高级设置 -> IPv6 转发加固\" 里看一下，或者自己确认"
        yellow "    一下 ip6tables/nft 的 FORWARD 默认策略。"
        echo
    else
        use_ipv6="no"
        vpn_network6=""
        server_ip6=""
        nat66="no"
    fi

    set_config "WG_INTERFACE" "$WG_INTERFACE"
    set_config "WG_PORT" "$listen_port"
    set_config "VPN_NETWORK4" "$vpn_network4"
    set_config "SERVER_IP4" "$server_ip4"
    set_config "DNS" "$dns"
    set_config "MTU" "$mtu"
    set_config "ENDPOINT" "$endpoint"
    set_config "WAN_INTERFACE" "$default_iface"
    set_config "USE_IPV6" "$use_ipv6"
    set_config "VPN_NETWORK6" "$vpn_network6"
    set_config "SERVER_IP6" "$server_ip6"
    set_config "NAT66" "$nat66"
    set_config "INTERNET_NAT" "$internet_nat"

    if [[ -f "$WG_CONFIG" ]]; then
        yellow
        yellow "检测到已有配置：$WG_CONFIG"
        if ! confirm "是否覆盖现有 WireGuard 配置？" "N"; then
            yellow "取消覆盖。"
            pause
            return
        fi
    fi

    configure_ip_forward "$use_ipv6"

    generate_server_keys
    rebuild_server_config || { pause; return; }   # 会在内部调用 fw_sync_state 统一处理防火墙

    systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
    log_action "SERVER_SETUP port=${listen_port} vpn4=${vpn_network4} nat=${internet_nat}"

    green
    green "=========================================="
    green "WireGuard 服务端初始化完成"
    green "=========================================="
    echo
    echo "接口       : $WG_INTERFACE"
    echo "端口       : UDP $listen_port"
    echo "VPN IPv4   : $vpn_network4"
    echo "服务器 IPv4: $server_ip4"
    [[ "$use_ipv6" == "yes" ]] && echo "VPN IPv6   : $vpn_network6" && echo "服务器 IPv6: $server_ip6"
    echo "公网地址   : $endpoint"
    echo "公网网卡   : $default_iface"
    echo
    echo "服务器公钥："
    cyan "$(get_server_public_key)"
    echo

    if confirm "现在启动 WireGuard？" "Y"; then
        wg_up
    fi

    pause
}

# ============================================================
# 启停 / 状态
# ============================================================

wg_up() {
    if [[ ! -f "$WG_CONFIG" ]]; then
        yellow "WireGuard 配置不存在。"
        return
    fi

    systemctl enable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true
    systemctl restart "wg-quick@${WG_INTERFACE}"
    sleep 1

    if wg_is_up; then
        green "WireGuard ${WG_INTERFACE} 已启动。"
        log_action "WG_UP"
    else
        red "WireGuard 启动失败。"
        systemctl status "wg-quick@${WG_INTERFACE}" --no-pager
    fi
}

wg_down() {
    systemctl stop "wg-quick@${WG_INTERFACE}" 2>/dev/null || true
    green "WireGuard 已停止。"
    log_action "WG_DOWN"
}

wg_restart() {
    systemctl restart "wg-quick@${WG_INTERFACE}"
    sleep 1
    if wg_is_up; then
        green "WireGuard 已重启。"
    else
        red "WireGuard 重启失败。"
        systemctl status "wg-quick@${WG_INTERFACE}" --no-pager
    fi
}

show_server_info() {

    clear
    bold "=========================================="
    bold "       WireGuard 服务端信息"
    bold "=========================================="

    if [[ ! -f "$WG_CONFIG" ]]; then
        yellow "尚未初始化 WireGuard 服务端。"
        pause
        return
    fi

    echo
    echo "接口       : ${WG_INTERFACE}"
    echo "端口       : $(get_config WG_PORT)"
    echo "VPN IPv4   : $(get_config VPN_NETWORK4)"
    echo "服务器 IPv4: $(get_config SERVER_IP4)"
    [[ "$(get_config USE_IPV6)" == "yes" ]] && {
        echo "VPN IPv6   : $(get_config VPN_NETWORK6)"
        echo "服务器 IPv6: $(get_config SERVER_IP6)"
    }
    echo "公网地址   : $(get_config ENDPOINT)"
    echo "公网网卡   : $(get_config WAN_INTERFACE)"
    echo "MTU        : $(get_config MTU)"
    echo "Internet NAT: $( [[ "$(get_config INTERNET_NAT)" == "no" ]] && echo "关闭（客户端上不了外网，只能访问 VPN/Site LAN）" || echo "开启" )"
    echo
    echo "服务器公钥（可直接复制给对端 Site-to-Site 使用）："
    cyan "$(get_server_public_key)"
    echo

    if confirm "是否显示服务器私钥？" "N"; then
        red "警告：以下内容属于敏感私钥，注意不要粘贴到公共渠道："
        echo
        red "$(get_server_private_key)"
    fi

    echo
    pause
}

# ============================================================
# 客户端管理
# ============================================================

client_dir_for() { echo "${CLIENTS_DIR}/$1"; }

# 生成客户端密钥对 + 写 meta.conf + 渲染可直接导入的 <name>.conf。
# 交互式 add_client 和非交互式 `wgmgr client add` 都走这里，
# 这样两条路径产出的 .conf 不可能随时间漂移。
# 结果通过全局变量传出：CLIENT_PRIV / CLIENT_PUB / CLIENT_CONF_PATH
CLIENT_PRIV=""
CLIENT_PUB=""
CLIENT_CONF_PATH=""

client_provision() {
    local name="$1" ip4="$2" ip6="${3-}" allowed="${4-0.0.0.0/0}"

    local cdir cconf
    cdir=$(client_dir_for "$name")
    cconf="${cdir}/${name}.conf"

    local server_public endpoint port dns mtu keepalive
    server_public=$(get_server_public_key)
    endpoint=$(get_config ENDPOINT)
    port=$(get_config WG_PORT)
    dns=$(get_config DNS)
    mtu=$(get_config MTU);          mtu="${mtu:-1420}"
    keepalive=$(get_config DEFAULT_KEEPALIVE); keepalive="${keepalive:-25}"

    if [[ -z "$server_public" || -z "$endpoint" || -z "$port" ]]; then
        red "服务端信息不完整（公钥/Endpoint/端口），请先初始化服务端。"
        return 1
    fi

    mkdir -p "$cdir"
    chmod 700 "$cdir"

    local private_key public_key
    private_key=$(umask 077; wg genkey) || { red "wg genkey 失败。"; return 1; }
    public_key=$(echo "$private_key" | wg pubkey) || { red "wg pubkey 失败。"; return 1; }

    echo "$private_key" > "${cdir}/private.key"
    echo "$public_key"  > "${cdir}/public.key"
    chmod 600 "${cdir}/private.key" "${cdir}/public.key"

    set_kv "${cdir}/meta.conf" "NAME"        "$name"
    set_kv "${cdir}/meta.conf" "IP4"         "$ip4"
    set_kv "${cdir}/meta.conf" "IP6"         "$ip6"
    set_kv "${cdir}/meta.conf" "PUBLIC_KEY"  "$public_key"
    set_kv "${cdir}/meta.conf" "ALLOWED_IPS" "$allowed"
    set_kv "${cdir}/meta.conf" "ENABLED"     "yes"
    set_kv "${cdir}/meta.conf" "CREATED"     "$(date '+%Y-%m-%d %H:%M:%S')"
    chmod 600 "${cdir}/meta.conf"

    {
        echo "[Interface]"
        if [[ -n "$ip6" ]]; then
            echo "Address = ${ip4}/32, ${ip6}/128"
        else
            echo "Address = ${ip4}/32"
        fi
        echo "PrivateKey = ${private_key}"
        echo "DNS = ${dns}"
        echo "MTU = ${mtu}"
        echo
        echo "[Peer]"
        echo "PublicKey = ${server_public}"
        echo "Endpoint = ${endpoint}:${port}"
        echo "AllowedIPs = ${allowed}"
        echo "PersistentKeepalive = ${keepalive}"
    } > "$cconf"
    chmod 600 "$cconf"

    CLIENT_PRIV="$private_key"
    CLIENT_PUB="$public_key"
    CLIENT_CONF_PATH="$cconf"
    return 0
}

add_client() {

    clear
    bold "=========================================="
    bold "           添加 WireGuard 客户端"
    bold "=========================================="

    if [[ ! -f "$WG_CONFIG" ]]; then
        yellow "服务端尚未初始化，无法添加客户端。"
        echo
        echo "请先在主菜单选择「2. 服务端」->「1. 初始化 / 重新配置服务端」"
        echo "完成服务端初始化后再回来添加客户端。"
        pause
        return
    fi

    local name client_ip4 client_ip6 private_key public_key
    local server_public endpoint port dns allowed_ips cdir cconf use_ipv6

    print_existing_clients
    echo
    read -rp "客户端名称，例如 iphone/home-pc: " name
    [[ -z "$name" ]] && { red "客户端名称不能为空。"; pause; return; }
    [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] || { red "名称只能包含字母、数字、下划线、短横线。"; pause; return; }

    cdir=$(client_dir_for "$name")
    if [[ -d "$cdir" ]]; then
        red "客户端已经存在。"
        pause
        return
    fi

    client_ip4=$(get_next_client_ip4) || { red "没有可用的 IPv4 地址。"; pause; return; }
    read -rp "客户端 VPN IPv4 [$client_ip4]: " input
    client_ip4="${input:-$client_ip4}"

    use_ipv6=$(get_config USE_IPV6)
    client_ip6=""
    if [[ "$use_ipv6" == "yes" ]]; then
        client_ip6=$(get_next_client_ip6) || true
        if [[ -n "$client_ip6" ]]; then
            read -rp "客户端 VPN IPv6 [$client_ip6]: " input
            client_ip6="${input:-$client_ip6}"
        fi
    fi

    local vpn_net4 vpn_net6 allow_choice
    vpn_net4=$(get_config VPN_NETWORK4)
    vpn_net6=$(get_config VPN_NETWORK6)

    echo
    echo "客户端流量模式："
    echo "  1. 全局代理    —— AllowedIPs = 0.0.0.0/0，这台设备所有流量都走这条隧道"
    echo "  2. 仅访问 VPN  —— AllowedIPs = ${vpn_net4}，只能访问服务端和其他 VPN 成员"
    echo "  3. VPN + 自定义 LAN —— 再加一段你指定的网段（比如某个 Site 的 LAN）"
    echo "  4. 自定义       —— 完全自己输入 AllowedIPs"
    read -rp "选择 [1]: " allow_choice
    allow_choice="${allow_choice:-1}"

    case "$allow_choice" in
        2)
            allowed_ips="$vpn_net4"
            ;;
        3)
            local extra_lan
            read -rp "要额外放行的网段（如 192.168.10.0/24）: " extra_lan
            if [[ -n "$extra_lan" ]]; then
                allowed_ips="${vpn_net4}, ${extra_lan}"
            else
                allowed_ips="$vpn_net4"
            fi
            ;;
        4)
            read -rp "AllowedIPs（逗号分隔）: " allowed_ips
            [[ -z "$allowed_ips" ]] && allowed_ips="0.0.0.0/0"
            ;;
        *)
            allowed_ips="0.0.0.0/0"
            ;;
    esac

    if [[ -n "$client_ip6" ]] && [[ "$allow_choice" == "1" ]]; then
        if confirm "同时把 IPv6 全部流量 (::/0) 也走隧道？" "Y"; then
            allowed_ips="${allowed_ips}, ::/0"
        fi
    fi

    dns=$(get_config DNS)
    endpoint=$(get_config ENDPOINT)
    port=$(get_config WG_PORT)

    if ! client_provision "$name" "$client_ip4" "$client_ip6" "$allowed_ips"; then
        red "客户端创建失败。"
        pause
        return
    fi

    if ! rebuild_server_config; then
        red "服务端配置生成失败，客户端元数据已保留，请检查后重试或删除该客户端。"
        pause
        return
    fi

    log_action "CLIENT_ADD ${name} ip4=${client_ip4}"

    green
    green "=========================================="
    green "客户端创建成功"
    green "=========================================="
    echo
    echo "名称       : $name"
    echo "VPN IPv4   : $client_ip4"
    [[ -n "$client_ip6" ]] && echo "VPN IPv6   : $client_ip6"
    echo "公钥       : $CLIENT_PUB"
    echo "配置文件   : $CLIENT_CONF_PATH"
    echo
    echo "客户端配置："
    echo "------------------------------------------"
    cat "$CLIENT_CONF_PATH"
    echo "------------------------------------------"

    pause
}

list_clients() {

    clear
    bold "=========================================="
    bold "              客户端列表"
    bold "=========================================="

    if ! compgen -G "${CLIENTS_DIR}/*/meta.conf" >/dev/null; then
        yellow "暂无客户端。"
        pause
        return
    fi

    local handshakes transfers
    handshakes=$(wg show "$WG_INTERFACE" latest-handshakes 2>/dev/null)
    transfers=$(wg show "$WG_INTERFACE" transfer 2>/dev/null)

    printf "%-16s %-16s %-6s %-14s %-10s %-10s\n" "名称" "VPN IPv4" "状态" "最后握手" "接收" "发送"
    printf "%-16s %-16s %-6s %-14s %-10s %-10s\n" "----------------" "----------------" "------" "--------------" "----------" "----------"

    local mdir name ip4 pubkey enabled hs_epoch hs_str rx tx now

    now=$(date +%s)

    for mdir in "$CLIENTS_DIR"/*/; do
        [[ -f "${mdir}meta.conf" ]] || continue

        name=$(get_kv "${mdir}meta.conf" NAME)
        ip4=$(get_kv "${mdir}meta.conf" IP4)
        pubkey=$(get_kv "${mdir}meta.conf" PUBLIC_KEY)
        enabled=$(get_kv "${mdir}meta.conf" ENABLED)

        hs_epoch=$(echo "$handshakes" | awk -v k="$pubkey" '$1==k {print $2}')
        rx=$(echo "$transfers" | awk -v k="$pubkey" '$1==k {print $2}')
        tx=$(echo "$transfers" | awk -v k="$pubkey" '$1==k {print $3}')

        if [[ -z "$hs_epoch" || "$hs_epoch" == "0" ]]; then
            hs_str="从未连接"
        else
            hs_str="$(( (now - hs_epoch) / 60 )) 分钟前"
        fi

        rx=${rx:-0}; tx=${tx:-0}

        printf "%-16s %-16s %-6s %-14s %-10s %-10s\n" \
            "$name" "$ip4" \
            "$( [[ "$enabled" == "yes" ]] && echo 启用 || echo 禁用 )" \
            "$hs_str" \
            "$(numfmt --to=iec "$rx" 2>/dev/null || echo "${rx}B")" \
            "$(numfmt --to=iec "$tx" 2>/dev/null || echo "${tx}B")"
    done

    echo
    pause
}

show_client_config() {

    clear
    bold "=========================================="
    bold "       查看客户端配置"
    bold "=========================================="
    echo
    prompt_client_name "请输入客户端名称: " || { pause; return; }
    local cdir cconf
    cdir=$(client_dir_for "$name")
    cconf="${cdir}/${name}.conf"

    if [[ ! -f "$cconf" ]]; then
        red "客户端不存在。"
        pause
        return
    fi

    echo
    bold "客户端配置："
    echo "------------------------------------------"
    cat "$cconf"
    echo "------------------------------------------"
    echo

    if confirm "是否显示二维码？" "Y"; then
        if command_exists qrencode; then
            echo
            qrencode -t ANSIUTF8 < "$cconf"
        else
            yellow "未安装 qrencode。"
        fi
    fi

    pause
}

toggle_client() {
    local target_state="$1" # yes / no
    clear

    if [[ "$target_state" == "yes" ]]; then
       bold "启用客户端"
    else
       bold "禁用客户端"
    fi

    echo
    prompt_client_name "请输入客户端名称: " || { pause; return; }
    local cdir="${CLIENTS_DIR}/${name}"

    if [[ ! -f "${cdir}/meta.conf" ]]; then
        red "客户端不存在。"
        pause
        return
    fi

    set_kv "${cdir}/meta.conf" "ENABLED" "$target_state"

    if rebuild_server_config; then
        green "客户端 ${name} 已$( [[ "$target_state" == "yes" ]] && echo 启用 || echo 禁用 )。"
        log_action "CLIENT_TOGGLE ${name} -> ${target_state}"
    fi

    pause
}

delete_client() {

    clear
    bold "=========================================="
    bold "          删除客户端"
    bold "=========================================="
    echo
    prompt_client_name "请输入要删除的客户端名称: " || { pause; return; }
    local cdir="${CLIENTS_DIR}/${name}"

    if [[ ! -f "${cdir}/meta.conf" ]]; then
        red "客户端不存在。"
        pause
        return
    fi

    yellow "即将删除客户端：$name（含私钥、配置文件）"
    read -rp "确认删除？输入 DELETE: " confirm_text

    if [[ "$confirm_text" != "DELETE" ]]; then
        yellow "已取消。"
        pause
        return
    fi

    rm -rf "$cdir"

    if rebuild_server_config; then
        green "客户端已删除。"
        log_action "CLIENT_DELETE ${name}"
    fi

    pause
}

# ============================================================
# Peer / 连接状态（基于 `wg show <iface> dump`）
# ============================================================

# 输出格式（每行一个字段，tab 分隔）：
#   public-key  preshared-key  endpoint  allowed-ips  latest-handshake  transfer-rx  transfer-tx  persistent-keepalive
wg_dump_peer_line() {
    local pubkey="$1"
    wg show "$WG_INTERFACE" dump 2>/dev/null | awk -F'\t' -v k="$pubkey" '$1==k {print; exit}'
}

human_bytes() {
    numfmt --to=iec "$1" 2>/dev/null || echo "${1}B"
}

human_ago() {
    local epoch="$1" now
    if [[ -z "$epoch" || "$epoch" == "0" ]]; then
        echo "从未连接"
        return
    fi
    now=$(date +%s)
    local diff=$(( now - epoch ))
    if   (( diff < 60 ));    then echo "${diff} 秒前"
    elif (( diff < 3600 ));  then echo "$(( diff / 60 )) 分钟前"
    elif (( diff < 86400 )); then echo "$(( diff / 3600 )) 小时前"
    else echo "$(( diff / 86400 )) 天前"
    fi
}

peer_status_menu() {

    clear
    bold "=========================================="
    bold "          Peer / 连接状态"
    bold "=========================================="
    echo

    printf "%-16s %-10s %-6s %-12s\n" "名称" "类型" "状态" "最后握手"
    printf "%-16s %-10s %-6s %-12s\n" "----------------" "----------" "------" "------------"

    local mdir name pubkey line hs online
    for mdir in "$CLIENTS_DIR"/*/; do
        [[ -f "${mdir}meta.conf" ]] || continue
        name=$(get_kv "${mdir}meta.conf" NAME)
        pubkey=$(get_kv "${mdir}meta.conf" PUBLIC_KEY)
        line=$(wg_dump_peer_line "$pubkey")
        hs=$(awk -F'\t' '{print $5}' <<< "$line")
        online="离线"
        [[ -n "$hs" && "$hs" != "0" ]] && (( $(date +%s) - hs < 180 )) && online="在线"
        printf "%-16s %-10s %-6s %-12s\n" "$name" "客户端" "$online" "$(human_ago "$hs")"
    done

    local sdir sname spub sline shs sonline
    for sdir in "$SITES_DIR"/*/; do
        [[ -f "${sdir}meta.conf" ]] || continue
        sname=$(get_kv "${sdir}meta.conf" NAME)
        spub=$(get_kv "${sdir}meta.conf" REMOTE_PUBLIC_KEY)
        sline=$(wg_dump_peer_line "$spub")
        shs=$(awk -F'\t' '{print $5}' <<< "$sline")
        sonline="离线"
        [[ -n "$shs" && "$shs" != "0" ]] && (( $(date +%s) - shs < 180 )) && sonline="在线"
        printf "%-16s %-10s %-6s %-12s\n" "$sname" "Site" "$sonline" "$(human_ago "$shs")"
    done

    echo
    read -rp "输入名称查看详情（Enter 返回）: " name
    if [[ -z "$name" ]]; then
        green "已返回。"
        sleep 1
        return
    fi

    show_peer_detail "$name"
    echo
    pause
}

show_peer_detail() {

    local name="$1"
    local pubkey ip4 keepalive allowed_default source="客户端"

    if [[ -f "${CLIENTS_DIR}/${name}/meta.conf" ]]; then
        pubkey=$(get_kv "${CLIENTS_DIR}/${name}/meta.conf" PUBLIC_KEY)
        ip4=$(get_kv "${CLIENTS_DIR}/${name}/meta.conf" IP4)
    elif [[ -f "${SITES_DIR}/${name}/meta.conf" ]]; then
        pubkey=$(get_kv "${SITES_DIR}/${name}/meta.conf" REMOTE_PUBLIC_KEY)
        ip4=$(get_kv "${SITES_DIR}/${name}/meta.conf" REMOTE_WG_IP)
        source="Site-to-Site"
    else
        red "找不到名为 ${name} 的客户端或站点。"
        pause
        return
    fi

    local line endpoint allowed hs rx tx keep
    line=$(wg_dump_peer_line "$pubkey")

    if [[ -z "$line" ]]; then
        yellow "该 Peer 当前不在运行中的 wg0 配置里（可能被禁用，或 WireGuard 未启动）。"
        pause
        return
    fi

    IFS=$'\t' read -r _ _ endpoint allowed hs rx tx keep <<< "$line"

    clear
    bold "=========================================="
    bold "  Peer: ${name}  (${source})"
    bold "=========================================="
    echo
    echo "VPN IP:"
    cyan "  ${ip4}"
    echo
    echo "Endpoint:"
    cyan "  ${endpoint:-（尚未连接）}"
    echo
    echo "Latest Handshake:"
    cyan "  $(human_ago "$hs")"
    echo
    echo "Received:"
    cyan "  $(human_bytes "${rx:-0}")"
    echo
    echo "Sent:"
    cyan "  $(human_bytes "${tx:-0}")"
    echo
    echo "Keepalive:"
    cyan "  ${keep:-off}"
    echo
    echo "AllowedIPs:"
    cyan "  ${allowed}"
    echo

    pause
}

# ============================================================
# 路由管理
# ============================================================

list_routes() {

    clear
    bold "=========================================="
    bold "              路由管理"
    bold "=========================================="
    echo

    echo "手动添加的静态路由（写入 wg0.conf 的 PostUp/PostDown，重启/reboot 后仍生效）："
    echo

    if [[ ! -s "$ROUTES_CONF" ]]; then
        yellow "  （无）"
    else
        printf "%-16s %-20s %-16s %-20s\n" "名称" "目标网段" "下一跳" "备注"
        local rname rsubnet rvia rcomment
        while IFS='|' read -r rname rsubnet rvia rcomment; do
            [[ -z "$rname" ]] && continue
            printf "%-16s %-20s %-16s %-20s\n" "$rname" "$rsubnet" "$rvia" "$rcomment"
        done < "$ROUTES_CONF"
    fi

    echo
    echo "当前内核里 ${WG_INTERFACE} 相关的路由："
    ip route show dev "$WG_INTERFACE" 2>/dev/null || yellow "  （接口未运行）"

    echo
    pause
}

add_route() {

    clear
    bold "添加静态路由"
    echo
    echo "典型用途：某个 Site-to-Site 站点后面还有下一级网段，需要多跳到达。"
    echo "例如分部 LAN 是 192.168.20.0/24，但仓库子网 192.168.30.0/24 要经"
    echo "分部路由器（对端 VPN IP）转一手才能到，这里就补一条路由。"
    echo

    local rname rsubnet rvia rcomment

    if [[ -s "$ROUTES_CONF" ]]; then
        echo "已有路由："
        printf "%-16s %-20s %-16s %-20s\n" "名称" "目标网段" "下一跳" "备注"
        while IFS='|' read -r rname rsubnet rvia rcomment; do
            [[ -z "$rname" ]] && continue
            printf "%-16s %-20s %-16s %-20s\n" "$rname" "$rsubnet" "$rvia" "$rcomment"
        done < "$ROUTES_CONF"
        echo
    fi
    rname=""; rsubnet=""; rvia=""; rcomment=""

    read -rp "路由名称（便于识别，如 warehouse-net）: " rname
    [[ -z "$rname" ]] && { red "名称不能为空。"; pause; return; }

    if grep -q "^${rname}|" "$ROUTES_CONF" 2>/dev/null; then
        red "同名路由已存在。"
        pause
        return
    fi

    read -rp "目标网段（如 192.168.30.0/24）: " rsubnet
    read -rp "下一跳 IP（通常是某个 Site 的对端 VPN IP，如 10.66.66.253）: " rvia
    read -rp "备注（可选）: " rcomment

    if [[ -z "$rsubnet" || -z "$rvia" ]]; then
        red "目标网段和下一跳为必填项。"
        pause
        return
    fi

    if ! is_valid_ipv4 "$rsubnet" || ! is_valid_ipv4 "$rvia"; then
        red "网段或下一跳 IP 格式不正确。"
        pause
        return
    fi

    backup_snapshot "before_add_route_${rname}" >/dev/null

    echo "${rname}|${rsubnet}|${rvia}|${rcomment}" >> "$ROUTES_CONF"
    chmod 600 "$ROUTES_CONF"

    if ! rebuild_server_config; then
        red "配置生成失败，路由未生效，请检查后重试（已从 routes.conf 保留，可在路由管理中删除）。"
        pause
        return
    fi

    # 立即生效一次，不用等下次 wg-quick up
    ip route replace "$rsubnet" via "$rvia" dev "$WG_INTERFACE" 2>/dev/null || true

    green "路由已添加并生效：${rsubnet} via ${rvia}"
    pause
}

delete_route() {

    clear

    bold "=========================================="
    bold "       删除静态路由"
    bold "=========================================="
    echo
    if [[ ! -s "$ROUTES_CONF" ]]; then
        yellow "暂无路由。"
        pause
        return
    fi
    printf "%-16s %-20s %-16s %-20s\n" "名称" "目标网段" "下一跳" "备注"
    local rname rsubnet rvia rcomment
    while IFS='|' read -r rname rsubnet rvia rcomment; do
        [[ -z "$rname" ]] && continue
        printf "%-16s %-20s %-16s %-20s\n" "$rname" "$rsubnet" "$rvia" "$rcomment"
    done < "$ROUTES_CONF"
    echo
    read -rp "要删除的路由名称: " rname

    if ! grep -q "^${rname}|" "$ROUTES_CONF" 2>/dev/null; then
        red "路由不存在。"
        pause
        return
    fi

    local rsubnet rvia
    rsubnet=$(grep "^${rname}|" "$ROUTES_CONF" | cut -d'|' -f2)
    rvia=$(grep "^${rname}|" "$ROUTES_CONF" | cut -d'|' -f3)

    backup_snapshot "before_del_route_${rname}" >/dev/null

    sed -i "/^${rname}|/d" "$ROUTES_CONF"

    if rebuild_server_config; then
        ip route del "$rsubnet" via "$rvia" dev "$WG_INTERFACE" 2>/dev/null || true
        green "路由已删除。"
    fi

    pause
}

routing_menu() {
    while true; do
        clear
        bold "=========================================="
        bold "              路由管理"
        bold "=========================================="
        echo
        echo "  1. 查看路由"
        echo "  2. 添加静态路由"
        echo "  3. 删除静态路由"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) list_routes ;;
            2) add_route ;;
            3) delete_route ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 密钥管理
# ============================================================

key_management_menu() {
    while true; do
        clear
        bold "=========================================="
        bold "              密钥管理"
        bold "=========================================="
        echo
        echo "  1. 查看服务器公钥 / 私钥"
        echo "  2. 轮换服务器密钥（会导致所有客户端需要重新导入配置！）"
        echo "  3. 轮换某个客户端的密钥"
        echo "  4. 导出所有客户端公钥列表"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) show_server_info ;;
            2) rotate_server_key ;;
            3) rotate_client_key ;;
            4) export_client_pubkeys ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

rotate_server_key() {

    clear
    bold "轮换服务器密钥"
    echo
    red "警告：服务器公钥变化后，所有已下发的客户端配置文件里的 Peer PublicKey"
    red "都会失效，必须重新分发配置（本脚本会自动更新它保存的客户端 .conf 文件，"
    red "但你已经导入到手机/电脑上的配置需要手动重新导入）。"
    echo

    read -rp "确认轮换？输入 ROTATE: " confirm_text
    [[ "$confirm_text" != "ROTATE" ]] && { yellow "已取消。"; pause; return; }

    backup_snapshot "before_rotate_server_key" >/dev/null

    local new_priv new_pub
    umask 077
    new_priv=$(wg genkey)
    new_pub=$(echo "$new_priv" | wg pubkey)

    echo "$new_priv" > "$SERVER_PRIVATE_KEY"
    echo "$new_pub" > "$SERVER_PUBLIC_KEY"
    chmod 600 "$SERVER_PRIVATE_KEY" "$SERVER_PUBLIC_KEY"

    # 同步更新每个客户端保存下来的 .conf 文件里的服务端公钥
    local mdir name cconf
    for mdir in "$CLIENTS_DIR"/*/; do
        [[ -f "${mdir}meta.conf" ]] || continue
        name=$(get_kv "${mdir}meta.conf" NAME)
        cconf="${mdir}${name}.conf"
        [[ -f "$cconf" ]] && sed -i "s#^PublicKey = .*#PublicKey = ${new_pub}#" "$cconf"
    done

    log_action "ROTATE_SERVER_KEY"
    if rebuild_server_config; then
        green "服务器密钥已轮换，新公钥："
        cyan "$new_pub"
        yellow "请尽快把更新后的客户端配置重新发给各设备。"
    fi

    pause
}

rotate_client_key() {

    clear
    bold "=========================================="
    bold "       轮换客户端密钥"
    bold "=========================================="
    echo
    prompt_client_name "请输入客户端名称: " || { pause; return; }
    local cdir="${CLIENTS_DIR}/${name}"

    [[ -f "${cdir}/meta.conf" ]] || { red "客户端不存在。"; pause; return; }

    read -rp "确认轮换该客户端密钥？输入 ROTATE: " confirm_text
    [[ "$confirm_text" != "ROTATE" ]] && { yellow "已取消。"; pause; return; }

    backup_snapshot "before_rotate_client_${name}" >/dev/null

    local new_priv new_pub
    umask 077
    new_priv=$(wg genkey)
    new_pub=$(echo "$new_priv" | wg pubkey)

    echo "$new_priv" > "${cdir}/private.key"
    echo "$new_pub" > "${cdir}/public.key"
    chmod 600 "${cdir}/private.key" "${cdir}/public.key"

    set_kv "${cdir}/meta.conf" "PUBLIC_KEY" "$new_pub"

    local cconf="${cdir}/${name}.conf"
    if [[ -f "$cconf" ]]; then
        sed -i "s#^PrivateKey = .*#PrivateKey = ${new_priv}#" "$cconf"
    fi

    log_action "ROTATE_CLIENT_KEY ${name}"
    if rebuild_server_config; then
        green "客户端 ${name} 密钥已轮换，请重新分发以下配置文件："
        echo "------------------------------------------"
        cat "$cconf"
        echo "------------------------------------------"
    fi

    pause
}

export_client_pubkeys() {

    clear
    bold "客户端公钥列表"
    echo

    local mdir name pubkey
    for mdir in "$CLIENTS_DIR"/*/; do
        [[ -f "${mdir}meta.conf" ]] || continue
        name=$(get_kv "${mdir}meta.conf" NAME)
        pubkey=$(get_kv "${mdir}meta.conf" PUBLIC_KEY)
        printf "%-16s %s\n" "$name" "$pubkey"
    done

    echo
    pause
}

# ============================================================
# 高级设置
# ============================================================

advanced_menu() {
    while true; do
        clear
        bold "=========================================="
        bold "              高级设置"
        bold "=========================================="
        echo
        echo "  1. 修改默认 DNS（仅影响之后新建的客户端）"
        echo "  2. 修改默认 PersistentKeepalive（仅影响之后新建的客户端）"
        echo "  3. 修改 Internet NAT 开关（客户端能否通过本机访问公网）"
        echo "  4. IPv6 转发加固（仅在启用了 IPv6 时有意义，默认关闭）"
        echo "  5. 查看操作日志（最近 50 条）"
        echo "  6. 卸载 WireGuard Manager（清理防火墙规则 + 停止服务，"
        echo "     可选择是否连同配置数据一起删除）"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1)
                read -rp "新的默认 DNS [$(get_config DNS)]: " v
                [[ -n "$v" ]] && set_config "DNS" "$v" && green "已更新（不影响已生成的客户端配置）。"
                pause
                ;;
            2)
                read -rp "新的默认 PersistentKeepalive 秒数 [25]: " v
                v="${v:-25}"
                set_config "DEFAULT_KEEPALIVE" "$v"
                green "已更新。"
                pause
                ;;
            3)
                clear
                echo "当前：$( [[ "$(get_config INTERNET_NAT)" == "no" ]] && echo "关闭" || echo "开启" )"
                if confirm "切换 Internet NAT 开关？" "N"; then
                    if [[ "$(get_config INTERNET_NAT)" == "no" ]]; then
                        set_config "INTERNET_NAT" "yes"
                    else
                        set_config "INTERNET_NAT" "no"
                    fi
                    if rebuild_server_config; then
                        green "已切换为：$( [[ "$(get_config INTERNET_NAT)" == "no" ]] && echo "关闭" || echo "开启" )（已通过防火墙同步生效，无需重启接口）。"
                    fi
                fi
                pause
                ;;
            4)
                clear
                bold "IPv6 转发加固"
                echo
                if [[ "$(get_config USE_IPV6)" != "yes" ]]; then
                    yellow "当前没有启用 IPv6，这个开关不会有任何效果。"
                else
                    echo "当前：$( [[ "$(get_config IPV6_FORWARD_HARDEN)" == "yes" ]] && echo "已开启" || echo "关闭" )"
                    echo
                    echo "开启后：只允许经过 ${WG_INTERFACE} 的 IPv6 流量被转发，其余 IPv6"
                    echo "转发一律丢弃。只影响 IPv6，完全不碰 IPv4/Docker 的转发规则。"
                    echo "如果这台机器上还有其他用途的 IPv6 转发（不经过 WireGuard），"
                    echo "开启后会被一起挡掉，请确认后再开。"
                fi
                echo
                if confirm "切换这个开关？" "N"; then
                    if [[ "$(get_config IPV6_FORWARD_HARDEN)" == "yes" ]]; then
                        set_config "IPV6_FORWARD_HARDEN" "no"
                    else
                        set_config "IPV6_FORWARD_HARDEN" "yes"
                    fi
                    fw_sync_state
                    green "已切换为：$( [[ "$(get_config IPV6_FORWARD_HARDEN)" == "yes" ]] && echo "开启" || echo "关闭" )。"
                fi
                pause
                ;;
            5)
                clear
                bold "最近 50 条操作日志："
                echo
                tail -n 50 "${LOG_DIR}/manager.log" 2>/dev/null || yellow "暂无日志。"
                pause
                ;;
            6) uninstall_manager ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

uninstall_manager() {

    clear
    bold "卸载 WireGuard Manager"
    echo
    yellow "这会：停止并禁用 wg-quick@${WG_INTERFACE}、清理本脚本添加过的防火墙规则。"
    echo

    if ! confirm "确认执行？" "N"; then
        pause
        return
    fi

    local ts final_backup
    ts=$(date '+%Y%m%d_%H%M%S')
    final_backup="/root/wireguard-manager-uninstall-backup_${ts}.tar.gz"

    tar -czf "$final_backup" "$WG_DIR" "$MANAGER_DIR" /etc/sysctl.d/99-wireguard.conf 2>/dev/null || true
    chmod 600 "$final_backup" 2>/dev/null || true
    green "卸载前完整备份已保存到（不在 ${MANAGER_DIR} 内，删除数据时不会被一起清掉）："
    echo "  $final_backup"
    echo

    log_action "UNINSTALL"

    # 先收掉 Web 层。顺序很重要：如果先停 wg-quick 再管面板，采集进程会在
    # 一个已经不存在的接口上每 30 秒空跑一次 wg show，/opt/wireguard-manager
    # 和两个 systemd 单元也会变成没人认领的孤儿。
    if [[ "$(get_kv "$WEB_CONF" WEB_ENABLED 2>/dev/null)" == "yes" ]]; then
        yellow "检测到 Web 面板仍处于启用状态，会先卸载它（不影响 ${MANAGER_DIR} 下的配置数据）。"
        web_uninstall
    fi

    wg_down
    systemctl disable "wg-quick@${WG_INTERFACE}" >/dev/null 2>&1 || true

    fw_cleanup_all

    echo
    if confirm "是否连同 ${MANAGER_DIR} 和 ${WG_CONFIG}（客户端密钥等所有数据）一起删除？" "N"; then
        read -rp "这是不可逆操作，输入 DELETE-ALL 确认: " confirm_text
        if [[ "$confirm_text" == "DELETE-ALL" ]]; then
            rm -rf "$MANAGER_DIR" "$WG_CONFIG"
            green "已彻底清理，需要恢复时用上面那份 ${final_backup} 即可。"
        else
            yellow "未输入 DELETE-ALL，跳过数据删除，仅完成了服务停止和防火墙清理。"
        fi
    fi

    pause
}

# ============================================================
# Site-to-Site
# ============================================================

site_dir_for() { echo "${SITES_DIR}/$1"; }

# 网段冲突检查。返回值：
#   0 = 无冲突，可以正常三层路由
#   1 = 两端 LAN 完全相同，只能降级成"仅 VPN IP 互通"
#   2 = 部分重叠（VPN 网段撞 LAN、或两端 LAN 有交集），不推荐但允许强行继续
site_check_conflicts() {
    local local_lan="$1" remote_lan="$2" vpn_net4="$3"

    if [[ -n "$local_lan" && "$local_lan" == "$remote_lan" ]]; then
        echo
        red "⚠️  两端 LAN 网段相同（都是 ${remote_lan}），无法直接进行正常三层路由。"
        yellow "    两边都有一堆同网段主机，隧道另一端根本分不清「目标是本地网关"
        yellow "    还是对端某台机器」。请先给其中一端的 LAN 重新分配网段"
        yellow "    （例如把分部改成 192.168.20.0/24），这是唯一能让两边正常"
        yellow "    互通全部主机的办法。"
        return 1
    fi

    if [[ -n "$local_lan" ]] && cidr4_overlap "$local_lan" "$remote_lan" 2>/dev/null; then
        red "冲突：本地 LAN 与对端 LAN 网段有部分重叠！"
        return 2
    fi

    if cidr4_overlap "$vpn_net4" "$remote_lan" 2>/dev/null; then
        red "冲突：VPN 网段（${vpn_net4}）与对端 LAN 网段重叠！"
        return 2
    fi

    if [[ -n "$local_lan" ]] && cidr4_overlap "$vpn_net4" "$local_lan" 2>/dev/null; then
        red "冲突：VPN 网段（${vpn_net4}）与本地 LAN 网段重叠！"
        return 2
    fi

    return 0
}

# 站点落盘 + 生效。交互式 create_site 和非交互式 `wgmgr site create` 共用。
site_commit() {
    local name="$1" local_lan="$2" remote_lan="$3" remote_wg_ip="$4"
    local remote_endpoint="$5" remote_pubkey="$6" mode="$7" keepalive="${8:-25}"

    local sdir lan_iface
    sdir=$(site_dir_for "$name")

    mkdir -p "$sdir"
    chmod 700 "$sdir"

    set_kv "${sdir}/meta.conf" "NAME"              "$name"
    set_kv "${sdir}/meta.conf" "LOCAL_LAN"         "$local_lan"
    set_kv "${sdir}/meta.conf" "REMOTE_LAN"        "$remote_lan"
    set_kv "${sdir}/meta.conf" "REMOTE_WG_IP"      "$remote_wg_ip"
    set_kv "${sdir}/meta.conf" "REMOTE_ENDPOINT"   "$remote_endpoint"
    set_kv "${sdir}/meta.conf" "REMOTE_PUBLIC_KEY" "$remote_pubkey"
    set_kv "${sdir}/meta.conf" "KEEPALIVE"         "$keepalive"
    set_kv "${sdir}/meta.conf" "MODE"              "$mode"
    set_kv "${sdir}/meta.conf" "ENABLED"           "yes"
    set_kv "${sdir}/meta.conf" "CREATED"           "$(date '+%Y-%m-%d %H:%M:%S')"

    backup_snapshot "before_site_${name}" >/dev/null

    if [[ "$mode" != "conflict" && -n "$local_lan" ]]; then
        lan_iface=$(ip route | awk -v net="$local_lan" '$0 ~ net {print $3; exit}')
        if [[ -z "$lan_iface" ]]; then
            yellow "未能从当前路由表里自动识别本地 LAN（${local_lan}）所在网卡，"
            yellow "本机可能确实没有直连这个网段（比如它在另一台路由器后面）。"
            yellow "这种情况下 LAN<->WireGuard 的转发规则不会自动生成，只有 VPN"
            yellow "内网 IP 互通；等把这台机器接入该 LAN 之后，重新进「防火墙」"
            yellow "菜单执行一次同步即可补上。"
        fi
    fi

    if ! rebuild_server_config; then
        red "配置生成失败，站点元数据已保留，请检查后重试。"
        return 1
    fi
    # 上面这一步内部会调用 fw_sync_state()，按 LOCAL_LAN/MODE 自动把
    # LAN<->wg 转发和（如果选了 NAT 模式）MASQUERADE 规则一起下发好，
    # 不需要在这里再单独调用 fw_add_forward/fw_add_nat。

    configure_ip_forward "$(get_config USE_IPV6)"
    log_action "SITE_ADD ${name} remote_lan=${remote_lan} mode=${mode}"

    green
    green "=========================================="
    green "Site-to-Site 站点已创建：$name"
    green "=========================================="
    echo
    echo "对端需要在自己的配置里添加如下 Peer（本机信息）："
    echo "------------------------------------------"
    echo "PublicKey  = $(get_server_public_key)"
    echo "Endpoint   = $(get_config ENDPOINT):$(get_config WG_PORT)"
    if [[ -n "$local_lan" ]]; then
        echo "AllowedIPs = ${local_lan}, $(get_config VPN_NETWORK4)"
    else
        echo "AllowedIPs = $(get_config VPN_NETWORK4)"
    fi
    echo "------------------------------------------"
    return 0
}

create_site() {

    clear
    bold "=========================================="
    bold "        创建 Site-to-Site 连接"
    bold "=========================================="

    if [[ ! -f "$WG_CONFIG" ]]; then
        yellow "请先初始化本机服务端。"
        pause
        return
    fi

    echo
    echo "本向导会："
    echo "  1) 在本机生成到对端的 [Peer] 配置"
    echo "  2) 检查本地 LAN / 对端 LAN / VPN 网段是否冲突"
    echo "  3) 让你在「纯路由模式」和「NAT 模式」之间选择"
    echo "  4) 按选择自动放通 LAN <-> WireGuard 转发 / 配置 NAT"
    echo
    echo "对端需要提供：站点公钥、Endpoint（IP:端口，可选）、对端 LAN 网段、"
    echo "分配给对端的 VPN 内网 IP。"
    echo

    local name local_lan remote_lan remote_wg_ip remote_endpoint remote_pubkey
    local mode keepalive vpn_net4

    print_existing_sites
    echo
    read -rp "站点名称（如 hq / branch-a）: " name
    [[ -z "$name" ]] && { red "名称不能为空。"; pause; return; }
    [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] || { red "名称只能包含字母、数字、下划线、短横线。"; pause; return; }

    if [[ -d "$(site_dir_for "$name")" ]]; then
        red "该站点已存在，如需修改请先删除重建。"
        pause
        return
    fi

    read -rp "本地 LAN 网段（如 192.168.10.0/24，本机作为该网段网关时填写）: " local_lan
    read -rp "对端 LAN 网段（如 192.168.20.0/24）: " remote_lan
    read -rp "对端 VPN 内网 IP（如 10.66.66.253）: " remote_wg_ip
    read -rp "对端 Endpoint（如 1.2.3.4:51820，本机主动连对端时填写，否则留空）: " remote_endpoint
    read -rp "对端公钥: " remote_pubkey

    if [[ -z "$remote_lan" || -z "$remote_wg_ip" || -z "$remote_pubkey" ]]; then
        red "对端 LAN / VPN IP / 公钥 为必填项。"
        pause
        return
    fi

    if ! is_valid_wg_key "$remote_pubkey"; then
        red "对端公钥格式不像是合法的 WireGuard 公钥（应为 44 位，以 = 结尾），请检查后重试。"
        pause
        return
    fi

    vpn_net4=$(get_config VPN_NETWORK4)

    site_check_conflicts "$local_lan" "$remote_lan" "$vpn_net4"
    case "$?" in
        1)
            echo
            yellow "仍然可以创建这个站点，但只用于访问对端的 VPN 内网 IP（${remote_wg_ip}）本身，"
            yellow "不会尝试路由整个 LAN 网段，避免产生错误路由把你现有网络搞乱。"
            if ! confirm "以这种「仅 VPN IP 互通」的方式继续吗？" "N"; then
                pause
                return
            fi
            mode="conflict"
            ;;
        2)
            if ! confirm "检测到网段冲突，仍要继续吗（不推荐，可能导致路由行为不符合预期）？" "N"; then
                pause
                return
            fi
            mode="conflict"
            ;;
        *)
            echo
            echo "请选择转发模式："
            echo "  1. 纯路由模式（推荐）—— 双方网关都能加一条指向本机 VPN IP 的静态路由"
            echo "                    时用这个，最干净，站点之间不做 MASQUERADE，"
            echo "                    对端能看到真实的本地 LAN 源 IP。"
            echo "  2. NAT 模式   —— 对端路由器改不了（比如你不是分部那边的网络管理员），"
            echo "                    本地 LAN 访问对端 LAN 的流量会被伪装成本机的 VPN IP，"
            echo "                    对端只需要认识这台 WireGuard 机器，不用管你整个 LAN。"
            echo
            read -rp "选择 [1/2，默认 1]: " mode_choice
            if [[ "$mode_choice" == "2" ]]; then
                mode="nat"
            else
                mode="routing"
            fi
            ;;
    esac

    read -rp "PersistentKeepalive 秒数 [25]: " keepalive
    keepalive="${keepalive:-25}"

    site_commit "$name" "$local_lan" "$remote_lan" "$remote_wg_ip" \
                "$remote_endpoint" "$remote_pubkey" "$mode" "$keepalive" || { pause; return; }

    pause
}

list_sites() {

    clear
    bold "=========================================="
    bold "          Site-to-Site 列表"
    bold "=========================================="

    if ! compgen -G "${SITES_DIR}/*/meta.conf" >/dev/null; then
        yellow "暂无 Site-to-Site 配置。"
        pause
        return
    fi

    printf "%-16s %-18s %-16s %-6s %-22s\n" "名称" "对端 LAN" "对端 VPN IP" "状态" "Endpoint"
    printf "%-16s %-18s %-16s %-6s %-22s\n" "----------------" "------------------" "----------------" "------" "----------------------"

    local sdir name remote_lan remote_ip endpoint enabled
    for sdir in "$SITES_DIR"/*/; do
        [[ -f "${sdir}meta.conf" ]] || continue
        name=$(get_kv "${sdir}meta.conf" NAME)
        remote_lan=$(get_kv "${sdir}meta.conf" REMOTE_LAN)
        remote_ip=$(get_kv "${sdir}meta.conf" REMOTE_WG_IP)
        endpoint=$(get_kv "${sdir}meta.conf" REMOTE_ENDPOINT)
        enabled=$(get_kv "${sdir}meta.conf" ENABLED)

        printf "%-16s %-18s %-16s %-6s %-22s\n" \
            "$name" "$remote_lan" "$remote_ip" \
            "$( [[ "$enabled" == "yes" ]] && echo 启用 || echo 禁用 )" \
            "${endpoint:-（等待对方连入）}"
    done

    echo
    pause
}

toggle_site() {
    local target_state="$1"
    clear
    if [[ "$target_state" == "yes" ]]; then
        bold "=========================================="
        bold "          启用站点"
        bold "=========================================="
    else
        bold "=========================================="
        bold "          禁用站点"
        bold "=========================================="
    fi
    echo
    prompt_site_name "请输入站点名称: " || { pause; return; }
    local sdir="${SITES_DIR}/${name}"

    [[ -f "${sdir}/meta.conf" ]] || { red "站点不存在。"; pause; return; }

    set_kv "${sdir}/meta.conf" "ENABLED" "$target_state"

    if rebuild_server_config; then
        green "站点 ${name} 已$( [[ "$target_state" == "yes" ]] && echo 启用 || echo 禁用 )。"
    fi

    pause
}

delete_site() {

    clear
    bold "=========================================="
    bold "          删除站点"
    bold "=========================================="
    echo
    prompt_site_name "请输入要删除的站点名称: " || { pause; return; }
    local sdir="${SITES_DIR}/${name}"

    [[ -f "${sdir}/meta.conf" ]] || { red "站点不存在。"; pause; return; }

    read -rp "确认删除站点 ${name}？输入 DELETE: " confirm_text
    [[ "$confirm_text" != "DELETE" ]] && { yellow "已取消。"; pause; return; }

    rm -rf "$sdir"

    if rebuild_server_config; then
        green "站点已删除，对应的 LAN 转发/NAT 规则已随之自动清理。"
        log_action "SITE_DELETE ${name}"
    fi

    pause
}

test_site() {

    clear
    bold "=========================================="
    bold "       站点连通性测试"
    bold "=========================================="
    echo
    prompt_site_name "请输入站点名称: " || { pause; return; }
    local sdir="${SITES_DIR}/${name}"

    [[ -f "${sdir}/meta.conf" ]] || { red "站点不存在。"; pause; return; }

    local remote_ip remote_lan
    remote_ip=$(get_kv "${sdir}/meta.conf" REMOTE_WG_IP)
    remote_lan=$(get_kv "${sdir}/meta.conf" REMOTE_LAN)

    echo
    echo "测试到对端 VPN IP（${remote_ip}）的连通性："
    ping -c 4 -W 2 "$remote_ip" || yellow "无法 ping 通，请检查对端是否已配置好对称的 Peer。"

    if [[ -n "$remote_lan" ]]; then
        local gw="${remote_lan%.*/*}.1"
        echo
        echo "尝试 ping 对端 LAN 网关（猜测为 ${gw}，仅供参考）："
        ping -c 2 -W 2 "$gw" 2>/dev/null || true
    fi

    echo
    echo "WireGuard 侧握手/流量情况："
    wg show "$WG_INTERFACE" 2>/dev/null | grep -A4 "$(get_kv "${sdir}/meta.conf" REMOTE_PUBLIC_KEY)" || true

    pause
}

# ============================================================
# 状态 / 诊断
# ============================================================

show_status() {

    clear
    bold "=========================================="
    bold "          WireGuard 实时状态"
    bold "=========================================="

    if ! command_exists wg; then
        red "WireGuard 未安装。"
        pause
        return
    fi

    echo
    wg show "$WG_INTERFACE" 2>/dev/null || {
        yellow "接口 ${WG_INTERFACE} 当前未运行。"
        echo
        systemctl status "wg-quick@${WG_INTERFACE}" --no-pager 2>/dev/null || true
    }

    echo
    pause
}

diagnostic() {

    clear
    bold "=========================================="
    bold "           WireGuard 系统诊断"
    bold "=========================================="
    echo

    command_exists wg && green "[✓] WireGuard 已安装" || red "[✗] WireGuard 未安装"

    if wg_is_up; then
        green "[✓] ${WG_INTERFACE} 正在运行"
    else
        red "[✗] ${WG_INTERFACE} 未运行"
    fi

    if sysctl net.ipv4.ip_forward 2>/dev/null | grep -q "= 1"; then
        green "[✓] IPv4 forwarding 已开启"
    else
        red "[✗] IPv4 forwarding 未开启"
    fi

    if [[ "$(get_config USE_IPV6)" == "yes" ]]; then
        if sysctl net.ipv6.conf.all.forwarding 2>/dev/null | grep -q "= 1"; then
            green "[✓] IPv6 forwarding 已开启"
        else
            red "[✗] IPv6 forwarding 未开启"
        fi

        if [[ "$(get_config IPV6_FORWARD_HARDEN)" == "yes" ]]; then
            green "[✓] IPv6 转发加固已开启（只放行经 ${WG_INTERFACE} 的 IPv6 转发）"
        else
            yellow "[!] IPv6 转发加固未开启：net.ipv6.conf.all.forwarding 是全局开关，"
            yellow "    如果这台机器自己的 ip6tables/nft 对 IPv6 转发没有另外做限制，"
            yellow "    存在被当作公网路由器盗用的风险，建议去「高级设置」里确认。"
        fi
    fi

    [[ -f "$WG_CONFIG" ]] && green "[✓] WireGuard 配置存在" || red "[✗] WireGuard 配置不存在"
    [[ -f "$SERVER_PRIVATE_KEY" ]] && green "[✓] 服务器私钥存在" || red "[✗] 服务器私钥不存在"
    [[ -f "$SERVER_PUBLIC_KEY" ]] && green "[✓] 服务器公钥存在" || red "[✗] 服务器公钥不存在"

    local backend
    backend=$(fw_detect_backend)
    if [[ "$backend" != "none" ]]; then
        green "[✓] 防火墙后端：$backend"
    else
        red "[✗] 未检测到可用的防火墙工具"
    fi

    if [[ -f /.dockerenv ]]; then
        yellow "[i] 本脚本运行在 Docker 容器内部，wg-quick@ 的 systemd 集成可能不可用"
    fi
    command_exists docker && green "[i] 本机已安装 Docker（宿主机身份，不代表跑在容器里）"
    command_exists pveversion && green "[i] 本机是 Proxmox VE 宿主机"

    local port
    port=$(get_config WG_PORT)
    if [[ -n "$port" ]] && command_exists ss; then
        if ss -lunp 2>/dev/null | grep -q ":${port} "; then
            green "[✓] UDP ${port} 正在监听"
        else
            red "[✗] 未检测到 UDP ${port} 监听"
        fi
    fi

    local wan_iface vpn_net4
    wan_iface=$(get_config WAN_INTERFACE)
    vpn_net4=$(get_config VPN_NETWORK4)
    if [[ -n "$wan_iface" && -n "$vpn_net4" ]]; then
        if iptables -t nat -C POSTROUTING -s "$vpn_net4" -o "$wan_iface" -j MASQUERADE 2>/dev/null || \
           nft list ruleset 2>/dev/null | grep -q "masquerade"; then
            green "[✓] NAT 规则存在"
        else
            yellow "[?] 未能确认 NAT 规则（如使用 nftables/ufw 请手动核实）"
        fi
    fi

    local peer_count enabled_count
    peer_count=$(find "$CLIENTS_DIR" -maxdepth 1 -mindepth 1 -type d 2>/dev/null | wc -l)
    enabled_count=0
    for f in "$CLIENTS_DIR"/*/meta.conf; do
        [[ -f "$f" ]] || continue
        [[ "$(get_kv "$f" ENABLED)" == "yes" ]] && enabled_count=$((enabled_count + 1))
    done
    echo
    echo "客户端总数 : $peer_count（启用 $enabled_count）"

    local connected=0
    local now hs
    now=$(date +%s)
    for f in "$CLIENTS_DIR"/*/meta.conf; do
        [[ -f "$f" ]] || continue
        local pk
        pk=$(get_kv "$f" PUBLIC_KEY)
        hs=$(wg show "$WG_INTERFACE" latest-handshakes 2>/dev/null | awk -v k="$pk" '$1==k {print $2}')
        [[ -n "$hs" && "$hs" != "0" && $((now - hs)) -lt 180 ]] && connected=$((connected + 1))
    done
    echo "近 3 分钟内有握手 : $connected"

    echo
    echo "RX/TX 汇总："
    wg show "$WG_INTERFACE" transfer 2>/dev/null | \
        awk '{rx+=$2; tx+=$3} END {printf "  接收: %s   发送: %s\n", rx+0, tx+0}'

    echo
    pause
}

# ============================================================
# 备份 / 恢复
# ============================================================

backup_config() {

    local ts backup
    ts=$(date '+%Y%m%d_%H%M%S')
    backup="${BACKUP_DIR}/wireguard-full_${ts}.tar.gz"

    tar -czf "$backup" \
        "$WG_DIR" \
        "$MANAGER_DIR" \
        /etc/sysctl.d/99-wireguard.conf \
        2>/dev/null || true

    chmod 600 "$backup"

    green "备份完成："
    echo "$backup"
    pause
}

list_backups() {
    ls -1t "${BACKUP_DIR}"/wireguard-full_*.tar.gz 2>/dev/null
}

restore_backup() {

    clear
    bold "=========================================="
    bold "              恢复备份"
    bold "=========================================="
    echo

    local backups
    mapfile -t backups < <(list_backups)

    if [[ ${#backups[@]} -eq 0 ]]; then
        yellow "没有可用的完整备份（快照式的 wg0.conf 备份不在此列，仅用于内部回滚）。"
        pause
        return
    fi

    local i
    for i in "${!backups[@]}"; do
        echo "  $((i+1)). ${backups[$i]}"
    done
    echo

    read -rp "选择要恢复的备份编号（0 取消）: " choice
    [[ "$choice" == "0" || -z "$choice" ]] && return

    local idx=$((choice - 1))
    [[ -z "${backups[$idx]:-}" ]] && { red "无效编号。"; pause; return; }

    yellow "即将用 ${backups[$idx]} 覆盖当前 ${WG_DIR} 和 ${MANAGER_DIR}！"
    read -rp "确认恢复？输入 RESTORE: " confirm_text
    [[ "$confirm_text" != "RESTORE" ]] && { yellow "已取消。"; pause; return; }

    wg_down 2>/dev/null || true

    tar -xzf "${backups[$idx]}" -C /

    green "恢复完成，请重新进入菜单检查状态并按需启动 WireGuard。"
    pause
}

# ============================================================
# Site-to-Site 菜单
# ============================================================

site_to_site_menu() {

    while true; do
        clear
        bold "=========================================="
        bold "          WireGuard Site-to-Site"
        bold "=========================================="
        echo
        echo "  1. 创建 Site-to-Site"
        echo "  2. 查看 Site-to-Site 列表"
        echo "  3. 启用站点"
        echo "  4. 禁用站点"
        echo "  5. 删除站点"
        echo "  6. 连通性测试"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) create_site ;;
            2) list_sites ;;
            3) toggle_site "yes" ;;
            4) toggle_site "no" ;;
            5) delete_site ;;
            6) test_site ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 服务端菜单
# ============================================================

server_menu() {

    while true; do
        clear
        bold "=========================================="
        bold "          WireGuard 服务端"
        bold "=========================================="
        echo
        echo "  1. 初始化 / 重新配置服务端"
        echo "  2. 查看服务器信息"
        echo "  3. 查看 WireGuard 状态"
        echo "  4. 启动 WireGuard"
        echo "  5. 停止 WireGuard"
        echo "  6. 重启 WireGuard"
        echo "  7. 重新生成配置（从元数据）"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) server_setup ;;
            2) show_server_info ;;
            3) show_status ;;
            4) wg_up; pause ;;
            5) wg_down; pause ;;
            6) wg_restart; pause ;;
            7) rebuild_server_config && green "已重新生成。"; pause ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 客户端菜单
# ============================================================

client_menu() {

    while true; do
        clear
        bold "=========================================="
        bold "          WireGuard 客户端"
        bold "=========================================="
        echo
        echo "  1. 添加客户端"
        echo "  2. 客户端列表（含状态 / 握手 / 流量）"
        echo "  3. 查看客户端配置 / 二维码"
        echo "  4. 启用客户端"
        echo "  5. 禁用客户端"
        echo "  6. 删除客户端"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) add_client ;;
            2) list_clients ;;
            3) show_client_config ;;
            4) toggle_client "yes" ;;
            5) toggle_client "no" ;;
            6) delete_client ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 防火墙菜单
# ============================================================

firewall_menu() {

    while true; do
        clear
        bold "=========================================="
        bold "             防火墙管理"
        bold "=========================================="
        echo
        echo "当前后端：$(fw_detect_backend)"
        echo
        echo "  1. 查看防火墙规则概览"
        echo "  2. 清理本脚本添加的规则（不影响你自己的其他规则）"
        echo "  3. 重新同步（按当前客户端/站点状态重新生成规则，不影响连接）"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1)
                clear
                if command_exists ufw; then
                    echo "----- UFW -----"
                    ufw status verbose 2>/dev/null || true
                    echo
                fi
                if command_exists nft; then
                    echo "----- nftables (wg_manager 表) -----"
                    nft list table inet wg_manager 2>/dev/null || echo "（无）"
                    nft list table ip wg_manager_nat 2>/dev/null || true
                    nft list table ip6 wg_manager_nat6 2>/dev/null || true
                    echo
                fi
                if command_exists iptables; then
                    echo "----- iptables（带 ${FW_TAG} 标签的规则）-----"
                    iptables -L -n --line-numbers 2>/dev/null | grep -B1 "$FW_TAG" || echo "（无）"
                    echo
                    iptables -t nat -L -n --line-numbers 2>/dev/null | grep -B1 "$FW_TAG" || true
                fi
                if command_exists ip6tables; then
                    echo "----- ip6tables（带 ${FW_TAG} 标签的规则）-----"
                    ip6tables -L -n --line-numbers 2>/dev/null | grep -B1 "$FW_TAG" || echo "（无）"
                    echo
                    ip6tables -t nat -L -n --line-numbers 2>/dev/null | grep -B1 "$FW_TAG" || true
                fi
                pause
                ;;
            2)
                if confirm "确认清理本脚本添加过的所有防火墙规则？" "N"; then
                    fw_cleanup_all
                fi
                pause
                ;;
            3)
                fw_sync_state
                green "已按当前客户端/站点状态重新同步防火墙规则（这不会影响已建立的 WireGuard 连接）。"
                pause
                ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 环境信息
# ============================================================

show_environment() {

    clear
    bold "=========================================="
    bold "             系统环境"
    bold "=========================================="
    echo
    echo "操作系统 : ${OS_NAME:-未知}"
    echo "内核     : $(uname -r)"
    echo "架构     : $(uname -m)"
    echo "主机名   : $(hostname)"
    echo
    echo "默认网卡 : $(get_default_interface)"
    echo "网关     : $(get_default_gateway)"
    echo "本地 IP  : $(get_local_ipv4 "$(get_default_interface)")"
    echo "公网 IPv4: $(get_public_ipv4)"
    echo "公网 IPv6: $(get_public_ipv6)"
    echo
    echo "WireGuard："
    command_exists wg && wg --version || echo "未安装"
    echo
    echo "防火墙："
    command_exists ufw && echo "UFW: 已安装"
    command_exists nft && echo "nftables: 已安装"
    command_exists iptables && echo "iptables: 已安装"
    echo "当前使用后端: $(fw_detect_backend)"
    echo
    echo "虚拟化 / 容器环境："
    if command_exists docker; then
        echo "Docker: 已安装（$(docker version --format '{{.Server.Version}}' 2>/dev/null || echo '版本未知，daemon 可能未运行')）"
    else
        echo "Docker: 未安装"
    fi
    if command_exists pveversion; then
        echo "Proxmox VE: $(pveversion 2>/dev/null)"
    else
        echo "Proxmox VE: 不是 PVE 宿主机（或未安装 PVE 工具）"
    fi
    if [[ -f /.dockerenv ]]; then
        yellow "检测到本脚本自己就跑在 Docker 容器里——WireGuard 需要 NET_ADMIN"
        yellow "权限和 /dev/net/tun 设备，容器里的 wg-quick@ systemd 服务通常也不可用，"
        yellow "建议改成直接在容器启动脚本里跑 wg-quick up，而不是依赖 systemctl。"
    fi

    pause
}

# ============================================================
# State 层（V2.0）
#
# 把"配置真相"（manager.conf + clients/*/meta.conf + sites/*/meta.conf）
# 和"运行事实"（wg show dump / ip route / sysctl / ss / /proc）合成一份
# 结构化 JSON，写到 state/status.json。
#
# 这是 API、Web 面板、告警引擎、终端 Dashboard 的唯一数据源——
# 不让每个消费者各自去 grep wg 输出、各自算一遍在线状态，
# 否则阈值和口径迟早会分叉。
# ============================================================

json_str() {
    local s="${1-}"
    s="${s//\\/\\\\}"
    s="${s//\"/\\\"}"
    s="${s//$'\n'/\\n}"
    s="${s//$'\r'/\\r}"
    s="${s//$'\t'/\\t}"
    printf '"%s"' "$s"
}

json_bool() {
    case "${1-}" in
        yes|true|1|on|YES) printf 'true' ;;
        *)                 printf 'false' ;;
    esac
}

# 数字字段：空值/非数字一律落 0。wg dump 在接口没起来时会给出空串，
# 直接拼进 JSON 会得到非法文档，整个面板就白屏了。
json_num() {
    local v="${1-}"
    [[ "$v" =~ ^-?[0-9]+$ ]] || v=0
    printf '%s' "$v"
}

# 原子写入：先写同目录临时文件再 mv。采集守护进程每 30 秒写一次，
# Web 服务随时在读，没有这一步就可能读到写了一半的 JSON。
atomic_write() {
    local dest="$1" tmp
    tmp="${dest}.tmp.$$"
    cat > "$tmp" || { rm -f "$tmp"; return 1; }
    chmod 640 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
}

declare -gA META

# 把一个 meta.conf 整体读进 META 关联数组。
# 之前的 get_kv 每取一个字段都要 fork grep+tail+cut 三个进程，
# 采集 12 个 Peer × 8 个字段就是近 300 次 fork；守护进程每 30 秒
# 跑一次，这个开销没必要。
load_meta() {
    META=()
    local f="$1" line k v
    [[ -f "$f" ]] || return 0
    while IFS= read -r line || [[ -n "$line" ]]; do
        [[ -z "$line" || "$line" == \#* ]] && continue
        [[ "$line" != *=* ]] && continue
        k="${line%%=*}"
        v="${line#*=}"
        META["$k"]="$v"
    done < "$f"
    return 0
}

meta() { printf '%s' "${META[$1]-}"; }

# wg show dump 的输出一次性解析进关联数组，key 是公钥。
#   接口行：private-key \t listen-port \t fwmark                     （3 字段）
#   Peer 行：pubkey \t psk \t endpoint \t allowed-ips \t handshake
#            \t rx \t tx \t keepalive                                （8 字段）
# 注意私钥同样是 44 位以 = 结尾的 base64，光靠 is_valid_wg_key 分不出
# 接口行和 Peer 行，所以用"第 8 个字段是否存在"来区分。
declare -gA WG_LIVE WG_ENDPOINT WG_ALLOWED_LIVE WG_HS WG_RX WG_TX WG_KEEP

wg_dump_load() {
    WG_LIVE=(); WG_ENDPOINT=(); WG_ALLOWED_LIVE=()
    WG_HS=(); WG_RX=(); WG_TX=(); WG_KEEP=()

    local pk psk ep allowed hs rx tx keep
    while IFS=$'\t' read -r pk psk ep allowed hs rx tx keep; do
        [[ -z "${pk-}" ]] && continue
        [[ -z "${keep-}" ]] && continue          # 接口行，跳过
        is_valid_wg_key "$pk" || continue
        WG_LIVE["$pk"]=1
        WG_ENDPOINT["$pk"]="${ep-}"
        WG_ALLOWED_LIVE["$pk"]="${allowed-}"
        WG_HS["$pk"]="${hs-0}"
        WG_RX["$pk"]="${rx-0}"
        WG_TX["$pk"]="${tx-0}"
        WG_KEEP["$pk"]="${keep-off}"
    done < <(wg show "$WG_INTERFACE" dump 2>/dev/null)
}

# Peer 状态五态判定。V1.3 只有"在线/离线"，把"从没连过"和"三小时前
# 掉线"混成同一类，排障时分不清是新配置没生效还是链路真的断了。
#
#   disabled —— 元数据里 ENABLED != yes，压根没下发到内核
#   pending  —— 已启用，但 wg dump 里找不到（接口没起来 / 配置没同步）
#   never    —— 已在内核里，但对端从未完成过一次握手
#   online   —— 最近 PEER_ONLINE_SECS(180s) 内握过手
#   idle     —— 180s ~ PEER_IDLE_SECS(900s) 之间，通常是客户端休眠/切网
#   offline  —— 超过 15 分钟没握手
peer_status_class() {
    local enabled="$1" live="$2" hs="$3" now diff

    [[ "$enabled" == "yes" ]] || { printf 'disabled'; return; }
    [[ -n "$live" ]]          || { printf 'pending';  return; }
    if [[ -z "$hs" || "$hs" == "0" ]]; then
        printf 'never'
        return
    fi

    now=$(date +%s)
    diff=$(( now - hs ))
    (( diff < 0 )) && diff=0     # 对端时钟漂移导致握手时间在未来

    if   (( diff < PEER_ONLINE_SECS )); then printf 'online'
    elif (( diff < PEER_IDLE_SECS ));   then printf 'idle'
    else                                     printf 'offline'
    fi
}

peer_status_label() {
    case "$1" in
        online)   printf '在线' ;;
        idle)     printf '空闲' ;;
        offline)  printf '离线' ;;
        never)    printf '从未连接' ;;
        pending)  printf '未下发' ;;
        disabled) printf '已禁用' ;;
        *)        printf '%s' "$1" ;;
    esac
}

# 系统级事实。这里只负责"如实报告"，不做任何判断——
# 判断留给 Health Check Engine（web/wgm_health.py），
# 这样改健康规则不需要动 Bash。
_sys_ipv4_forward() {
    [[ "$(cat /proc/sys/net/ipv4/ip_forward 2>/dev/null)" == "1" ]] && printf 'yes' || printf 'no'
}

_sys_ipv6_forward() {
    [[ "$(cat /proc/sys/net/ipv6/conf/all/forwarding 2>/dev/null)" == "1" ]] && printf 'yes' || printf 'no'
}

_sys_port_listening() {
    local port="$1"
    [[ -z "$port" ]] && { printf 'no'; return; }
    command_exists ss || { printf 'no'; return; }
    if ss -lun 2>/dev/null | tail -n +2 | awk '{print $5}' | grep -qE "[:.]${port}\$"; then
        printf 'yes'
    else
        printf 'no'
    fi
}

_sys_nat_present() {
    local vpn4="$1" wan="$2"
    [[ -z "$vpn4" || -z "$wan" ]] && { printf 'no'; return; }
    if command_exists iptables && \
       iptables -t nat -C POSTROUTING -s "$vpn4" -o "$wan" -m comment --comment "$FW_TAG" -j MASQUERADE 2>/dev/null; then
        printf 'yes'; return
    fi
    if command_exists nft && nft list table ip wg_manager_nat 2>/dev/null | grep -q masquerade; then
        printf 'yes'; return
    fi
    printf 'no'
}

_sys_uptime_sec() {
    cut -d' ' -f1 /proc/uptime 2>/dev/null | cut -d'.' -f1
}

_sys_meminfo() {
    # $1 = MemTotal / MemAvailable
    awk -v k="$1" '$1 == k":" {print $2; exit}' /proc/meminfo 2>/dev/null
}

_sys_loadavg() {
    cat /proc/loadavg 2>/dev/null | awk '{printf "[%s, %s, %s]", $1, $2, $3}'
}

state_collect() {

    local dest="${1:-$STATE_STATUS_JSON}"
    local tmp now configured running first

    mkdir -p "$STATE_DIR"
    now=$(date +%s)
    tmp="${dest}.tmp.$$"

    wg_dump_load

    configured="no"; [[ -f "$WG_CONFIG" ]] && configured="yes"
    running="no";    wg_is_up && running="yes"

    local port vpn4 vpn6 srv4 srv6 dns mtu endpoint wan iface_cfg
    local use_v6 nat66 internet_nat harden backend pubkey
    port=$(get_config WG_PORT)
    vpn4=$(get_config VPN_NETWORK4)
    vpn6=$(get_config VPN_NETWORK6)
    srv4=$(get_config SERVER_IP4)
    srv6=$(get_config SERVER_IP6)
    dns=$(get_config DNS)
    mtu=$(get_config MTU);            mtu="${mtu:-1420}"
    endpoint=$(get_config ENDPOINT)
    wan=$(get_config WAN_INTERFACE)
    iface_cfg=$(get_config WG_INTERFACE); iface_cfg="${iface_cfg:-wg0}"
    use_v6=$(get_config USE_IPV6)
    nat66=$(get_config NAT66)
    internet_nat=$(get_config INTERNET_NAT); internet_nat="${internet_nat:-yes}"
    harden=$(get_config IPV6_FORWARD_HARDEN)
    backend=$(fw_detect_backend 2>/dev/null || echo none)
    pubkey=$(get_server_public_key)

    {
        echo "{"
        echo "  \"schema\": ${STATE_SCHEMA},"
        echo "  \"version\": $(json_str "$VERSION"),"
        echo "  \"generated_at\": $(json_num "$now"),"
        echo "  \"generated_at_str\": $(json_str "$(date '+%Y-%m-%d %H:%M:%S')"),"
        echo "  \"hostname\": $(json_str "$(hostname 2>/dev/null)"),"
        echo "  \"interface\": {"
        echo "    \"name\": $(json_str "$iface_cfg"),"
        echo "    \"configured\": $(json_bool "$configured"),"
        echo "    \"running\": $(json_bool "$running"),"
        echo "    \"listen_port\": $(json_num "$port"),"
        echo "    \"public_key\": $(json_str "$pubkey"),"
        echo "    \"mtu\": $(json_num "$mtu"),"
        echo "    \"vpn_network4\": $(json_str "$vpn4"),"
        echo "    \"vpn_network6\": $(json_str "$vpn6"),"
        echo "    \"server_ip4\": $(json_str "$srv4"),"
        echo "    \"server_ip6\": $(json_str "$srv6"),"
        echo "    \"endpoint\": $(json_str "$endpoint"),"
        echo "    \"wan_interface\": $(json_str "$wan"),"
        echo "    \"dns\": $(json_str "$dns"),"
        echo "    \"internet_nat\": $(json_bool "$internet_nat"),"
        echo "    \"use_ipv6\": $(json_bool "$use_v6"),"
        echo "    \"nat66\": $(json_bool "$nat66"),"
        echo "    \"ipv6_forward_harden\": $(json_bool "$harden"),"
        echo "    \"fw_backend\": $(json_str "$backend"),"
        echo "    \"config_path\": $(json_str "$WG_CONFIG")"
        echo "  },"

        # ---- system：只报事实，不下结论 ----
        local in_container="no" is_pve="no" has_docker="no" wg_installed="no"
        [[ -f /.dockerenv ]] && in_container="yes"
        grep -qa 'docker\|lxc\|containerd' /proc/1/cgroup 2>/dev/null && in_container="yes"
        command_exists pveversion && is_pve="yes"
        command_exists docker && has_docker="yes"
        command_exists wg && wg_installed="yes"

        echo "  \"system\": {"
        echo "    \"os\": $(json_str "${OS_NAME:-$(. /etc/os-release 2>/dev/null; echo "${PRETTY_NAME:-unknown}")}"),"
        echo "    \"kernel\": $(json_str "$(uname -r 2>/dev/null)"),"
        echo "    \"arch\": $(json_str "$(uname -m 2>/dev/null)"),"
        echo "    \"uptime_sec\": $(json_num "$(_sys_uptime_sec)"),"
        echo "    \"loadavg\": $(_sys_loadavg),"
        echo "    \"mem_total_kb\": $(json_num "$(_sys_meminfo MemTotal)"),"
        echo "    \"mem_avail_kb\": $(json_num "$(_sys_meminfo MemAvailable)"),"
        echo "    \"disk_avail_kb_root\": $(json_num "$(df -Pk / 2>/dev/null | awk 'NR==2 {print $4}')"),"
        echo "    \"in_container\": $(json_bool "$in_container"),"
        echo "    \"is_pve_host\": $(json_bool "$is_pve"),"
        echo "    \"has_docker\": $(json_bool "$has_docker"),"
        echo "    \"wg_installed\": $(json_bool "$wg_installed"),"
        echo "    \"ipv4_forward\": $(json_bool "$(_sys_ipv4_forward)"),"
        echo "    \"ipv6_forward\": $(json_bool "$(_sys_ipv6_forward)"),"
        echo "    \"port_listening\": $(json_bool "$(_sys_port_listening "$port")"),"
        echo "    \"nat_rule_present\": $(json_bool "$(_sys_nat_present "$vpn4" "$wan")")"
        echo "  },"

        # ---- peers：客户端 + 站点统一成一种对象，用 kind 区分 ----
        echo "  \"peers\": ["
        first=1

        local mdir mname mip4 mip6 mpub menabled mallowed mcreated mkeep
        local live hs rx tx keep_ep ep allowed_live cls diff
        for mdir in "$CLIENTS_DIR"/*/; do
            [[ -f "${mdir}meta.conf" ]] || continue
            load_meta "${mdir}meta.conf"

            mname=$(meta NAME); [[ -z "$mname" ]] && mname="$(basename "$mdir")"
            mip4=$(meta IP4)
            mip6=$(meta IP6)
            mpub=$(meta PUBLIC_KEY)
            menabled=$(meta ENABLED)
            mallowed=$(meta ALLOWED_IPS)
            mcreated=$(meta CREATED)
            mkeep=$(get_config DEFAULT_KEEPALIVE); mkeep="${mkeep:-25}"

            live=""; ep=""; allowed_live=""; hs="0"; rx="0"; tx="0"; keep_ep="off"
            if [[ -n "$mpub" && -n "${WG_LIVE[$mpub]-}" ]]; then
                live="1"
                ep="${WG_ENDPOINT[$mpub]-}"
                allowed_live="${WG_ALLOWED_LIVE[$mpub]-}"
                hs="${WG_HS[$mpub]-0}"
                rx="${WG_RX[$mpub]-0}"
                tx="${WG_TX[$mpub]-0}"
                keep_ep="${WG_KEEP[$mpub]-off}"
            fi
            cls=$(peer_status_class "$menabled" "$live" "$hs")
            diff="null"
            if [[ "$hs" =~ ^[0-9]+$ && "$hs" != "0" ]]; then
                diff=$(( now - hs )); (( diff < 0 )) && diff=0
            fi

            (( first )) || echo "    ,"
            first=0
            echo "    {"
            echo "      \"id\": $(json_str "$mname"),"
            echo "      \"name\": $(json_str "$mname"),"
            echo "      \"kind\": \"client\","
            echo "      \"enabled\": $(json_bool "$menabled"),"
            echo "      \"public_key\": $(json_str "$mpub"),"
            echo "      \"vpn_ip4\": $(json_str "$mip4"),"
            echo "      \"vpn_ip6\": $(json_str "$mip6"),"
            echo "      \"client_allowed_ips\": $(json_str "$mallowed"),"
            echo "      \"peer_allowed_ips\": $(json_str "${allowed_live:-${mip4}/32}"),"
            echo "      \"keepalive\": $(json_str "$keep_ep"),"
            echo "      \"configured_keepalive\": $(json_num "$mkeep"),"
            echo "      \"created\": $(json_str "$mcreated"),"
            echo "      \"loaded\": $(json_bool "$live"),"
            echo "      \"endpoint\": $(json_str "$([[ "$ep" == "(none)" ]] && echo "" || echo "$ep")"),"
            echo "      \"latest_handshake\": $(json_num "$hs"),"
            echo "      \"handshake_ago_sec\": ${diff},"
            echo "      \"status\": $(json_str "$cls"),"
            echo "      \"rx_bytes\": $(json_num "$rx"),"
            echo "      \"tx_bytes\": $(json_num "$tx")"
            echo "    }"
        done

        local sdir sname spub senabled smode sllocal srlocal srwgip srepend skeep screated
        for sdir in "$SITES_DIR"/*/; do
            [[ -f "${sdir}meta.conf" ]] || continue
            load_meta "${sdir}meta.conf"

            sname=$(meta NAME); [[ -z "$sname" ]] && sname="$(basename "$sdir")"
            spub=$(meta REMOTE_PUBLIC_KEY)
            senabled=$(meta ENABLED)
            smode=$(meta MODE); smode="${smode:-routing}"
            sllocal=$(meta LOCAL_LAN)
            srlocal=$(meta REMOTE_LAN)
            srwgip=$(meta REMOTE_WG_IP)
            srepend=$(meta REMOTE_ENDPOINT)
            skeep=$(meta KEEPALIVE); skeep="${skeep:-25}"
            screated=$(meta CREATED)

            live=""; ep=""; allowed_live=""; hs="0"; rx="0"; tx="0"; keep_ep="off"
            if [[ -n "$spub" && -n "${WG_LIVE[$spub]-}" ]]; then
                live="1"
                ep="${WG_ENDPOINT[$spub]-}"
                allowed_live="${WG_ALLOWED_LIVE[$spub]-}"
                hs="${WG_HS[$spub]-0}"
                rx="${WG_RX[$spub]-0}"
                tx="${WG_TX[$spub]-0}"
                keep_ep="${WG_KEEP[$spub]-off}"
            fi
            cls=$(peer_status_class "$senabled" "$live" "$hs")
            diff="null"
            if [[ "$hs" =~ ^[0-9]+$ && "$hs" != "0" ]]; then
                diff=$(( now - hs )); (( diff < 0 )) && diff=0
            fi

            (( first )) || echo "    ,"
            first=0
            echo "    {"
            echo "      \"id\": $(json_str "$sname"),"
            echo "      \"name\": $(json_str "$sname"),"
            echo "      \"kind\": \"site\","
            echo "      \"enabled\": $(json_bool "$senabled"),"
            echo "      \"public_key\": $(json_str "$spub"),"
            echo "      \"vpn_ip4\": $(json_str "$srwgip"),"
            echo "      \"vpn_ip6\": \"\","
            echo "      \"mode\": $(json_str "$smode"),"
            echo "      \"local_lan\": $(json_str "$sllocal"),"
            echo "      \"remote_lan\": $(json_str "$srlocal"),"
            echo "      \"remote_endpoint\": $(json_str "$srepend"),"
            echo "      \"peer_allowed_ips\": $(json_str "$allowed_live"),"
            echo "      \"keepalive\": $(json_str "$keep_ep"),"
            echo "      \"configured_keepalive\": $(json_num "$skeep"),"
            echo "      \"created\": $(json_str "$screated"),"
            echo "      \"loaded\": $(json_bool "$live"),"
            echo "      \"endpoint\": $(json_str "$([[ "$ep" == "(none)" ]] && echo "" || echo "$ep")"),"
            echo "      \"latest_handshake\": $(json_num "$hs"),"
            echo "      \"handshake_ago_sec\": ${diff},"
            echo "      \"status\": $(json_str "$cls"),"
            echo "      \"rx_bytes\": $(json_num "$rx"),"
            echo "      \"tx_bytes\": $(json_num "$tx")"
            echo "    }"
        done
        echo "  ],"

        # ---- routes：manager 自己维护的静态路由 + 内核里实际的路由 ----
        echo "  \"routes\": ["
        first=1
        if [[ -s "$ROUTES_CONF" ]]; then
            local rname rsubnet rvia rcomment
            while IFS='|' read -r rname rsubnet rvia rcomment; do
                [[ -z "$rname" ]] && continue
                (( first )) || echo "    ,"
                first=0
                echo "    {"
                echo "      \"name\": $(json_str "$rname"),"
                echo "      \"subnet\": $(json_str "$rsubnet"),"
                echo "      \"via\": $(json_str "$rvia"),"
                echo "      \"comment\": $(json_str "${rcomment-}")"
                echo "    }"
            done < "$ROUTES_CONF"
        fi
        echo "  ],"

        echo "  \"kernel_routes\": ["
        first=1
        local kr
        while IFS= read -r kr; do
            [[ -z "$kr" ]] && continue
            (( first )) || echo "    ,"
            first=0
            echo "    $(json_str "$kr")"
        done < <({ ip route show dev "$WG_INTERFACE" 2>/dev/null; ip -6 route show dev "$WG_INTERFACE" 2>/dev/null; })
        echo "  ],"

        # ---- web / collector：面板自己也要能在 Dashboard 上看到自身状态 ----
        local web_installed="no" web_running="no" collector_running="no" web_listen=""
        [[ -f "${WEB_APP_DIR}/wgm_web.py" ]] && web_installed="yes"
        web_listen="$(get_kv "$WEB_CONF" WEB_LISTEN)"
        web_listen="${web_listen:-127.0.0.1:8443}"
        if command_exists systemctl; then
            systemctl is-active --quiet "$WEB_SERVICE" 2>/dev/null && web_running="yes"
            systemctl is-active --quiet "$COLLECTOR_SERVICE" 2>/dev/null && collector_running="yes"
        fi

        echo "  \"web\": {"
        echo "    \"installed\": $(json_bool "$web_installed"),"
        echo "    \"running\": $(json_bool "$web_running"),"
        echo "    \"listen\": $(json_str "$web_listen"),"
        echo "    \"app_dir\": $(json_str "$WEB_APP_DIR"),"
        echo "    \"public_url\": $(json_str "$(get_kv "$WEB_CONF" WEB_PUBLIC_URL)")"
        echo "  },"
        echo "  \"collector\": {"
        echo "    \"running\": $(json_bool "$collector_running"),"
        echo "    \"interval_sec\": $(json_num "$(get_config COLLECT_INTERVAL)")"
        echo "  },"

        # ---- summary：面板首屏直接读这里，不用自己在前端再聚合一遍 ----
        local p_total=0 p_enabled=0 c_online=0 c_idle=0 c_offline=0 c_never=0
        local c_pending=0 c_disabled=0 n_client=0 n_site=0 t_rx=0 t_tx=0
        local st kd
        for kd in "$CLIENTS_DIR"/*/; do
            [[ -f "${kd}meta.conf" ]] || continue
            n_client=$((n_client + 1))
        done
        for kd in "$SITES_DIR"/*/; do
            [[ -f "${kd}meta.conf" ]] || continue
            n_site=$((n_site + 1))
        done

        # 直接从刚生成的 peers 段落里统计，避免再扫一遍磁盘。
        # 注意抽出来的值形如 `123,`（JSON 里带尾逗号），必须先截断再交给
        # json_num，否则它会因为不匹配纯数字正则而返回 0，流量累计恒为 0。
        local line_json val
        while IFS= read -r line_json; do
            case "$line_json" in
                *'"status":'*)
                    st="${line_json#*\"status\": }"; st="${st%%,*}"; st="${st//\"/}"
                    p_total=$((p_total + 1))
                    case "$st" in
                        online)   c_online=$((c_online + 1));     p_enabled=$((p_enabled + 1)) ;;
                        idle)     c_idle=$((c_idle + 1));         p_enabled=$((p_enabled + 1)) ;;
                        offline)  c_offline=$((c_offline + 1));   p_enabled=$((p_enabled + 1)) ;;
                        never)    c_never=$((c_never + 1));       p_enabled=$((p_enabled + 1)) ;;
                        pending)  c_pending=$((c_pending + 1));   p_enabled=$((p_enabled + 1)) ;;
                        disabled) c_disabled=$((c_disabled + 1)) ;;
                    esac
                    ;;
                *'"rx_bytes":'*)
                    val="${line_json#*\"rx_bytes\": }"; val="${val%%,*}"
                    t_rx=$(( t_rx + $(json_num "$val") )) ;;
                *'"tx_bytes":'*)
                    val="${line_json#*\"tx_bytes\": }"; val="${val%%,*}"
                    t_tx=$(( t_tx + $(json_num "$val") )) ;;
            esac
        done < <(grep -E '^[[:space:]]+"(status|rx_bytes|tx_bytes)":' "$tmp" 2>/dev/null)

        echo "  \"summary\": {"
        echo "    \"clients\": $(json_num "$n_client"),"
        echo "    \"sites\": $(json_num "$n_site"),"
        echo "    \"peers_total\": $(json_num "$p_total"),"
        echo "    \"peers_enabled\": $(json_num "$p_enabled"),"
        echo "    \"online\": $(json_num "$c_online"),"
        echo "    \"idle\": $(json_num "$c_idle"),"
        echo "    \"offline\": $(json_num "$c_offline"),"
        echo "    \"never\": $(json_num "$c_never"),"
        echo "    \"pending\": $(json_num "$c_pending"),"
        echo "    \"disabled\": $(json_num "$c_disabled"),"
        echo "    \"rx_bytes_total\": $(json_num "$t_rx"),"
        echo "    \"tx_bytes_total\": $(json_num "$t_tx")"
        echo "  }"
        echo "}"
    } > "$tmp" 2>/dev/null

    chmod 640 "$tmp" 2>/dev/null || true
    mv -f "$tmp" "$dest" || { rm -f "$tmp"; return 1; }
    return 0
}

# ============================================================
# 终端 Dashboard（V2.0）
#   和 Web 面板读同一份 state/status.json，口径完全一致。
#   支持 watch 式自动刷新，SSH 上去不想开浏览器时用。
# ============================================================

_status_glyph() {
    case "$1" in
        online)   printf '\033[32m● ONLINE \033[0m' ;;
        idle)     printf '\033[33m● IDLE   \033[0m' ;;
        offline)  printf '\033[31m● OFFLINE\033[0m' ;;
        never)    printf '\033[90m○ NEVER  \033[0m' ;;
        pending)  printf '\033[35m○ PENDING\033[0m' ;;
        disabled) printf '\033[90m■ DISABLE\033[0m' ;;
        *)        printf '%-9s' "$1" ;;
    esac
}

# 从 status.json 里按顺序抽取字段。这里刻意不依赖 jq——
# 目标机器不一定装了，而 state 文件的格式是本脚本自己生成的，
# 结构稳定，用 awk 抽字段足够可靠。
_json_field() {
    local file="$1" key="$2"
    awk -v k="\"${key}\":" 'index($0, k) { sub(/.*"'"$key"'": */, ""); gsub(/[",]/, ""); print; exit }' "$file" 2>/dev/null
}

dash_render() {

    local f="$STATE_STATUS_JSON"

    if [[ ! -f "$f" ]]; then
        yellow "还没有状态数据，先采集一次..."
        state_collect || { red "采集失败。"; return 1; }
    fi

    local running port vpn4 srv4 online idle offline never pending disabled
    local total rx tx hostname_str generated
    running=$(_json_field "$f" running)
    port=$(_json_field "$f" listen_port)
    vpn4=$(_json_field "$f" vpn_network4)
    srv4=$(_json_field "$f" server_ip4)
    hostname_str=$(_json_field "$f" hostname)
    generated=$(_json_field "$f" generated_at_str)
    online=$(_json_field "$f" online)
    idle=$(_json_field "$f" idle)
    offline=$(_json_field "$f" offline)
    never=$(_json_field "$f" never)
    pending=$(_json_field "$f" pending)
    disabled=$(_json_field "$f" disabled)
    total=$(_json_field "$f" peers_total)
    rx=$(_json_field "$f" rx_bytes_total)
    tx=$(_json_field "$f" tx_bytes_total)

    [[ "$RUN_MODE" == "interactive" ]] && clear
    bold "╔══════════════════════════════════════════════════════════════════════╗"
    printf '\033[1m║  WireGuard Manager v%s   %-20s                    ║\033[0m\n' "$VERSION" "$hostname_str"
    if [[ "$running" == "true" ]]; then
        printf '\033[1m║  %s                                                            ║\033[0m\n' "wg0: RUNNING  UDP/${port}  ${vpn4}  ${srv4}"
    else
        printf '\033[1m║  %s                                                            ║\033[0m\n' "wg0: STOPPED  UDP/${port}"
    fi
    bold "╠══════════════════════════════════════════════════════════════════════╣"
    echo
    printf '  Peer 总数 %-4s  ' "$total"
    printf '\033[32m在线 %-4s\033[0m ' "$online"
    printf '\033[33m空闲 %-4s\033[0m ' "$idle"
    printf '\033[31m离线 %-4s\033[0m ' "$offline"
    printf '\033[90m从未连接 %-4s\033[0m ' "$never"
    printf '\033[90m禁用 %-4s\033[0m\n' "$disabled"
    printf '  流量累计   ↓ %s   ↑ %s\n' "$(human_bytes "${rx:-0}")" "$(human_bytes "${tx:-0}")"
    printf '  采集时间   %s\n' "$generated"
    echo
    bold "  ── Peer 状态 ───────────────────────────────────────────────────────"
    printf '  %-16s %-8s %-16s %-10s %-8s %-9s %-9s\n' "NAME" "KIND" "IP" "STATUS" "HS" "RX" "TX"

    # peers 数组里每个对象跨多行，用 awk 按字段名逐个累积、遇到下一个 id
    # 或文件结束时输出一行。字节数和时间差都在 awk 里换算好，避免每行
    # 再 fork 一次 numfmt。
    local pname pkind pip pstatus phs prx ptx
    while IFS='|' read -r pname pkind pip pstatus phs prx ptx; do
        [[ -z "$pname" ]] && continue
        printf '  %-16s %-8s %-16s %b %-8s %-9s %-9s\n' \
            "$pname" "$pkind" "${pip:--}" "$(_status_glyph "$pstatus")" "$phs" "$prx" "$ptx"
    done < <(awk '
        function val(line, key,   s) {
            s = line
            sub(".*\"" key "\": *", "", s)
            gsub(/^"|"$/, "", s)
            sub(/,$/, "", s)
            gsub(/"$/, "", s)
            return s
        }
        function human(b,   u, n, i) {
            b = b + 0
            n = split("B K M G T P", u, " ")
            i = 1
            while (b >= 1024 && i < n) { b = b / 1024; i++ }
            if (i == 1) return sprintf("%d%s", b, u[i])
            return sprintf("%.1f%s", b, u[i])
        }
        function ago(s) {
            if (s == "null" || s == "") return "-"
            s = s + 0
            if (s < 60)    return s "s"
            if (s < 3600)  return int(s / 60) "m"
            if (s < 86400) return int(s / 3600) "h"
            return int(s / 86400) "d"
        }
        function flush() {
            if (id == "") return
            printf "%s|%s|%s|%s|%s|%s|%s\n", id, kind, ip, st, ago(hs), human(rx), human(tx)
            id = ""; kind = ""; ip = ""; st = ""; hs = ""; rx = 0; tx = 0
        }
        /"id":/                { flush(); id = val($0, "id") }
        /"kind":/              { kind = val($0, "kind") }
        /"vpn_ip4":/           { ip   = val($0, "vpn_ip4") }
        /"status":/            { st   = val($0, "status") }
        /"handshake_ago_sec":/ { hs   = val($0, "handshake_ago_sec") }
        /"rx_bytes":/          { rx   = val($0, "rx_bytes") + 0 }
        /"tx_bytes":/          { tx   = val($0, "tx_bytes") + 0 }
        END { flush() }
    ' "$f")

    echo
    bold "  ── Site-to-Site ────────────────────────────────────────────────────"
    local sname smode slan sstatus
    local have_site=0
    while IFS='|' read -r sname smode slan sstatus; do
        [[ -z "$sname" ]] && continue
        have_site=1
        printf '  %-16s %-10s %-22s %b\n' "$sname" "$smode" "${slan:--}" "$(_status_glyph "$sstatus")"
    done < <(awk '
        function val(line, key,   s) {
            s = line; sub(".*\"" key "\": *", "", s); gsub(/^"|"$/, "", s); sub(/,$/, "", s); gsub(/"$/, "", s); return s
        }
        /"kind": "site"/ { insite = 1 }
        insite && /"name":/       { n = val($0, "name") }
        insite && /"mode":/       { m = val($0, "mode") }
        insite && /"remote_lan":/ { l = val($0, "remote_lan") }
        insite && /"status":/     { s = val($0, "status"); print n "|" m "|" l "|" s; insite = 0 }
    ' "$f")
    (( have_site )) || echo "  （无）"

    echo
    return 0
}

dashboard_menu() {
    local refresh="${1:-0}"

    if [[ "$refresh" == "0" ]]; then
        state_collect >/dev/null 2>&1 || true
        dash_render
        echo
        read -rp "自动刷新间隔秒数（0=不刷新，直接返回）: " refresh
        refresh="${refresh:-0}"
        [[ "$refresh" =~ ^[0-9]+$ ]] || refresh=0
    fi

    if (( refresh == 0 )); then
        pause
        return
    fi

    while true; do
        state_collect >/dev/null 2>&1 || true
        dash_render
        printf '\n  每 %s 秒刷新，Ctrl-C 返回菜单\n' "$refresh"
        sleep "$refresh" || return
    done
}

# ============================================================
# Web 面板端口放行（V2.0）
#
# 这条规则必须写在 fw_sync_state() 里，而不是安装时单独下发一次。
# fw_sync_state 每次改配置都会先清空所有带标签的规则再全量重建，
# 如果面板端口规则游离在这个循环之外，那么任何一次"加客户端/改 NAT
# 开关"都会顺手把面板端口关掉，你会突然发现浏览器连不上了——
# 而这恰好是你最想打开面板看一眼的时候。
# ============================================================

# 只放行从 WireGuard 接口进来的面板流量（绑定到 VPN IP 时用这个）。
# 比全局放行 tcp/8443 安全得多：没连上 VPN 的人连 SYN 都发不进来。
fw_add_web_port_vpn() {
    local port="$1"
    local backend
    backend=$(fw_detect_backend)

    case "$backend" in
        nftables)
            fw_nft_ensure_table
            nft add rule inet wg_manager input iifname "$WG_INTERFACE" tcp dport "$port" accept 2>/dev/null || \
                yellow "nftables 放行面板端口失败（tcp/${port} via ${WG_INTERFACE}）。"
            ;;
        iptables)
            iptables -C INPUT -i "$WG_INTERFACE" -p tcp --dport "$port" -m comment --comment "$FW_TAG" -j ACCEPT 2>/dev/null || \
            iptables -I INPUT -i "$WG_INTERFACE" -p tcp --dport "$port" -m comment --comment "$FW_TAG" -j ACCEPT
            ;;
        ufw)
            ufw allow in on "$WG_INTERFACE" to any port "$port" proto tcp comment "$FW_TAG" >/dev/null 2>&1 || \
            ufw allow "$port/tcp" comment "$FW_TAG" >/dev/null 2>&1 || true
            ;;
        none) : ;;
    esac
}

# ============================================================
# Python 层委派（V2.0）
#
# 流量历史、Health Check、告警推送这三件事交给 Python：
# 它们要处理时间序列、结构化规则和 HTTP 出站，用 Bash 写既啰嗦又容易错。
# Bash 这边只负责把路径通过环境变量传过去，不在 Python 里硬编码路径，
# 这样源码树里直接跑也能用（不必先 install）。
# ============================================================

web_python() {
    local mod="$1"; shift
    local appdir="$WEB_APP_DIR"

    [[ -f "${appdir}/${mod}" ]] || appdir="$WEB_SRC_DIR"

    if [[ ! -f "${appdir}/${mod}" ]]; then
        red "找不到 ${mod}：Web/采集层尚未安装。"
        yellow "源码目录 ${WEB_SRC_DIR} 里也没有，请确认 V2.0 的 web/ 目录"
        yellow "和本脚本放在一起，或先执行：wgmgr web install"
        return 1
    fi

    if ! command_exists python3; then
        red "系统没有 python3，流量历史 / Health Check / 告警 / Web 面板都跑不起来。"
        yellow "安装：apt-get install -y python3"
        return 1
    fi

    WGM_MANAGER_DIR="$MANAGER_DIR" \
    WGM_STATE_DIR="$STATE_DIR" \
    WGM_LOG_DIR="$LOG_DIR" \
    WGM_WEB_CONF="$WEB_CONF" \
    WGM_MANAGER_CONF="$MANAGER_CONF" \
    WGM_CLI="${SCRIPT_PATH}" \
    WGM_INTERFACE="$WG_INTERFACE" \
        python3 "${appdir}/${mod}" "$@"
}

# ============================================================
# 流量统计（V2.0）
# ============================================================

traffic_menu() {
    while true; do
        clear
        bold "=========================================="
        bold "              流量统计"
        bold "=========================================="
        echo
        echo "  1. 最近 24 小时"
        echo "  2. 最近 7 天"
        echo "  3. 最近 30 天"
        echo "  4. 按 Peer 汇总（本月）"
        echo "  5. 趋势图（最近 24 小时）"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) web_python wgm_traffic.py report --range 24h ;;
            2) web_python wgm_traffic.py report --range 7d ;;
            3) web_python wgm_traffic.py report --range 30d ;;
            4) web_python wgm_traffic.py report --range 30d --by-peer ;;
            5) web_python wgm_traffic.py chart  --range 24h ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
        echo
        pause
    done
}

# ============================================================
# Health Check（V2.0）
# ============================================================

health_menu() {
    while true; do
        clear
        bold "=========================================="
        bold "          诊断 / Health Check"
        bold "=========================================="
        echo
        echo "  1. Health Check（结构化结论 + 下一步该查什么）"
        echo "  2. 传统系统诊断（✓/✗ 清单，不依赖 Python 层）"
        echo "  3. 告警设置（开关 / 监控范围 / 防抖次数 / 推送渠道 / 测试）"
        echo "  4. 最近告警记录"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) web_python wgm_health.py check --pretty ;;
            2) diagnostic; return ;;
            3) alert_menu ;;
            4) web_python wgm_alert.py history ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
        echo
        pause
    done
}

# ============================================================
# 告警（V2.0）
# ============================================================

alert_menu() {
    while true; do
        clear
        bold "=========================================="
        bold "              告警设置"
        bold "=========================================="
        echo
        echo "  总开关     : $( [[ "$(get_config ALERT_ENABLED)" == "yes" ]] && echo "已开启" || echo "关闭" )"
        echo "  监控范围   : $(get_config ALERT_WATCH)"
        echo "  确认次数   : $(get_config ALERT_THRESHOLD) 次判定离线后才告警"
        echo "  渠道       : $(get_config ALERT_CHANNELS)"
        echo
        echo "  1. 开关告警"
        echo "  2. 设置监控范围（all / sites / clients / 逗号分隔名单）"
        echo "  3. 设置确认次数（防抖，避免一次采集抖动就推送）"
        echo "  4. 配置 Telegram"
        echo "  5. 配置 Bark"
        echo "  6. 配置企业微信"
        echo "  7. 配置钉钉"
        echo "  8. 配置通用 Webhook"
        echo "  9. 发一条测试告警"
        echo " 10. 查看最近告警记录"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1)
                if [[ "$(get_config ALERT_ENABLED)" == "yes" ]]; then
                    set_config "ALERT_ENABLED" "no"
                else
                    set_config "ALERT_ENABLED" "yes"
                fi
                green "告警总开关：$(get_config ALERT_ENABLED)"
                pause
                ;;
            2)
                read -rp "监控范围 [all/sites/clients/名称列表] [$(get_config ALERT_WATCH)]: " v
                [[ -n "$v" ]] && set_config "ALERT_WATCH" "$v"
                green "已更新。"
                pause
                ;;
            3)
                read -rp "确认次数 [3]: " v
                v="${v:-3}"
                [[ "$v" =~ ^[0-9]+$ ]] && (( v >= 1 )) && (( v <= 20 )) || { red "必须是 1-20 的整数。"; pause; continue; }
                set_config "ALERT_THRESHOLD" "$v"
                green "已更新：连续 ${v} 次判定离线才推送。"
                pause
                ;;
            4)
                read -rsp "Telegram Bot Token: " v; echo
                [[ -n "$v" ]] && set_config "ALERT_TELEGRAM_TOKEN" "$v"
                read -rp "Telegram Chat ID: " v
                [[ -n "$v" ]] && set_config "ALERT_TELEGRAM_CHAT_ID" "$v"
                _alert_channel_add "telegram"
                pause
                ;;
            5)
                read -rp "Bark 推送地址（如 https://api.day.app/xxxxxxxx）: " v
                [[ -n "$v" ]] && set_config "ALERT_BARK_URL" "$v" && _alert_channel_add "bark"
                pause
                ;;
            6)
                read -rsp "企业微信机器人 Webhook Key: " v; echo
                [[ -n "$v" ]] && set_config "ALERT_WECOM_KEY" "$v" && _alert_channel_add "wecom"
                pause
                ;;
            7)
                read -rsp "钉钉机器人 Access Token: " v; echo
                [[ -n "$v" ]] && set_config "ALERT_DINGTALK_TOKEN" "$v"
                read -rsp "钉钉加签 Secret（没开加签就留空）: " v; echo
                [[ -n "$v" ]] && set_config "ALERT_DINGTALK_SECRET" "$v"
                _alert_channel_add "dingtalk"
                pause
                ;;
            8)
                read -rp "Webhook URL（POST JSON）: " v
                [[ -n "$v" ]] && set_config "ALERT_WEBHOOK_URL" "$v" && _alert_channel_add "webhook"
                pause
                ;;
            9) web_python wgm_alert.py test; pause ;;
            10) web_python wgm_alert.py history; pause ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# 往 ALERT_CHANNELS 里追加一个渠道，保持逗号分隔且不重复
_alert_channel_add() {
    local ch="$1" cur out
    cur=$(get_config ALERT_CHANNELS)
    if [[ ",${cur}," == *",${ch},"* ]]; then
        return 0
    fi
    if [[ -z "$cur" ]]; then
        out="$ch"
    else
        out="${cur},${ch}"
    fi
    set_config "ALERT_CHANNELS" "$out"
    green "已启用告警渠道：${ch}（当前：${out}）"
}

# ============================================================
# Web 面板（V2.0）
# ============================================================

# 口令哈希：scrypt + 随机盐，格式 scrypt$N$r$p$salt_b64$hash_b64。
# 口令一律走 stdin 传给 python，绝不放进 argv——argv 在 /proc/<pid>/cmdline
# 里对同机其他用户是可见的。
_web_hash_password() {
    python3 -c '
import base64, hashlib, os, sys
pw = sys.stdin.buffer.read()
salt = os.urandom(16)
dk = hashlib.scrypt(pw, salt=salt, n=16384, r=8, p=1, dklen=32)
print("scrypt$16384$8$1$%s$%s" % (
    base64.b64encode(salt).decode(), base64.b64encode(dk).decode()))
'
}

# 面板绑定范围。这一项决定了防火墙要不要放行、放行多大范围，
# 所以显式存进 web.conf，而不是靠解析监听地址去猜。
#   local  —— 只绑 127.0.0.1，配合 SSH 隧道或反向代理，不放行任何入站
#   vpn    —— 绑 WireGuard 的 VPN IP，只有连上 VPN 的设备能访问（推荐）
#   public —— 绑 0.0.0.0，公网可达，必须自己在前面挂 HTTPS 反代
web_bind_address() {
    local scope="$1" port="$2" vpn_ip
    case "$scope" in
        vpn)
            vpn_ip="$(get_config SERVER_IP4)"
            vpn_ip="${vpn_ip%%/*}"
            [[ -n "$vpn_ip" ]] && { echo "${vpn_ip}:${port}"; return; }
            echo "127.0.0.1:${port}"
            ;;
        public) echo "0.0.0.0:${port}" ;;
        *)      echo "127.0.0.1:${port}" ;;
    esac
}

web_passwd() {
    local user="${1-}" pass1 pass2 hash

    if [[ -z "$user" ]]; then
        read -rp "面板用户名 [$(get_kv "$WEB_CONF" WEB_USER)]: " user
        user="${user:-$(get_kv "$WEB_CONF" WEB_USER)}"
        user="${user:-admin}"
    fi

    [[ "$user" =~ ^[A-Za-z0-9_.-]{1,32}$ ]] || {
        red "用户名只能包含字母/数字/._-，长度 1-32。"; return 1; }

    if [[ -t 0 ]]; then
        read -rsp "密码（至少 12 位）: " pass1; echo
        read -rsp "再输入一次: " pass2; echo
        [[ "$pass1" == "$pass2" ]] || { red "两次输入不一致。"; return 1; }
    else
        # 非交互：从 stdin 读一行口令，供 `wgmgr web passwd --stdin` 和自动化使用
        IFS= read -r pass1
        pass2="$pass1"
    fi

    [[ ${#pass1} -ge 12 ]] || { red "密码太短，至少 12 位。"; return 1; }

    command_exists python3 || { red "需要 python3 才能生成口令哈希。"; return 1; }

    hash=$(printf '%s' "$pass1" | _web_hash_password) || { red "生成口令哈希失败。"; return 1; }

    set_kv "$WEB_CONF" "WEB_USER"      "$user"
    set_kv "$WEB_CONF" "WEB_PASS_HASH" "$hash"
    chmod 600 "$WEB_CONF"

    pass1=""; pass2=""
    green "面板账号已设置：${user}"
    log_action "WEB_PASSWD user=${user}"
    return 0
}

web_install() {

    clear
    bold "=========================================="
    bold "           安装 Web 面板 / 采集层"
    bold "=========================================="
    echo

    if ! command_exists python3; then
        red "系统没有 python3。"
        if confirm "现在用 apt 安装 python3？" "Y"; then
            apt-get update && apt-get install -y python3 || { red "安装失败。"; pause; return 1; }
        else
            pause; return 1
        fi
    fi

    local pyver
    pyver=$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])' 2>/dev/null)
    if ! python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 8) else 1)' 2>/dev/null; then
        red "python3 版本过低（当前 ${pyver:-未知}），需要 3.8 以上。"
        pause
        return 1
    fi
    green "[✓] python3 ${pyver}"

    if [[ ! -d "$WEB_SRC_DIR" ]]; then
        red "找不到 Web 层源码目录：${WEB_SRC_DIR}"
        yellow "V2.0 不再是单文件分发，web/ 和 systemd/ 必须和本脚本放在一起。"
        pause
        return 1
    fi
    green "[✓] 源码目录 ${WEB_SRC_DIR}"

    if [[ ! -d "$SYSTEMD_SRC_DIR" ]]; then
        yellow "[!] 找不到 systemd 单元目录 ${SYSTEMD_SRC_DIR}，将只安装文件，不注册服务。"
    fi

    echo
    echo "安装位置：${WEB_INSTALL_DIR}"
    echo "  - 采集服务 ${COLLECTOR_SERVICE}.service"
    echo "  - 面板服务 ${WEB_SERVICE}.service"
    echo "  - 全局命令 ${WEB_BIN} -> ${SCRIPT_PATH}"
    echo

    # ---- 绑定范围 ----
    local vpn_ip scope port
    vpn_ip="$(get_config SERVER_IP4)"; vpn_ip="${vpn_ip%%/*}"

    echo "面板监听范围："
    echo "  1. 仅 VPN 内可达  —— 绑 ${vpn_ip:-<VPN IP>}，只有连上 WireGuard 的设备能打开（推荐）"
    echo "  2. 仅本机         —— 绑 127.0.0.1，配合 SSH 隧道或 Nginx/Cloudflare 反代"
    echo "  3. 公网可达       —— 绑 0.0.0.0，任何人扫到端口就能访问登录页"
    echo
    read -rp "选择 [1]: " scope_choice
    case "$scope_choice" in
        2) scope="local" ;;
        3)
            scope="public"
            echo
            red "⚠️  你选择了把管理面板直接暴露在公网上。"
            red "    这意味着登录页对全网可见，会被自动化扫描器持续爆破。"
            red "    只有在前面挂了 HTTPS 反向代理（Nginx Proxy Manager / Caddy /"
            red "    Cloudflare Tunnel）并且限制了来源时才建议这么选。"
            echo
            confirm "确认继续用 0.0.0.0 绑定？" "N" || { pause; return 1; }
            ;;
        *) scope="vpn" ;;
    esac

    if [[ "$scope" == "vpn" && -z "$vpn_ip" ]]; then
        yellow "服务端还没初始化，拿不到 VPN IP，先按「仅本机」安装，"
        yellow "初始化之后可以回到这里重新执行一次安装改绑定。"
        scope="local"
    fi

    read -rp "面板端口 [8443]: " port
    port="${port:-8443}"
    [[ "$port" =~ ^[0-9]+$ ]] && (( port > 0 && port < 65536 )) || { red "端口不合法。"; pause; return 1; }

    local listen
    listen=$(web_bind_address "$scope" "$port")

    set_kv "$WEB_CONF" "WEB_BIND_SCOPE" "$scope"
    set_kv "$WEB_CONF" "WEB_LISTEN"     "$listen"
    set_kv "$WEB_CONF" "WEB_ENABLED"    "yes"

    local interval
    read -rp "状态采集间隔秒数 [30]: " interval
    interval="${interval:-30}"
    [[ "$interval" =~ ^[0-9]+$ ]] && (( interval >= 5 )) || interval=30
    set_config "COLLECT_INTERVAL" "$interval"

    # ---- 落地文件 ----
    echo
    mkdir -p "$WEB_INSTALL_DIR"
    rm -rf "$WEB_APP_DIR"
    cp -a "$WEB_SRC_DIR" "$WEB_APP_DIR" || { red "复制 Web 层文件失败。"; pause; return 1; }
    chmod 750 "$WEB_INSTALL_DIR" "$WEB_APP_DIR"
    find "$WEB_APP_DIR" -type f -name '*.py' -exec chmod 750 {} \; 2>/dev/null || true
    green "[✓] Web 层已安装到 ${WEB_APP_DIR}"

    ln -sf "$SCRIPT_PATH" "$WEB_BIN" 2>/dev/null && green "[✓] ${WEB_BIN} -> ${SCRIPT_PATH}"

    # ---- 专用运行账号 ----
    # 采集进程要跑 wg show / 读 root 拥有的 manager.log，所以它仍以 root 跑；
    # 但面板服务降权到 wgmgr-web——它只读 state/ 和 web.conf/manager.conf，
    # 写操作一律经 sudo 落到白名单 wgmgr 子命令上。这里把面板"读得到运行所需、
    # 但读不到任何密钥"的最小权限放好；之后由 init_directories 每次幂等维持。
    if ! getent group wgmgr-web >/dev/null 2>&1; then
        groupadd --system wgmgr-web 2>/dev/null || true
    fi
    if ! id -u wgmgr-web >/dev/null 2>&1; then
        useradd --system --no-create-home --shell /usr/sbin/nologin \
                --gid wgmgr-web wgmgr-web 2>/dev/null || true
    fi
    if id -u wgmgr-web >/dev/null 2>&1; then
        # state/ 下已存在的文件补属组+组可读；之后新建的靠 setgid 自动继承。
        chgrp -R wgmgr-web "$STATE_DIR" 2>/dev/null || true
        find "$STATE_DIR" -type f -exec chmod g+r {} + 2>/dev/null || true
        chmod 2750 "$STATE_DIR" "$TRAFFIC_DIR" 2>/dev/null || true
        # 面板要能 traverse 进 /etc/wireguard-manager 并读到这两个 conf。
        chgrp wgmgr-web "$MANAGER_DIR" "$WEB_CONF" "$MANAGER_CONF" 2>/dev/null || true
        chmod 710 "$MANAGER_DIR" 2>/dev/null || true
        chmod 640 "$WEB_CONF" "$MANAGER_CONF" 2>/dev/null || true
        # 面板还要能读到 /opt/wireguard-manager/web 下的 .py 与 static/。
        chgrp -R wgmgr-web "$WEB_INSTALL_DIR" 2>/dev/null || true
        green "[✓] 已创建降权账号 wgmgr-web，并放好 state/ 与配置的最小读权限"
    else
        yellow "[!] 无法创建 wgmgr-web 账号，面板将以 root 运行（可用但不推荐）。"
    fi

    # ---- sudoers：让降权面板能免密 sudo 调用 root 的 wgmgr ----
    # 面板以 wgmgr-web 跑，但加客户端/建站点这些写操作最终要落到 root 的 wgmgr。
    # wgm_common.run_cli 在非 root 时会自动加 `sudo -n`，靠的就是这条规则。
    # 只放行 /usr/local/bin/wgmgr 这一个绝对路径；具体哪些子命令能调，仍由
    # Python 侧 wgm_common.ALLOWED_CLI 白名单把关——两层一起构成纵深防御。
    if id -u wgmgr-web >/dev/null 2>&1; then
        if ! command_exists sudo; then
            yellow "[!] 系统没有 sudo，降权面板将无法执行写操作。"
            if confirm "现在用 apt 安装 sudo？" "Y"; then
                apt-get update && apt-get install -y sudo >/dev/null 2>&1 \
                    || yellow "[!] sudo 安装失败，写操作将不可用。"
            fi
        fi
        local sudoers_src="${SYSTEMD_SRC_DIR}/${WEB_SERVICE}.sudoers"
        if [[ -f "$sudoers_src" ]] && command_exists sudo; then
            # 必须先用 visudo 校验语法再装：一份语法错的 sudoers 落到
            # /etc/sudoers.d/ 会让整机所有 sudo 直接瘫痪，绝不能 cp 了事。
            if visudo -cf "$sudoers_src" >/dev/null 2>&1; then
                install -m 0440 -o root -g root "$sudoers_src" "$WEB_SUDOERS_FILE"
                green "[✓] sudoers 规则已安装 ${WEB_SUDOERS_FILE}"
            else
                red "[!] sudoers 模板语法校验未通过，已跳过安装（面板写操作将不可用）。"
                red "    请检查 ${sudoers_src}"
            fi
        else
            yellow "[!] 找不到 sudoers 模板 ${sudoers_src}，跳过（面板写操作将不可用）。"
        fi
    fi

    # ---- systemd 单元 ----
    if [[ -d "$SYSTEMD_SRC_DIR" ]] && command_exists systemctl; then
        install -m 644 "${SYSTEMD_SRC_DIR}/${COLLECTOR_SERVICE}.service" \
                "/etc/systemd/system/${COLLECTOR_SERVICE}.service" 2>/dev/null
        install -m 644 "${SYSTEMD_SRC_DIR}/${WEB_SERVICE}.service" \
                "/etc/systemd/system/${WEB_SERVICE}.service" 2>/dev/null
        systemctl daemon-reload
        green "[✓] systemd 单元已安装"
    else
        yellow "[!] 跳过 systemd 单元安装（容器内通常没有 systemd）。"
        yellow "    容器里可以手动前台跑："
        yellow "      python3 ${WEB_APP_DIR}/wgm_collector.py"
        yellow "      python3 ${WEB_APP_DIR}/wgm_web.py"
    fi

    # ---- 防火墙 ----
    fw_sync_state
    case "$scope" in
        vpn)    green "[✓] 防火墙：仅放行 ${WG_INTERFACE} 上的 tcp/${port}" ;;
        public) green "[✓] 防火墙：已放行 tcp/${port}（公网可达）" ;;
        *)      green "[✓] 防火墙：未放行任何入站（面板只绑回环）" ;;
    esac

    # ---- 账号 ----
    echo
    if [[ -z "$(get_kv "$WEB_CONF" WEB_PASS_HASH)" ]]; then
        yellow "还没有设置面板账号，现在设置："
        web_passwd || { pause; return 1; }
    else
        green "[✓] 面板账号已存在（$(get_kv "$WEB_CONF" WEB_USER)），如需修改用「重置面板密码」"
    fi

    # ---- 启动 ----
    echo
    state_collect >/dev/null 2>&1 || true

    if command_exists systemctl && [[ -f "/etc/systemd/system/${WEB_SERVICE}.service" ]]; then
        if confirm "现在启动采集服务和面板服务？" "Y"; then
            systemctl enable --now "$COLLECTOR_SERVICE" >/dev/null 2>&1
            systemctl enable --now "$WEB_SERVICE" >/dev/null 2>&1
            sleep 1
            web_ctl status
        fi
    fi

    echo
    web_url
    log_action "WEB_INSTALL scope=${scope} listen=${listen} interval=${interval}"
    pause
    return 0
}

web_ctl() {
    local action="${1:-status}"

    if ! command_exists systemctl; then
        red "系统没有 systemd，无法用 systemctl 管理面板服务。"
        yellow "容器里请手动跑：python3 ${WEB_APP_DIR}/wgm_collector.py  /  wgm_web.py"
        return 1
    fi

    case "$action" in
        start)
            systemctl enable --now "$COLLECTOR_SERVICE" >/dev/null 2>&1
            systemctl enable --now "$WEB_SERVICE" >/dev/null 2>&1
            sleep 1
            green "已启动。"
            web_ctl status
            ;;
        stop)
            systemctl stop "$WEB_SERVICE" >/dev/null 2>&1
            systemctl stop "$COLLECTOR_SERVICE" >/dev/null 2>&1
            green "已停止（WireGuard 本身不受影响）。"
            ;;
        restart)
            systemctl restart "$COLLECTOR_SERVICE" >/dev/null 2>&1
            systemctl restart "$WEB_SERVICE" >/dev/null 2>&1
            sleep 1
            green "已重启。"
            web_ctl status
            ;;
        disable)
            systemctl disable --now "$WEB_SERVICE" >/dev/null 2>&1
            systemctl disable --now "$COLLECTOR_SERVICE" >/dev/null 2>&1
            green "已停止并取消开机自启。"
            ;;
        status)
            echo
            printf '  %-28s %s\n' "采集服务 ${COLLECTOR_SERVICE}:" \
                "$(systemctl is-active "$COLLECTOR_SERVICE" 2>/dev/null || echo unknown)"
            printf '  %-28s %s\n' "面板服务 ${WEB_SERVICE}:" \
                "$(systemctl is-active "$WEB_SERVICE" 2>/dev/null || echo unknown)"
            echo
            local f="$STATE_STATUS_JSON"
            if [[ -f "$f" ]]; then
                local age now gen
                now=$(date +%s)
                gen=$(_json_field "$f" generated_at)
                age=$(( now - ${gen:-0} ))
                printf '  %-28s %s\n' "最近一次采集:" "$(_json_field "$f" generated_at_str) （${age} 秒前）"
                if (( age > 300 )); then
                    yellow "  ⚠️  状态数据已超过 5 分钟没更新，采集服务可能没在跑。"
                    yellow "     排查：journalctl -u ${COLLECTOR_SERVICE} -n 50"
                fi
            else
                yellow "  还没有状态数据，先跑一次：wgmgr collect"
            fi
            echo
            ;;
        logs)
            journalctl -u "$WEB_SERVICE" -u "$COLLECTOR_SERVICE" -n 80 --no-pager 2>/dev/null || \
                yellow "取不到日志。"
            ;;
        *)
            red "未知操作：${action}"
            return 1
            ;;
    esac
    return 0
}

web_url() {
    local scope listen port pub url
    scope=$(get_kv "$WEB_CONF" WEB_BIND_SCOPE); scope="${scope:-local}"
    listen=$(get_kv "$WEB_CONF" WEB_LISTEN);    listen="${listen:-127.0.0.1:8443}"
    port="${listen##*:}"
    pub=$(get_kv "$WEB_CONF" WEB_PUBLIC_URL)

    bold "面板访问方式："
    echo
    case "$scope" in
        vpn)
            local vpn_ip; vpn_ip="$(get_config SERVER_IP4)"; vpn_ip="${vpn_ip%%/*}"
            url="http://${vpn_ip:-<VPN IP>}:${port}/"
            echo "  ${url}"
            echo "  （需要先连上这台机器的 WireGuard，用 VPN 内的地址打开）"
            ;;
        public)
            url="http://${listen}:${port}/"
            url="http://$(get_config ENDPOINT):${port}/"
            echo "  ${url}"
            red "  ⚠️  公网 HTTP 明文，口令会被中间人看到。请务必在前面挂 HTTPS 反代。"
            ;;
        *)
           echo "  http://127.0.0.1:${port}/   （仅本机）"
           echo
           echo "  从你自己的电脑建 SSH 隧道后访问："
            echo "    ssh -L ${port}:127.0.0.1:${port} root@$(get_config ENDPOINT 2>/dev/null || echo YOUR_SERVER_IP)"
           echo "    然后浏览器打开 http://127.0.0.1:${port}/"
           ;;
   esac

    if [[ -n "$pub" ]]; then
        echo
        echo "  反向代理地址：${pub}"
    fi
    echo
    return 0
}

web_uninstall() {
    clear
    bold "卸载 Web 面板 / 采集层"
    echo
    yellow "这会停止并删除两个 systemd 服务、删除 ${WEB_INSTALL_DIR}。"
    yellow "不会碰 WireGuard 本身，也不会删 ${MANAGER_DIR} 下的配置和密钥。"
    echo

    confirm "确认卸载？" "N" || { pause; return; }

    if command_exists systemctl; then
        systemctl disable --now "$WEB_SERVICE" >/dev/null 2>&1 || true
        systemctl disable --now "$COLLECTOR_SERVICE" >/dev/null 2>&1 || true
        rm -f "/etc/systemd/system/${WEB_SERVICE}.service" \
              "/etc/systemd/system/${COLLECTOR_SERVICE}.service"
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi

    rm -rf "$WEB_INSTALL_DIR"
    rm -f "$WEB_SUDOERS_FILE"
    set_kv "$WEB_CONF" "WEB_ENABLED" "no"

    # 收掉降权账号。删掉 wgmgr-web 组后，init_directories 下次运行因为
    # WEB_ENABLED!=yes 且组已不存在，会自动把 MANAGER_DIR/state/manager.conf
    # 收回严格的 700/750/600；唯独 web.conf 不在它的重置范围内（只在文件
    # 不存在时才 chmod 600），所以这里显式把它收回 root:root 600。
    if id -u wgmgr-web >/dev/null 2>&1; then
        userdel wgmgr-web >/dev/null 2>&1 || true
    fi
    if getent group wgmgr-web >/dev/null 2>&1; then
        groupdel wgmgr-web >/dev/null 2>&1 || true
    fi
    chgrp root "$WEB_CONF" 2>/dev/null || true
    chmod 600 "$WEB_CONF" 2>/dev/null || true

    fw_sync_state      # 把面板端口的放行规则一起收掉
    log_action "WEB_UNINSTALL"

    green "已卸载。WireGuard 与 ${MANAGER_DIR} 下的配置数据保持不变。"
    pause
}

web_menu() {
    while true; do
        clear
        bold "=========================================="
        bold "              Web 面板"
        bold "=========================================="
        echo
        local scope listen
        scope=$(get_kv "$WEB_CONF" WEB_BIND_SCOPE)
        listen=$(get_kv "$WEB_CONF" WEB_LISTEN)
        echo "  安装状态 : $( [[ -f "${WEB_APP_DIR}/wgm_web.py" ]] && echo "已安装 ${WEB_APP_DIR}" || echo "未安装" )"
        echo "  绑定范围 : ${scope:-未设置}"
        echo "  监听地址 : ${listen:-未设置}"
        echo "  登录用户 : $(get_kv "$WEB_CONF" WEB_USER)"
        echo
        echo "  1. 安装 / 重新安装（含绑定范围、端口、账号）"
        echo "  2. 启动"
        echo "  3. 停止"
        echo "  4. 重启"
        echo "  5. 查看状态"
        echo "  6. 查看服务日志"
        echo "  7. 重置面板密码"
        echo "  8. 设置对外访问地址（反向代理后的 URL，仅用于展示）"
        echo "  9. 显示访问方式"
        echo " 10. 立即采集一次状态"
        echo " 11. 卸载面板"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) web_install ;;
            2) web_ctl start;  pause ;;
            3) web_ctl stop;   pause ;;
            4) web_ctl restart; pause ;;
            5) web_ctl status; pause ;;
            6) web_ctl logs;   pause ;;
            7) web_passwd;     pause ;;
            8)
                read -rp "对外访问地址（如 https://wg.example.com）: " v
                set_kv "$WEB_CONF" "WEB_PUBLIC_URL" "$v"
                green "已保存。"
                pause
                ;;
            9) web_url; pause ;;
            10)
                if state_collect; then
                    green "已刷新 ${STATE_STATUS_JSON}"
                else
                    red "采集失败。"
                fi
                pause
                ;;
            11) web_uninstall ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 非交互式 CLI（V2.0）
#
# 这一层有三个用途：
#   1. Web 面板唯一的写入通道——面板只允许调用这里显式列出的子命令，
#      参数由本文件自己校验，浏览器传进来的字符串永远不会被拼进 shell。
#   2. cron / 监控 / Telegram Bot 可以直接调，不用去解析菜单输出。
#   3. 排障时可以脚本化，比如批量给 20 台设备建客户端。
#
# 约定：
#   - 带 --json 时 stdout 只有 JSON，所有提示走 stderr
#   - 会改配置的子命令拿排他锁；只读/采集类不加锁
#   - 成功返回 0，失败返回非 0（方便 shell 里判断）
# ============================================================

cli_usage() {
    cat <<EOF
WireGuard Manager V${VERSION} — 非交互式命令行

用法：wgmgr <命令> [子命令] [参数] [--json]

状态 / 采集
  collect [--print]                刷新 state/status.json（--print 同时输出到 stdout）
  status [--json]                  接口与 Peer 概览
  dashboard [--refresh N]          终端实时仪表盘
  health [--json]                  Health Check（结构化结论 + 排查建议）
  traffic [--range 24h|7d|30d] [--by-peer] [--json]
  diagnose                         传统 ✓/✗ 系统诊断

Peer
  peer list [--kind client|site] [--status online|idle|offline|never|pending|disabled] [--json]
  peer show <name> [--json]

客户端
  client list [--json]
  client add <name> [--ip4 <a.b.c.d>] [--ip6 <addr>] [--allowed <cidr,...>] [--print-conf] [--json]
  client enable|disable|delete <name>
  client conf <name> [--qrcode|--png]
  client rotate-key <name> [--print-conf]

Site-to-Site
  site list [--json]
  site create <name> --remote-lan <cidr> --remote-wg-ip <ip> --remote-pubkey <key>
                     [--local-lan <cidr>] [--remote-endpoint <ip:port>]
                     [--mode routing|nat] [--keepalive <sec>] [--force]
  site enable|disable|delete <name>
  site test <name>

服务端 / 路由 / 防火墙 / 密钥
  server info [--json]
  server up|down|restart|rebuild
  route list [--json] | route add <name> <subnet> <via> [comment] | route delete <name>
  fw backend|show|sync|clean
  key rotate-server | key export-pubkeys

DDNS
  ddns check                        手动触发一次 DDNS 解析与端点更新
  ddns status                       查看 DDNS 变更历史

告警 / 备份 / 面板
  alert test | alert history
  backup create|list
  web install|start|stop|restart|status|logs|passwd [--user <name>] [--stdin]|url|uninstall
  uninstall

其他
  version | help

示例
  wgmgr peer list --json | jq '.peers[] | select(.status=="offline")'
  wgmgr client add iphone --allowed 0.0.0.0/0 --print-conf
  wgmgr site create branch-a --remote-lan 192.168.20.0/24 \\
        --remote-wg-ip 10.77.77.1 --remote-pubkey <key> --remote-endpoint 2.2.2.2:51820
  wgmgr status --json > /tmp/wg.json
EOF
}

# 打印 status.json 里的 peers 表格（非 JSON 模式）
_cli_peer_table() {
    local f="$STATE_STATUS_JSON"
    printf '%-18s %-8s %-16s %-10s %-8s %-9s %-9s\n' \
        "NAME" "KIND" "IP" "STATUS" "HS" "RX" "TX"
    printf '%-18s %-8s %-16s %-10s %-8s %-9s %-9s\n' \
        "------------------" "--------" "----------------" "----------" "--------" "---------" "---------"

    awk '
        function val(line, key,   s) {
            s = line; sub(".*\"" key "\": *", "", s)
            gsub(/^"|"$/, "", s); sub(/,$/, "", s); gsub(/"$/, "", s); return s
        }
        function human(b,   u, n, i) {
            b = b + 0; n = split("B K M G T P", u, " "); i = 1
            while (b >= 1024 && i < n) { b = b / 1024; i++ }
            if (i == 1) return sprintf("%d%s", b, u[i])
            return sprintf("%.1f%s", b, u[i])
        }
        function ago(s) {
            if (s == "null" || s == "") return "-"
            s = s + 0
            if (s < 60)    return s "s"
            if (s < 3600)  return int(s / 60) "m"
            if (s < 86400) return int(s / 3600) "h"
            return int(s / 86400) "d"
        }
        function flush() {
            if (id == "") return
            printf "%-18s %-8s %-16s %-10s %-8s %-9s %-9s\n", \
                id, kind, (ip == "" ? "-" : ip), st, ago(hs), human(rx), human(tx)
            id=""; kind=""; ip=""; st=""; hs=""; rx=0; tx=0
        }
        /"id":/                { flush(); id = val($0, "id") }
        /"kind":/              { kind = val($0, "kind") }
        /"vpn_ip4":/           { ip   = val($0, "vpn_ip4") }
        /"status":/            { st   = val($0, "status") }
        /"handshake_ago_sec":/ { hs   = val($0, "handshake_ago_sec") }
        /"rx_bytes":/          { rx   = val($0, "rx_bytes") + 0 }
        /"tx_bytes":/          { tx   = val($0, "tx_bytes") + 0 }
        END { flush() }
    ' "$f"
}

# 从 status.json 里取一个顶层/嵌套对象的子集输出。用 python3 做，
# 因为目标机器不一定有 jq；没有 python3 时退化成输出整份 status.json
# （是个超集，消费方按需取字段），并在 stderr 说明。
_cli_json_subset() {
    local expr="$1"
    if command_exists python3; then
        python3 -c '
import json, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
print(json.dumps(eval(sys.argv[2], {"__builtins__": {}}, {"d": data}), ensure_ascii=False, indent=2))
' "$STATE_STATUS_JSON" "$expr"
    else
        yellow "系统没有 python3，输出整份 status.json（是所请求字段的超集）。" >&2
        cat "$STATE_STATUS_JSON"
    fi
}

cli_collect() {
    local do_print="no"
    [[ "${1-}" == "--print" ]] && do_print="yes"

    state_collect || { red "采集失败。"; return 1; }
    if [[ "$do_print" == "yes" ]]; then
        cat "$STATE_STATUS_JSON"
    else
        green "已刷新 ${STATE_STATUS_JSON}"
    fi
    return 0
}

cli_status() {
    state_collect >/dev/null 2>&1 || true

    if [[ "$JSON_MODE" == "yes" ]]; then
        cat "$STATE_STATUS_JSON"
        return 0
    fi

    dash_render
    return 0
}

cli_peer_list() {
    local kind="" status_filter=""
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --kind)   kind="${2-}";   shift 2 ;;
            --status) status_filter="${2-}"; shift 2 ;;
            *) red "未知参数：$1"; return 2 ;;
        esac
    done

    state_collect >/dev/null 2>&1 || true

    if [[ "$JSON_MODE" == "yes" ]]; then
        if command_exists python3; then
            WGM_K="$kind" WGM_S="$status_filter" python3 -c '
import json, os, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
k = os.environ.get("WGM_K", "")
s = os.environ.get("WGM_S", "")
peers = [p for p in data.get("peers", [])
         if (not k or p.get("kind") == k) and (not s or p.get("status") == s)]
print(json.dumps({"peers": peers, "count": len(peers)}, ensure_ascii=False, indent=2))
' "$STATE_STATUS_JSON"
        else
            yellow "系统没有 python3，无法按 --kind/--status 过滤，输出整份 status.json。" >&2
            cat "$STATE_STATUS_JSON"
        fi
        return 0
    fi

    if [[ -n "$kind" || -n "$status_filter" ]]; then
        yellow "提示：过滤条件只在 --json 模式下生效，下面是完整列表。"
    fi
    _cli_peer_table
    return 0
}

cli_peer_show() {
    local name="${1-}"
    [[ -z "$name" ]] && { red "用法：wgmgr peer show <name>"; return 2; }

    state_collect >/dev/null 2>&1 || true

    if [[ "$JSON_MODE" == "yes" ]]; then
        command_exists python3 || { red "需要 python3。"; return 1; }
        WGM_N="$name" python3 -c '
import json, os, sys
with open(sys.argv[1]) as f:
    data = json.load(f)
n = os.environ["WGM_N"]
for p in data.get("peers", []):
    if p.get("id") == n:
        print(json.dumps(p, ensure_ascii=False, indent=2)); sys.exit(0)
sys.stderr.write("找不到 Peer: %s\n" % n); sys.exit(1)
' "$STATE_STATUS_JSON"
        return $?
    fi

    show_peer_detail "$name"
    return 0
}

cli_client_add() {
    local name="" ip4="" ip6="" allowed="" print_conf="no"
    name="${1-}"; [[ -n "$name" ]] && shift
    [[ -z "$name" ]] && { red "用法：wgmgr client add <name> [--ip4 ..] [--allowed ..]"; return 2; }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --ip4)        ip4="${2-}";        shift 2 ;;
            --ip6)        ip6="${2-}";        shift 2 ;;
            --allowed)    allowed="${2-}";    shift 2 ;;
            --print-conf) print_conf="yes";   shift ;;
            *) red "未知参数：$1"; return 2 ;;
        esac
    done

    [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] || { red "名称只能包含字母、数字、下划线、短横线。"; return 2; }
    [[ -f "$WG_CONFIG" ]] || { red "服务端尚未初始化。"; return 1; }
    [[ -d "$(client_dir_for "$name")" ]] && { red "客户端 ${name} 已存在。"; return 1; }

    if [[ -z "$ip4" ]]; then
        ip4=$(get_next_client_ip4) || { red "没有可用的 IPv4 地址。"; return 1; }
    else
        is_valid_ipv4 "$ip4" || { red "IPv4 地址格式不正确：${ip4}"; return 2; }
        if grep -qx "$ip4" <<< "$(all_used_ip4)"; then
            red "IPv4 地址 ${ip4} 已被占用。"
            return 1
        fi
    fi

    if [[ -z "$allowed" ]]; then
        allowed="0.0.0.0/0"
    fi

    if [[ -z "$ip6" && "$(get_config USE_IPV6)" == "yes" ]]; then
        ip6=$(get_next_client_ip6) || ip6=""
    fi

    acquire_lock exclusive || return 1
    backup_snapshot "before_client_${name}" >/dev/null

    client_provision "$name" "$ip4" "$ip6" "$allowed" || return 1

    if ! rebuild_server_config; then
        red "服务端配置生成失败，客户端元数据已保留。"
        return 1
    fi

    log_action "CLIENT_ADD ${name} ip4=${ip4} via=cli"

    if [[ "$print_conf" == "yes" ]]; then
        cat "$CLIENT_CONF_PATH"
    elif [[ "$JSON_MODE" == "yes" ]]; then
        printf '{"name":"%s","ip4":"%s","ip6":"%s","public_key":"%s","conf_path":"%s"}\n' \
            "$name" "$ip4" "$ip6" "$CLIENT_PUB" "$CLIENT_CONF_PATH"
    else
        green "客户端 ${name} 已创建：${ip4}"
        echo "配置文件：${CLIENT_CONF_PATH}"
    fi
    return 0
}

cli_client_toggle() {
    local action="$1" name="${2-}"
    [[ -z "$name" ]] && { red "用法：wgmgr client ${action} <name>"; return 2; }

    local cdir="${CLIENTS_DIR}/${name}"
    [[ -f "${cdir}/meta.conf" ]] || { red "客户端不存在：${name}"; return 1; }

    acquire_lock exclusive || return 1

    local target="no"
    [[ "$action" == "enable" ]] && target="yes"
    set_kv "${cdir}/meta.conf" "ENABLED" "$target"

    rebuild_server_config || return 1
    log_action "CLIENT_TOGGLE ${name} -> ${target} via=cli"
    green "客户端 ${name} 已$( [[ "$target" == "yes" ]] && echo 启用 || echo 禁用 )。"
    return 0
}

cli_client_delete() {
    local name="${1-}"
    [[ -z "$name" ]] && { red "用法：wgmgr client delete <name>"; return 2; }

    local cdir="${CLIENTS_DIR}/${name}"
    [[ -f "${cdir}/meta.conf" ]] || { red "客户端不存在：${name}"; return 1; }

    acquire_lock exclusive || return 1
    backup_snapshot "before_delete_client_${name}" >/dev/null

    rm -rf "$cdir"
    rebuild_server_config || return 1
    log_action "CLIENT_DELETE ${name} via=cli"
    green "客户端 ${name} 已删除。"
    return 0
}

cli_client_conf() {
    local name="${1-}" fmt="text"
    [[ -z "$name" ]] && { red "用法：wgmgr client conf <name> [--qrcode|--png]"; return 2; }
    case "${2-}" in
        --qrcode) fmt="ansi" ;;
        --png)    fmt="png" ;;
        "")       fmt="text" ;;
        *)        red "用法：wgmgr client conf <name> [--qrcode|--png]"; return 2 ;;
    esac

    local cconf="${CLIENTS_DIR}/${name}/${name}.conf"
    [[ -f "$cconf" ]] || { red "客户端不存在：${name}"; return 1; }

    case "$fmt" in
        png)
            # Web 面板的"查看二维码"走这里：把 PNG 字节流原样吐到 stdout，
            # 由面板直接当 image/png 转发。刻意不在 Python 里自己实现 QR 编码
            # ——掩码/纠错任何一个细节写错，图能画出来但扫不出来，而且这种错
            # 在没有真机扫码的环境下根本验证不了。qrencode 本来就是依赖之一。
            command_exists qrencode || { red "未安装 qrencode。" >&2; return 1; }
            qrencode -t PNG -s 6 -m 2 -o - < "$cconf"
            ;;
        ansi)
            command_exists qrencode || { red "未安装 qrencode。"; return 1; }
            qrencode -t ANSIUTF8 < "$cconf"
            ;;
        *)
            cat "$cconf"
            ;;
    esac
    return 0
}

cli_site_create() {
    local name="" local_lan="" remote_lan="" remote_wg_ip="" remote_endpoint=""
    local remote_pubkey="" mode="" keepalive="25" force="no"

    name="${1-}"; [[ -n "$name" ]] && shift
    [[ -z "$name" ]] && { red "用法：wgmgr site create <name> --remote-lan .. --remote-wg-ip .. --remote-pubkey .."; return 2; }

    while [[ $# -gt 0 ]]; do
        case "$1" in
            --local-lan)       local_lan="${2-}";       shift 2 ;;
            --remote-lan)      remote_lan="${2-}";      shift 2 ;;
            --remote-wg-ip)    remote_wg_ip="${2-}";    shift 2 ;;
            --remote-endpoint) remote_endpoint="${2-}"; shift 2 ;;
            --remote-pubkey)   remote_pubkey="${2-}";   shift 2 ;;
            --mode)            mode="${2-}";            shift 2 ;;
            --keepalive)       keepalive="${2-}";       shift 2 ;;
            --force)           force="yes";             shift ;;
            *) red "未知参数：$1"; return 2 ;;
        esac
    done

    [[ "$name" =~ ^[A-Za-z0-9_-]+$ ]] || { red "名称只能包含字母、数字、下划线、短横线。"; return 2; }
    [[ -f "$WG_CONFIG" ]] || { red "服务端尚未初始化。"; return 1; }
    [[ -d "$(site_dir_for "$name")" ]] && { red "站点 ${name} 已存在。"; return 1; }

    [[ -n "$remote_lan" && -n "$remote_wg_ip" && -n "$remote_pubkey" ]] || {
        red "--remote-lan / --remote-wg-ip / --remote-pubkey 为必填项。"; return 2; }

    is_valid_wg_key "$remote_pubkey" || { red "对端公钥格式不合法（应为 44 位以 = 结尾）。"; return 2; }
    is_valid_ipv4 "$remote_lan"  || { red "--remote-lan 格式不正确。"; return 2; }
    is_valid_ipv4 "$remote_wg_ip" || { red "--remote-wg-ip 格式不正确。"; return 2; }
    [[ -n "$local_lan" ]] && { is_valid_ipv4 "$local_lan" || { red "--local-lan 格式不正确。"; return 2; }; }
    [[ "$keepalive" =~ ^[0-9]+$ ]] || { red "--keepalive 必须是整数。"; return 2; }

    if [[ -n "$remote_endpoint" ]]; then
        [[ "$remote_endpoint" =~ ^[A-Za-z0-9._:-]+:[0-9]{1,5}$ ]] || {
            red "--remote-endpoint 格式应为 IP或域名:端口，例如 2.2.2.2:51820"; return 2; }
    fi

    local vpn_net4 rc
    vpn_net4=$(get_config VPN_NETWORK4)

    site_check_conflicts "$local_lan" "$remote_lan" "$vpn_net4"
    rc=$?
    if (( rc != 0 )); then
        if [[ "$force" != "yes" ]]; then
            red "检测到网段冲突（code=${rc}），已拒绝创建。"
            yellow "确认理解风险后可加 --force 强制创建，此时会以「仅 VPN IP 互通」"
            yellow "的降级模式落盘（mode=conflict），不会路由整个 LAN 网段。"
            return 1
        fi
        mode="conflict"
        yellow "已按 --force 降级为 mode=conflict（仅 VPN IP 互通）。"
    elif [[ -z "$mode" ]]; then
        # 默认纯路由：站点之间不做 MASQUERADE，这是官方推荐的 Site-to-Site 形态
        mode="routing"
    fi

    case "$mode" in
        routing|nat|conflict) ;;
        *) red "--mode 只能是 routing / nat / conflict。"; return 2 ;;
    esac

    acquire_lock exclusive || return 1
    site_commit "$name" "$local_lan" "$remote_lan" "$remote_wg_ip" \
                "$remote_endpoint" "$remote_pubkey" "$mode" "$keepalive" || return 1
    return 0
}

cli_route() {
    local action="${1-}"
    shift || true

    case "$action" in
        list)
            state_collect >/dev/null 2>&1 || true
            if [[ "$JSON_MODE" == "yes" ]]; then
                _cli_json_subset '{"routes": d.get("routes", []), "kernel_routes": d.get("kernel_routes", [])}'
            else
                printf '%-18s %-20s %-18s %s\n' "NAME" "SUBNET" "VIA" "COMMENT"
                if [[ -s "$ROUTES_CONF" ]]; then
                    local rname rsubnet rvia rcomment
                    while IFS='|' read -r rname rsubnet rvia rcomment; do
                        [[ -z "$rname" ]] && continue
                        printf '%-18s %-20s %-18s %s\n' "$rname" "$rsubnet" "$rvia" "${rcomment-}"
                    done < "$ROUTES_CONF"
                else
                    echo "（无静态路由）"
                fi
                echo
                echo "内核里 ${WG_INTERFACE} 的路由："
                ip route show dev "$WG_INTERFACE" 2>/dev/null || echo "  （接口未运行）"
            fi
            ;;
        add)
            local rname="${1-}" rsubnet="${2-}" rvia="${3-}" rcomment="${4-}"
            [[ -z "$rname" || -z "$rsubnet" || -z "$rvia" ]] && {
                red "用法：wgmgr route add <name> <subnet> <via> [comment]"; return 2; }
            is_valid_ipv4 "$rsubnet" || { red "目标网段格式不正确。"; return 2; }
            is_valid_ipv4 "$rvia"    || { red "下一跳格式不正确。"; return 2; }
            [[ "$rname" =~ ^[A-Za-z0-9_-]+$ ]] || { red "名称只能包含字母、数字、下划线、短横线。"; return 2; }
            grep -q "^${rname}|" "$ROUTES_CONF" 2>/dev/null && { red "同名路由已存在。"; return 1; }

            acquire_lock exclusive || return 1
            backup_snapshot "before_add_route_${rname}" >/dev/null
            echo "${rname}|${rsubnet}|${rvia}|${rcomment}" >> "$ROUTES_CONF"
            chmod 600 "$ROUTES_CONF"
            rebuild_server_config || return 1
            ip route replace "$rsubnet" via "$rvia" dev "$WG_INTERFACE" 2>/dev/null || true
            log_action "ROUTE_ADD ${rname} ${rsubnet} via ${rvia} via=cli"
            green "路由已添加并生效：${rsubnet} via ${rvia}"
            ;;
        delete|del)
            local rname="${1-}" rsubnet rvia
            [[ -z "$rname" ]] && { red "用法：wgmgr route delete <name>"; return 2; }
            grep -q "^${rname}|" "$ROUTES_CONF" 2>/dev/null || { red "路由不存在。"; return 1; }
            rsubnet=$(grep "^${rname}|" "$ROUTES_CONF" | cut -d'|' -f2)
            rvia=$(grep "^${rname}|" "$ROUTES_CONF" | cut -d'|' -f3)

            acquire_lock exclusive || return 1
            backup_snapshot "before_del_route_${rname}" >/dev/null
            sed -i "/^${rname}|/d" "$ROUTES_CONF"
            rebuild_server_config || return 1
            ip route del "$rsubnet" via "$rvia" dev "$WG_INTERFACE" 2>/dev/null || true
            log_action "ROUTE_DELETE ${rname} via=cli"
            green "路由已删除。"
            ;;
        *)
            red "用法：wgmgr route list|add|delete"
            return 2
            ;;
    esac
    return 0
}

cli_server() {
    local action="${1-}"
    case "$action" in
        info)
            if [[ "$JSON_MODE" == "yes" ]]; then
                state_collect >/dev/null 2>&1 || true
                _cli_json_subset '{"interface": d.get("interface", {}), "system": d.get("system", {})}'
            else
                echo "接口        : ${WG_INTERFACE}"
                echo "运行状态    : $( wg_is_up && echo RUNNING || echo STOPPED )"
                echo "端口        : UDP $(get_config WG_PORT)"
                echo "VPN IPv4    : $(get_config VPN_NETWORK4)"
                echo "服务器 IPv4 : $(get_config SERVER_IP4)"
                if [[ "$(get_config USE_IPV6)" == "yes" ]]; then
                    echo "VPN IPv6    : $(get_config VPN_NETWORK6)"
                    echo "服务器 IPv6 : $(get_config SERVER_IP6)"
                fi
                echo "Endpoint    : $(get_config ENDPOINT)"
                echo "公网网卡    : $(get_config WAN_INTERFACE)"
                echo "MTU         : $(get_config MTU)"
                echo "Internet NAT: $( [[ "$(get_config INTERNET_NAT)" == "no" ]] && echo "关闭" || echo "开启" )"
                echo "防火墙后端  : $(fw_detect_backend)"
                echo "服务器公钥  : $(get_server_public_key)"
            fi
            ;;
        up)      acquire_lock exclusive && wg_up ;;
        down)    acquire_lock exclusive && wg_down ;;
        restart) acquire_lock exclusive && wg_restart ;;
        rebuild) acquire_lock exclusive && rebuild_server_config ;;
        *) red "用法：wgmgr server info|up|down|restart|rebuild"; return 2 ;;
    esac
}

cli_fw() {
    local action="${1-}"
    case "$action" in
        backend) fw_detect_backend ;;
        show)
            local backend; backend=$(fw_detect_backend)
            echo "防火墙后端：${backend}"
            echo
            case "$backend" in
                nftables)
                    nft list table inet wg_manager 2>/dev/null || echo "（inet wg_manager 表不存在）"
                    nft list table ip wg_manager_nat 2>/dev/null || true
                    nft list table ip6 wg_manager_nat6 2>/dev/null || true
                    ;;
                ufw)
                    ufw status verbose 2>/dev/null || true
                    ;;
                iptables|*)
                    iptables -S 2>/dev/null | grep -F "$FW_TAG" || echo "（无带 ${FW_TAG} 标签的规则）"
                    echo
                    iptables -t nat -S 2>/dev/null | grep -F "$FW_TAG" || true
                    ;;
            esac
            ;;
        sync)  acquire_lock exclusive && fw_sync_state && green "防火墙已按当前状态重新同步。" ;;
        clean) acquire_lock exclusive && fw_cleanup_all ;;
        *) red "用法：wgmgr fw backend|show|sync|clean"; return 2 ;;
    esac
}

cli_key() {
    local action="${1-}"
    case "$action" in
        export-pubkeys)
            local mdir name pubkey
            for mdir in "$CLIENTS_DIR"/*/; do
                [[ -f "${mdir}meta.conf" ]] || continue
                load_meta "${mdir}meta.conf"
                name=$(meta NAME); pubkey=$(meta PUBLIC_KEY)
                printf '%-18s %s\n' "$name" "$pubkey"
            done
            ;;
        rotate-server)
            red "警告：轮换服务器密钥会让所有已下发的客户端配置失效，需要重新分发。"
            [[ "$RUN_MODE" == "interactive" ]] || {
                yellow "非交互模式下拒绝执行此操作，请显式加 --yes 确认。"
                return 1
            }
            ;;
        *) red "用法：wgmgr key export-pubkeys|rotate-server"; return 2 ;;
    esac
}

cli_web() {
    local action="${1-}"; shift || true
    case "$action" in
        install)   web_install ;;
        start)     web_ctl start ;;
        stop)      web_ctl stop ;;
        restart)   web_ctl restart ;;
        status)    web_ctl status ;;
        logs)      web_ctl logs ;;
        url)       web_url ;;
        uninstall) web_uninstall ;;
        passwd)
            local user="" use_stdin="no"
            while [[ $# -gt 0 ]]; do
                case "$1" in
                    --user)  user="${2-}"; shift 2 ;;
                    --stdin) use_stdin="yes"; shift ;;
                    *) red "未知参数：$1"; return 2 ;;
                esac
            done
            if [[ "$use_stdin" == "yes" ]]; then
                web_passwd "$user" < /dev/stdin
            else
                web_passwd "$user"
            fi
            ;;
        *) red "用法：wgmgr web install|start|stop|restart|status|logs|passwd|url|uninstall"; return 2 ;;
    esac
}

cli_dispatch() {
    local cmd="${1-}"
    [[ -n "$cmd" ]] && shift

    # 全局开关先扫一遍，剩下的按位置参数交给各子命令
    local -a rest=()
    local arg
    for arg in "$cmd" "$@"; do
        case "$arg" in
            --json) JSON_MODE="yes" ;;
            *)      rest+=("$arg") ;;
        esac
    done
    set -- ${rest+"${rest[@]}"}

    cmd="${1-}"
    [[ -n "$cmd" ]] && shift

    RUN_MODE="cli"

    case "$cmd" in
        help|-h|--help)   cli_usage; return 0 ;;
        version|-v|--version) echo "$VERSION"; return 0 ;;

        collect)   cli_collect "$@" ;;
        status)    cli_status "$@" ;;
        dashboard) dash_render; return 0 ;;
        diagnose)  diagnostic; return 0 ;;
        health)
            state_collect >/dev/null 2>&1 || true
            if [[ "$JSON_MODE" == "yes" ]]; then
                web_python wgm_health.py check --json
            else
                web_python wgm_health.py check --pretty
            fi
            ;;
        traffic)
            if [[ "$JSON_MODE" == "yes" ]]; then
                web_python wgm_traffic.py report "$@" --json
            else
                web_python wgm_traffic.py report "$@"
            fi
            ;;

        peer)
            local sub="${1-}"; shift || true
            case "$sub" in
                list) cli_peer_list "$@" ;;
                show) cli_peer_show "$@" ;;
                *) red "用法：wgmgr peer list|show <name>"; return 2 ;;
            esac
            ;;

        client)
            local sub="${1-}"; shift || true
            case "$sub" in
                list)
                    state_collect >/dev/null 2>&1 || true
                    if [[ "$JSON_MODE" == "yes" ]]; then
                        cli_peer_list --kind client --json
                    else
                        list_clients
                    fi
                    ;;
                add)        cli_client_add "$@" ;;
                enable)     cli_client_toggle enable  "$@" ;;
                disable)    cli_client_toggle disable "$@" ;;
                delete)     cli_client_delete "$@" ;;
                conf)       cli_client_conf "$@" ;;
                rotate-key)
                    local name="${1-}"
                    [[ -z "$name" ]] && { red "用法：wgmgr client rotate-key <name>"; return 2; }
                    acquire_lock exclusive || return 1
                    rotate_client_key_noninteractive "$name"
                    ;;
                *) red "用法：wgmgr client list|add|enable|disable|delete|conf|rotate-key"; return 2 ;;
            esac
            ;;

        site)
            local sub="${1-}"; shift || true
            case "$sub" in
                list)
                    state_collect >/dev/null 2>&1 || true
                    if [[ "$JSON_MODE" == "yes" ]]; then
                        cli_peer_list --kind site --json
                    else
                        list_sites
                    fi
                    ;;
                create)  cli_site_create "$@" ;;
                enable)  _cli_site_toggle yes "$@" ;;
                disable) _cli_site_toggle no  "$@" ;;
                delete)  _cli_site_delete "$@" ;;
                test)    _cli_site_test "$@" ;;
                *) red "用法：wgmgr site list|create|enable|disable|delete|test"; return 2 ;;
            esac
            ;;

        ddns)
            local sub="${1-}"; shift || true
            case "$sub" in
                check)  web_python wgm_ddns.py --check ;;
                status) web_python wgm_ddns.py --status ;;
                *) red "用法：wgmgr ddns check|status"; return 2 ;;
            esac
            ;;
        route)  cli_route "$@" ;;
        server) cli_server "$@" ;;
        fw)     cli_fw "$@" ;;
        key)    cli_key "$@" ;;
        web)    cli_web "$@" ;;

        alert)
            local sub="${1-}"; shift || true
            case "$sub" in
                test)    web_python wgm_alert.py test ;;
                history) web_python wgm_alert.py history ;;
                *) red "用法：wgmgr alert test|history"; return 2 ;;
            esac
            ;;

        backup)
            local sub="${1-}"; shift || true
            case "$sub" in
                create) backup_config ;;
                list)   list_backups ;;
                *) red "用法：wgmgr backup create|list"; return 2 ;;
            esac
            ;;

        uninstall)
            red "非交互模式下拒绝直接卸载，请运行交互式菜单：wgmgr"
            return 1
            ;;

        "")
            red "缺少命令。"
            cli_usage >&2
            return 2
            ;;
        *)
            red "未知命令：${cmd}"
            cli_usage >&2
            return 2
            ;;
    esac
}

# ---- 站点相关的几个小 CLI 实现（复用交互式函数里的落盘逻辑）----

_cli_site_toggle() {
    local target="$1" name="${2-}"
    [[ -z "$name" ]] && { red "用法：wgmgr site enable|disable <name>"; return 2; }

    local sdir="${SITES_DIR}/${name}"
    [[ -f "${sdir}/meta.conf" ]] || { red "站点不存在：${name}"; return 1; }

    acquire_lock exclusive || return 1
    set_kv "${sdir}/meta.conf" "ENABLED" "$target"
    rebuild_server_config || return 1
    log_action "SITE_TOGGLE ${name} -> ${target} via=cli"
    green "站点 ${name} 已$( [[ "$target" == "yes" ]] && echo 启用 || echo 禁用 )。"
}

_cli_site_delete() {
    local name="${1-}"
    [[ -z "$name" ]] && { red "用法：wgmgr site delete <name>"; return 2; }

    local sdir="${SITES_DIR}/${name}"
    [[ -f "${sdir}/meta.conf" ]] || { red "站点不存在：${name}"; return 1; }

    acquire_lock exclusive || return 1
    backup_snapshot "before_delete_site_${name}" >/dev/null
    rm -rf "$sdir"
    rebuild_server_config || return 1
    log_action "SITE_DELETE ${name} via=cli"
    green "站点 ${name} 已删除，对应的 LAN 转发/NAT 规则已随之清理。"
}

_cli_site_test() {
    local name="${1-}"
    [[ -z "$name" ]] && { red "用法：wgmgr site test <name>"; return 2; }

    local sdir="${SITES_DIR}/${name}"
    [[ -f "${sdir}/meta.conf" ]] || { red "站点不存在：${name}"; return 1; }

    load_meta "${sdir}/meta.conf"
    local remote_ip remote_lan remote_pub
    remote_ip=$(meta REMOTE_WG_IP)
    remote_lan=$(meta REMOTE_LAN)
    remote_pub=$(meta REMOTE_PUBLIC_KEY)

    echo "站点：${name}"
    echo "对端 VPN IP：${remote_ip}"
    echo
    echo "--- ping 对端 VPN IP ---"
    ping -c 4 -W 2 "$remote_ip" || yellow "无法 ping 通，请检查对端是否已配置对称的 Peer。"

    if [[ -n "$remote_lan" ]]; then
        local gw="${remote_lan%.*/*}.1"
        echo
        echo "--- ping 对端 LAN 网关（猜测为 ${gw}，仅供参考）---"
        ping -c 2 -W 2 "$gw" 2>/dev/null || true
    fi

    echo
    echo "--- WireGuard 握手 / 流量 ---"
    wg show "$WG_INTERFACE" 2>/dev/null | grep -A4 "$remote_pub" || yellow "  （该 Peer 不在运行中的配置里）"
}

# rotate_client_key 的交互式版本会 read 确认，CLI 里不能那样，
# 单独实现一份：确认由调用方（人或面板的二次确认弹窗）负责。
rotate_client_key_noninteractive() {
    local name="$1"
    local cdir="${CLIENTS_DIR}/${name}"

    [[ -f "${cdir}/meta.conf" ]] || { red "客户端不存在：${name}"; return 1; }

    backup_snapshot "before_rotate_client_${name}" >/dev/null

    local new_priv new_pub
    new_priv=$(umask 077; wg genkey)
    new_pub=$(echo "$new_priv" | wg pubkey)

    echo "$new_priv" > "${cdir}/private.key"
    echo "$new_pub"  > "${cdir}/public.key"
    chmod 600 "${cdir}/private.key" "${cdir}/public.key"

    set_kv "${cdir}/meta.conf" "PUBLIC_KEY" "$new_pub"

    local cconf="${cdir}/${name}.conf"
    [[ -f "$cconf" ]] && sed -i "s#^PrivateKey = .*#PrivateKey = ${new_priv}#" "$cconf"

    rebuild_server_config || return 1
    log_action "ROTATE_CLIENT_KEY ${name} via=cli"

    green "客户端 ${name} 密钥已轮换，请重新分发配置："
    echo "------------------------------------------"
    cat "$cconf"
    echo "------------------------------------------"
}

# ============================================================
# 主菜单
# ============================================================

backup_restore_menu() {
    while true; do
        clear
        bold "=========================================="
        bold "              备份 / 恢复"
        bold "=========================================="
        echo
        echo "  1. 立即做一次完整备份（tar.gz，含全部密钥/配置）"
        echo "  2. 从完整备份恢复"
        echo "  3. 从自动快照回滚（改配置前自动打的轻量快照）"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) backup_config ;;
            2) restore_backup ;;
            3) restore_snapshot ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# 主菜单标题栏要显示实时的运行状态和在线计数，但 state_collect 每次要 fork
# 几十个子进程。菜单每画一次就重采一次，在客户端多的机器上会有明显的卡顿感，
# 所以加一个"3 秒内复用上次结果"的节流：既保证你从子菜单退回来看到的数字
# 是新的，又不会让菜单本身变慢。
_menu_state_fresh() {
    local f="$STATE_STATUS_JSON"
    [[ -f "$f" ]] || return 1
    local now mtime age
    now=$(date +%s)
    mtime=$(stat -c %Y "$f" 2>/dev/null || echo 0)
    age=$(( now - mtime ))
    (( age >= 0 && age < 3 ))
}

_menu_header() {
    _menu_state_fresh || state_collect >/dev/null 2>&1 || true

    local f="$STATE_STATUS_JSON"
    local running online idle offline total web_on
    running=$(_json_field "$f" running)
    online=$(_json_field "$f" online)
    idle=$(_json_field "$f" idle)
    offline=$(_json_field "$f" offline)
    total=$(_json_field "$f" peers_total)
    web_on=$(get_kv "$WEB_CONF" WEB_ENABLED 2>/dev/null)

    bold "╔══════════════════════════════════════════════════════╗"
    printf '\033[1m║          WireGuard Manager  V%-22s║\033[0m\n' "$VERSION"
    bold "║          Debian / Ubuntu                             ║"
    bold "╠══════════════════════════════════════════════════════╣"

    if [[ ! -f "$WG_CONFIG" ]]; then
        bold "║  接口: 尚未配置                                      ║"
    elif [[ "$running" == "true" ]]; then
        printf '\033[1m║  接口: \033[32mRUNNING\033[0m\033[1m  Peer %s/%s 在线\033[0m\033[1m%-17s║\033[0m\n' \
            "${online:-0}" "${total:-0}" "  空闲${idle:-0} 离线${offline:-0}"
    else
        printf '\033[1m║  接口: \033[31mSTOPPED\033[0m\033[1m%-40s║\033[0m\n' ""
    fi

    if [[ "$web_on" == "yes" ]]; then
        printf '\033[1m║  面板: \033[36m%s\033[0m\033[1m%-40s║\033[0m\n' \
            "$(get_kv "$WEB_CONF" WEB_LISTEN 2>/dev/null)" ""
    fi

    bold "╠══════════════════════════════════════════════════════╣"
}

main_menu() {

    while true; do
        clear
        _menu_header
        echo "║                                                      ║"
        echo "║   1. Dashboard / 实时状态                            ║"
        echo "║   2. 服务端                                          ║"
        echo "║   3. 客户端                                          ║"
        echo "║   4. Site-to-Site                                    ║"
        echo "║   5. Peer / 连接                                     ║"
        echo "║   6. 路由                                            ║"
        echo "║   7. 防火墙 / NAT                                    ║"
        echo "║   8. 密钥                                            ║"
        echo "║   9. 流量统计                                        ║"
        echo "║  10. 诊断 / Health Check                             ║"
        echo "║  11. 备份 / 恢复                                     ║"
        echo "║  12. Web 面板                                        ║"
        echo "║  13. 系统 / 日志                                     ║"
        echo "║  14. 高级设置                                        ║"
        echo "║                                                      ║"
        echo "║   0. 退出                                            ║"
        echo "║                                                      ║"
        bold "╚══════════════════════════════════════════════════════╝"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1)  dashboard_menu ;;
            2)  server_menu ;;
            3)  client_menu ;;
            4)  site_to_site_menu ;;
            5)  peer_status_menu ;;
            6)  routing_menu ;;
            7)  firewall_menu ;;
            8)  key_management_menu ;;
            9)  traffic_menu ;;
            10) health_menu ;;
            11) backup_restore_menu ;;
            12) web_menu ;;
            13) system_menu ;;
            14) advanced_menu ;;
            0) clear; green "感谢使用 WireGuard Manager。"; exit 0 ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# 系统 / 日志：把"这台机器现在是什么环境、状态层有没有在正常刷新、
# 两个 systemd 服务活着没有、最近改过什么"集中在一处，
# 排障时不用在 journalctl / ls / tail 之间来回切。
system_menu() {
    while true; do
        clear
        bold "=========================================="
        bold "              系统 / 日志"
        bold "=========================================="
        echo
        echo "  1. 系统环境（发行版 / 网卡 / 公网 IP / 虚拟化）"
        echo "  2. 操作日志（最近 50 条）"
        echo "  3. 状态层文件（state/*.json 是否存在、多久之前刷新）"
        echo "  4. 服务状态（wg-quick / collector / web）"
        echo "  0. 返回"
        echo

        read -rp "请选择: " choice
        case "$choice" in
            1) show_environment ;;
            2)
                clear
                bold "最近 50 条操作日志："
                echo
                tail -n 50 "${LOG_DIR}/manager.log" 2>/dev/null || yellow "暂无日志。"
                pause
                ;;
            3)
                clear
                bold "状态层（${STATE_DIR}）"
                echo
                local f mtime age now
                now=$(date +%s)
                for f in "$STATE_STATUS_JSON" "$STATE_HEALTH_JSON" "$STATE_ALERTS_JSON" "$STATE_TRAFFIC_JSON"; do
                    if [[ -f "$f" ]]; then
                        mtime=$(stat -c %Y "$f" 2>/dev/null || echo "$now")
                        age=$(( now - mtime ))
                        # human_ago 吃的是 epoch，不是时长——这里传 mtime，
                        # age 只用于下面"是否太久没刷新"的判断。
                        printf '  %-24s %8s 字节  %s刷新\n' \
                            "$(basename "$f")" "$(stat -c %s "$f" 2>/dev/null)" "$(human_ago "$mtime")"
                        if (( age > 300 )); then
                            yellow "    ↑ 超过 5 分钟没刷新，采集服务可能没在跑（菜单 12 -> 服务状态）"
                        fi
                    else
                        printf '  %-24s （不存在）\n' "$(basename "$f")"
                    fi
                done
                echo
                local n
                n=$(find "$TRAFFIC_DIR" -name '*.json' 2>/dev/null | wc -l)
                echo "  流量采样文件：${n} 个（${TRAFFIC_DIR}）"
                pause
                ;;
            4)
                clear
                bold "服务状态"
                echo
                local svc
                for svc in "wg-quick@${WG_INTERFACE}" "$COLLECTOR_SERVICE" "$WEB_SERVICE"; do
                    if command_exists systemctl; then
                        printf '  %-36s %s\n' "$svc" "$(systemctl is-active "$svc" 2>/dev/null || echo unknown)"
                    else
                        printf '  %-36s %s\n' "$svc" "（无 systemd）"
                    fi
                done
                echo
                if command_exists systemctl; then
                    echo "----- collector 最近 10 行日志 -----"
                    journalctl -u "$COLLECTOR_SERVICE" -n 10 --no-pager 2>/dev/null || echo "（无）"
                    echo
                    echo "----- web 最近 10 行日志 -----"
                    journalctl -u "$WEB_SERVICE" -n 10 --no-pager 2>/dev/null || echo "（无）"
                fi
                pause
                ;;
            0) green "已返回。"; sleep 1; return ;;
            *) yellow "无效选择。"; sleep 1 ;;
        esac
    done
}

# ============================================================
# 启动
# ============================================================
#
# 带参数 = 非交互式 CLI；不带参数 = 交互式菜单。
# 这不是两个"入口"，而是同一套核心逻辑的两张脸：菜单里能做的事，
# 几乎都能在 CLI 里用一条命令做完，而 Web 面板只会调用 CLI —— 它自己
# 一行 wg / iptables 都不碰。这样任何一条配置变更路径最终都收敛到
# 同一批函数上，不会出现"网页改了但脚本不知道"的分叉。

# RUN_MODE 必须在最前面就定下来：下面 require_root / check_os /
# init_directories 里都有 confirm，CLI 下它们必须走默认值而不是等 stdin。
if [[ $# -gt 0 ]]; then
    RUN_MODE="cli"
fi

require_root
check_os
init_directories

if [[ $# -gt 0 ]]; then
    # 迁移是幂等的、且只在存在 V1.0 遗留文件时才动手，CLI 下也要跑：
    # 否则一台只用自动化方式管理的机器永远升不上来。
    migrate_legacy_v1

    # 刻意不在 CLI 下跑 check_dependencies —— 它会调 apt-get 装包。
    # 采集守护进程每 30 秒拉起一次本脚本，绝不能有一次因为缺 qrencode
    # 就在后台默默 apt install。缺依赖这件事应该由人在交互菜单里决定。
    if ! command_exists wg; then
        red "未找到 wg 命令，请先运行交互式菜单安装依赖：wgmgr" >&2
        exit 1
    fi

    saved_interface=$(get_config WG_INTERFACE)
    if [[ -n "$saved_interface" ]]; then
        WG_INTERFACE="$saved_interface"
        WG_CONFIG="${WG_DIR}/${WG_INTERFACE}.conf"
    fi

    cli_dispatch "$@"
    exit $?
fi

# 交互式：全程持有排它锁。两个人同时改 wg0.conf 是这类脚本最经典的翻车方式。
# 注意采集守护进程走的是上面那条 CLI 路径、且完全不加锁——它只往 state/ 里
# 用 tmp+mv 原子写入，不碰任何配置，因此不需要和菜单抢锁。
acquire_lock exclusive
migrate_legacy_v1
check_dependencies

saved_interface=$(get_config WG_INTERFACE)
if [[ -n "$saved_interface" ]]; then
    WG_INTERFACE="$saved_interface"
    WG_CONFIG="${WG_DIR}/${WG_INTERFACE}.conf"
fi

main_menu
