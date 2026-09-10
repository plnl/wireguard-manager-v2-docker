 #!/usr/bin/env bash
 # WireGuard Manager V2 Docker 入口脚本
 # 同时启动采集进程和 Web 面板，容器内以 root 运行（无需 sudo）
 set -euo pipefail
 
 # 确保目录存在
 mkdir -p "${WGM_STATE_DIR}" "${WGM_LOG_DIR}"
 
 echo "[entrypoint] 启动 WireGuard Manager V2 容器..."
 echo "[entrypoint] WGM_MANAGER_DIR=${WGM_MANAGER_DIR}"
 echo "[entrypoint] WGM_CLI=${WGM_CLI}"
 echo "[entrypoint] WGM_INTERFACE=${WGM_INTERFACE}"
 
 # 先跑一次采集，让面板有初始数据
 echo "[entrypoint] 执行首次采集..."
 wgmgr collect 2>&1 || echo "[entrypoint] 首次采集失败（可能是接口未启动），继续..."
 
 # 启动采集守护进程（后台）
 echo "[entrypoint] 启动采集守护进程..."
 python3 /opt/wireguard-manager/web/wgm_collector.py &
 COLLECTOR_PID=$!
 
 # 启动 Web 面板（前台）
 echo "[entrypoint] 启动 Web 面板..."
 exec python3 /opt/wireguard-manager/web/wgm_web.py
