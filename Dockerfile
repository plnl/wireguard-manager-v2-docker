FROM debian:bookworm-slim

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
        python3 \
        wireguard-tools \
        iproute2 \
        iptables \
        qrencode \
        bash \
        sudo \
        curl \
    && rm -rf /var/lib/apt/lists/*

# 复制 wgmgr 脚本到容器内
COPY app/wireguard-manager-v2.0.sh /opt/wg-manager/wireguard-manager-v2.0.sh
RUN chmod +x /opt/wg-manager/wireguard-manager-v2.0.sh && \
    ln -sf /opt/wg-manager/wireguard-manager-v2.0.sh /usr/local/bin/wgmgr

# 复制 Web 层源码
COPY app/web/ /opt/wireguard-manager/web/
RUN chmod -R 750 /opt/wireguard-manager/web && \
    find /opt/wireguard-manager/web -type f -name '*.py' -exec chmod 750 {} +

# 复制 systemd 模板（容器内以 root 运行，不依赖 sudoers，但保持一致）
COPY app/systemd/ /opt/wg-manager/systemd/

# 复制 entrypoint
COPY entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

ENV WGM_MANAGER_DIR=/etc/wireguard-manager
ENV WGM_STATE_DIR=/etc/wireguard-manager/state
ENV WGM_LOG_DIR=/etc/wireguard-manager/logs
ENV WGM_WEB_CONF=/etc/wireguard-manager/web.conf
ENV WGM_MANAGER_CONF=/etc/wireguard-manager/manager.conf
ENV WGM_CLI=/usr/local/bin/wgmgr
ENV WGM_INTERFACE=wg0

EXPOSE 8443

WORKDIR /opt/wireguard-manager/web

ENTRYPOINT ["/entrypoint.sh"]
