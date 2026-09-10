/*
 * WireGuard Manager V2.0 —— 面板前端
 *
 * 约束（都由服务端的 CSP 强制，写之前先看清楚）：
 *   default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self';
 *   connect-src 'self'; form-action 'none'; frame-ancestors 'none'
 * 也就是说：没有 CDN、没有第三方库、没有内联 <script>/<style>、没有 eval、
 * 表单不能真的提交（只能 preventDefault 后走 fetch）。
 *
 * 还有一条安全上的自我约束：**所有服务端数据一律走 textContent 或属性赋值，
 * 全程不用 innerHTML 拼接**。Peer 名字、日志行、站点 LAN 这些都来自配置文件，
 * 是用户自己填的，等于半可信输入；一处 innerHTML 就是一个存储型 XSS，
 * 而这个面板手里握着能增删 Peer 的接口。
 */
(function () {
    "use strict";

    var SVG_NS = "http://www.w3.org/2000/svg";
    var REFRESH_MS = 15000;

    // ==================================================================
    // DOM 构造
    // ==================================================================

    function el(tag, props) {
        var node = document.createElement(tag);
        var kids = Array.prototype.slice.call(arguments, 2);
        if (props) {
            Object.keys(props).forEach(function (key) {
                var value = props[key];
                if (value === null || value === undefined || value === false) return;
                if (key === "class") node.className = value;
                else if (key === "text") node.textContent = value;
                else if (key === "dataset") Object.assign(node.dataset, value);
                else if (key === "style" && typeof value === "object") Object.assign(node.style, value);
                else if (key.slice(0, 2) === "on" && typeof value === "function") {
                    node.addEventListener(key.slice(2).toLowerCase(), value);
                } else if (value === true) node.setAttribute(key, "");
                else node.setAttribute(key, String(value));
            });
        }
        appendAll(node, kids);
        return node;
    }

    function svg(tag, props) {
        var node = document.createElementNS(SVG_NS, tag);
        if (props) {
            Object.keys(props).forEach(function (key) {
                var value = props[key];
                if (value === null || value === undefined) return;
                if (key === "text") node.textContent = value;
                else node.setAttribute(key, String(value));
            });
        }
        return node;
    }

    function appendAll(parent, kids) {
        kids.forEach(function (kid) {
            if (kid === null || kid === undefined || kid === false) return;
            if (Array.isArray(kid)) appendAll(parent, kid);
            else if (kid instanceof Node) parent.appendChild(kid);
            else parent.appendChild(document.createTextNode(String(kid)));
        });
        return parent;
    }

    function clear(node) {
        while (node.firstChild) node.removeChild(node.firstChild);
        return node;
    }

    function frag() {
        var f = document.createDocumentFragment();
        return appendAll(f, Array.prototype.slice.call(arguments));
    }

    // ==================================================================
    // 格式化
    // ==================================================================

    var STATUS_LABEL = {
        online: "在线", idle: "空闲", offline: "离线",
        never: "从未连接", pending: "等待握手", disabled: "已禁用"
    };
    var STATUS_PILL = {
        online: "pill-ok", idle: "pill-idle", offline: "pill-err",
        never: "pill-muted", pending: "pill-warn", disabled: "pill-muted"
    };
    var LEVEL_LABEL = { pass: "通过", info: "提示", warn: "警告", error: "错误" };
    var LEVEL_MARK = { pass: "✓", info: "ℹ", warn: "!", error: "✕" };

    function fmtBytes(n) {
        n = Number(n) || 0;
        if (n < 1024) return n + " B";
        var units = ["KB", "MB", "GB", "TB", "PB"];
        var v = n, i = -1;
        do { v /= 1024; i++; } while (v >= 1024 && i < units.length - 1);
        return (v >= 100 ? v.toFixed(0) : v >= 10 ? v.toFixed(1) : v.toFixed(2)) + " " + units[i];
    }

    function fmtDuration(sec) {
        sec = Number(sec);
        if (!isFinite(sec) || sec < 0) return "—";
        if (sec < 60) return sec + " 秒";
        if (sec < 3600) return Math.floor(sec / 60) + " 分钟";
        if (sec < 86400) {
            var h = Math.floor(sec / 3600), m = Math.floor((sec % 3600) / 60);
            return m ? h + " 小时 " + m + " 分" : h + " 小时";
        }
        var d = Math.floor(sec / 86400);
        return d + " 天 " + Math.floor((sec % 86400) / 3600) + " 小时";
    }

    function fmtAgo(sec) {
        if (sec === null || sec === undefined) return "从未";
        return fmtDuration(sec) + "前";
    }

    function fmtTime(epoch) {
        if (!epoch) return "—";
        var d = new Date(Number(epoch) * 1000);
        if (isNaN(d.getTime())) return "—";
        return pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " +
               pad(d.getHours()) + ":" + pad(d.getMinutes());
    }

    function fmtDateTime(epoch) {
        if (!epoch) return "—";
        var d = new Date(Number(epoch) * 1000);
        if (isNaN(d.getTime())) return "—";
        return d.getFullYear() + "-" + pad(d.getMonth() + 1) + "-" + pad(d.getDate()) + " " +
               pad(d.getHours()) + ":" + pad(d.getMinutes()) + ":" + pad(d.getSeconds());
    }

    function pad(n) { return n < 10 ? "0" + n : String(n); }

    function shortKey(key) {
        if (!key) return "—";
        return key.length > 18 ? key.slice(0, 8) + "…" + key.slice(-6) : key;
    }

    function dash(value) {
        return (value === null || value === undefined || value === "") ? "—" : String(value);
    }

    // ==================================================================
    // API
    // ==================================================================

    function ApiError(status, message) {
        this.name = "ApiError";
        this.status = status;
        this.message = message || "请求失败";
    }
    ApiError.prototype = Object.create(Error.prototype);

    function api(path, opts) {
        opts = opts || {};
        var init = {
            method: opts.method || "GET",
            credentials: "same-origin",
            headers: {}
        };
        if (opts.body !== undefined) {
            init.headers["Content-Type"] = "application/json";
            init.body = JSON.stringify(opts.body);
        }
        return fetch(path, init).then(function (res) {
            if (res.status === 401) {
                // 会话过期：不管当前在哪个视图，一律退回登录页。
                // 这里刻意不 reject 到调用方去处理——十个视图各写一遍
                // "如果是 401 就跳登录"只会漏掉其中一个。
                sessionExpired();
                throw new ApiError(401, "未登录或会话已过期");
            }
            return res.text().then(function (raw) {
                var data = null;
                if (raw) {
                    try { data = JSON.parse(raw); }
                    catch (e) { data = null; }
                }
                if (!res.ok) {
                    var msg = (data && data.error) || ("HTTP " + res.status);
                    throw new ApiError(res.status, msg);
                }
                return data;
            });
        });
    }

    // 下载含私钥的 .conf：不能用 window.location 直接跳，那样 403 的时候
    // 浏览器会把 JSON 错误当页面渲染出来，用户看到的是一坨 {"error":...}。
    // 走 fetch → blob → objectURL，错误才能正常弹 toast。
    function apiDownload(path, filename) {
        return fetch(path, { credentials: "same-origin" }).then(function (res) {
            if (res.status === 401) { sessionExpired(); throw new ApiError(401, "会话已过期"); }
            return res.text().then(function (raw) {
                if (!res.ok) {
                    var msg = raw;
                    try { msg = (JSON.parse(raw) || {}).error || raw; } catch (e) { /* 原样用 */ }
                    throw new ApiError(res.status, msg || ("HTTP " + res.status));
                }
                var blob = new Blob([raw], { type: "text/plain;charset=utf-8" });
                var url = URL.createObjectURL(blob);
                var a = el("a", { href: url, download: filename });
                document.body.appendChild(a);
                a.click();
                document.body.removeChild(a);
                // 立刻 revoke 会让部分浏览器取消下载，所以推迟一点。
                setTimeout(function () { URL.revokeObjectURL(url); }, 10000);
            });
        });
    }

    // ==================================================================
    // Toast
    // ==================================================================

    var toastBox = null;

    function toast(message, kind) {
        if (!toastBox) toastBox = document.getElementById("toasts");
        var node = el("div", { class: "toast toast-" + (kind || "info"), text: message });
        toastBox.appendChild(node);
        setTimeout(function () {
            node.style.opacity = "0";
            node.style.transition = "opacity .25s";
            setTimeout(function () { if (node.parentNode) node.parentNode.removeChild(node); }, 260);
        }, kind === "err" ? 7000 : 3800);
    }

    // ==================================================================
    // Modal
    // ==================================================================

    var modalRoot = null;
    var modalOpen = false;

    // 关掉弹窗时要还原焦点，否则焦点会掉回 body，键盘用户就迷路了。
    var lastFocus = null;

    function openModal(options) {
        closeModal();
        if (!modalRoot) modalRoot = document.getElementById("modal-root");
        lastFocus = document.activeElement;
        modalOpen = true;

        var bodyNode = el("div", { class: "modal-body" });
        appendAll(bodyNode, options.body || []);

        var footBtns = (options.buttons || []).map(function (spec) {
            return el("button", {
                class: "btn " + (spec.class || ""),
                type: "button",
                text: spec.label,
                onclick: function () { spec.onClick(closeModal, bodyNode); }
            });
        });

        var modal = el("div", { class: "modal" + (options.wide ? " wide" : ""), role: "dialog",
                                "aria-modal": "true" },
            el("div", { class: "modal-head" },
                el("h2", { class: "modal-title", text: options.title }),
                el("button", { class: "modal-close", type: "button", "aria-label": "关闭",
                               text: "×", onclick: closeModal })),
            bodyNode,
            footBtns.length ? el("div", { class: "modal-foot" }, footBtns) : null
        );

        var backdrop = el("div", { class: "modal-backdrop",
            onclick: function (ev) { if (ev.target === backdrop) closeModal(); } }, modal);

        modalRoot.appendChild(backdrop);

        var first = modal.querySelector("input, select, textarea, button");
        if (first) first.focus();

        backdrop.addEventListener("keydown", function (ev) {
            if (ev.key === "Escape") { ev.stopPropagation(); closeModal(); }
        });
        return { root: bodyNode, close: closeModal };
    }

    function closeModal() {
        if (!modalRoot) modalRoot = document.getElementById("modal-root");
        if (modalRoot && modalRoot.firstChild) clear(modalRoot);
        if (!modalOpen) return;
        modalOpen = false;
        if (lastFocus && document.contains(lastFocus)) lastFocus.focus();
        lastFocus = null;
    }

    // 二次确认：删除和轮换密钥都要求把名字打进去，光点一下确认不够。
    // 这两个操作的后果分别是"配置和密钥一起没了"和"设备立刻掉线"，
    // 一次误触的代价高于多打几个字。
    function confirmByName(options) {
        var target = options.name;
        var input = el("input", { class: "mono", type: "text", placeholder: target,
                                  autocomplete: "off", spellcheck: "false" });
        var err = el("p", { class: "form-error", text: "名字不一致", hidden: true });
        var busy = false;

        openModal({
            title: options.title,
            body: [
                el("p", { style: { marginTop: "0" } }, options.message),
                el("label", { class: "field" },
                    el("span", { class: "field-label", text: "请输入 " + target + " 以确认" }),
                    input),
                err
            ],
            buttons: [
                { label: "取消", onClick: closeModal },
                { label: options.confirmLabel || "确认", class: "btn-danger", onClick: function (close) {
                    if (busy) return;
                    if (input.value.trim() !== target) {
                        err.textContent = "需要输入的名字是：" + target;
                        err.hidden = false;
                        input.focus();
                        return;
                    }
                    busy = true;
                    err.hidden = true;
                    options.onConfirm().then(function () {
                        close();
                        refresh();
                    }).catch(function (exc) {
                        busy = false;
                        toast(exc.message || String(exc), "err");
                    });
                } }
            ]
        });
    }

    // ==================================================================
    // 通用小组件
    // ==================================================================

    function statusPill(status) {
        return el("span", { class: "pill " + (STATUS_PILL[status] || "pill-muted") },
            el("span", { class: "dot" }),
            STATUS_LABEL[status] || status || "未知");
    }

    function kindPill(kind) {
        return el("span", { class: "pill " + (kind === "site" ? "pill-info" : "pill-muted") },
            kind === "site" ? "站点" : "客户端");
    }

    function stat(label, value, note, cls) {
        return el("div", { class: "card stat" },
            el("div", { class: "stat-label", text: label }),
            el("div", { class: "stat-value" + (cls ? " " + cls : ""), text: dash(value) }),
            note ? el("div", { class: "stat-note", text: note }) : null);
    }

    function kvList(pairs) {
        var dl = el("dl", { class: "kv" });
        pairs.forEach(function (pair) {
            if (!pair) return;
            dl.appendChild(el("dt", { text: pair[0] }));
            dl.appendChild(el("dd", {}, pair[1] instanceof Node ? pair[1] : dash(pair[1])));
        });
        return dl;
    }

    function section(title, sub, actions, bodyNodes) {
        return el("section", { class: "section" },
            el("div", { class: "section-head" },
                el("div", {},
                    el("h2", { class: "section-title", text: title }),
                    sub ? el("div", { class: "section-sub", text: sub }) : null),
                actions && actions.length ? el("div", { class: "page-actions" }, actions) : null),
            bodyNodes);
    }

    function card(bodyNodes, pad) {
        return el("div", { class: "card" + (pad === false ? "" : " card-pad") }, bodyNodes);
    }

    function table(headers, rows) {
        var head = el("tr", {}, headers.map(function (h) {
            return el("th", { class: h.num ? "num" : null, text: h.label });
        }));
        var body = el("tbody", {}, rows.map(function (cells) {
            return el("tr", { class: cells.clickable ? "clickable" : null,
                              onclick: cells.onClick },
                cells.cols.map(function (c) {
                    return el(c.num ? "td" : "td", { class: c.num ? "num" : (c.class || null) },
                        c.node instanceof Node ? c.node : dash(c.text));
                }));
        }));
        return el("div", { class: "tbl-wrap card" },
            el("table", { class: "tbl" }, el("thead", {}, head), body));
    }

    function emptyBox(text) {
        return el("div", { class: "card empty", text: text });
    }

    function loadingBox() {
        return el("div", { class: "loading" }, el("span", { class: "spinner" }), " 加载中…");
    }

    function checksBlock(checks) {
        if (!checks || !checks.length) {
            return el("div", { class: "empty", text: "没有检查项。" });
        }
        return el("div", { class: "peer-checks" }, checks.map(function (chk) {
            return el("div", { class: "check lv-" + (chk.level || "info") },
                el("div", { class: "check-mark", text: LEVEL_MARK[chk.level] || "ℹ" }),
                el("div", { class: "check-body" },
                    el("div", { class: "check-title", text: chk.title || chk.id }),
                    chk.detail ? el("div", { class: "check-detail", text: chk.detail }) : null,
                    (chk.hints && chk.hints.length)
                        ? el("ul", { class: "check-hints" }, chk.hints.map(function (h) {
                              return el("li", { text: h });
                          }))
                        : null));
        }));
    }

    // ==================================================================
    // 流量图（SVG）
    // ==================================================================

    function niceMax(v) {
        if (!(v > 0)) return 1024;
        var exp = Math.floor(Math.log(v) / Math.LN10);
        var base = Math.pow(10, exp);
        var frac = v / base;
        var step = frac <= 1 ? 1 : frac <= 2 ? 2 : frac <= 5 ? 5 : 10;
        return step * base;
    }

    function trafficChart(series, bucketSec) {
        var W = 920, H = 210;
        var padL = 58, padR = 10, padT = 10, padB = 26;
        var plotW = W - padL - padR, plotH = H - padT - padB;

        var peak = 0;
        series.forEach(function (p) { peak = Math.max(peak, p.rx || 0, p.tx || 0); });
        var top = niceMax(peak);

        var root = svg("svg", { class: "chart", viewBox: "0 0 " + W + " " + H,
                                preserveAspectRatio: "none", role: "img",
                                "aria-label": "流量趋势图" });

        [0, 0.25, 0.5, 0.75, 1].forEach(function (ratio) {
            var y = padT + plotH * ratio;
            root.appendChild(svg("line", { class: "chart-grid", x1: padL, x2: W - padR, y1: y, y2: y }));
            root.appendChild(svg("text", { class: "chart-axis", x: padL - 6, y: y + 3.5,
                                         "text-anchor": "end",
                                         text: fmtBytes(top * (1 - ratio)) }));
        });

        var n = series.length;
        var slot = plotW / Math.max(n, 1);
        var barW = Math.max(1, (slot - 2) / 2);

        series.forEach(function (p, i) {
            var x = padL + slot * i;
            var baseY = padT + plotH;

            if (p.gap) {
                // 采集断档：画一条淡竖线而不是留白。留白会让人以为
                // 那段时间流量是 0，而实际上是"我们不知道"，这两件事
                // 在排障时的含义完全相反。
                root.appendChild(svg("rect", {
                    x: x, y: padT, width: Math.max(slot - 1, 1), height: plotH,
                    fill: "#2c3441", opacity: "0.28"
                }));
            }

            [["rx", "var(--rx)"], ["tx", "var(--tx)"]].forEach(function (pair, j) {
                var value = p[pair[0]] || 0;
                var h = top > 0 ? (value / top) * plotH : 0;
                if (h < 0.6 && value > 0) h = 0.6;
                if (h <= 0) return;
                root.appendChild(svg("rect", {
                    x: x + 1 + j * (barW + 1),
                    y: baseY - h,
                    width: barW,
                    height: h,
                    fill: pair[1],
                    opacity: pair[0] === "tx" ? "0.85" : "1"
                }));
            });
        });

        if (n) {
            var marks = n <= 2 ? [0, n - 1] : [0, Math.floor((n - 1) / 2), n - 1];
            marks.forEach(function (i, k) {
                root.appendChild(svg("text", {
                    class: "chart-axis",
                    x: padL + slot * i + slot / 2,
                    y: H - 8,
                    "text-anchor": k === 0 ? "start" : (k === marks.length - 1 ? "end" : "middle"),
                    text: fmtTime(series[i].t)
                }));
            });
        }

        return el("div", { class: "chart-wrap" },
            root,
            el("div", { class: "chart-legend" },
                el("span", {}, el("span", { class: "chart-key", style: { background: "var(--rx)" } }),
                   "接收 RX"),
                el("span", {}, el("span", { class: "chart-key", style: { background: "var(--tx)" } }),
                   "发送 TX"),
                el("span", {}, "每格 " + fmtDuration(bucketSec)),
                peak ? el("span", {}, "峰值 " + fmtBytes(peak) + " / 格") : null,
                el("span", { class: "section-sub", text: "灰色竖条 = 该时段没有采样，不是流量为 0" })
            ));
    }

    // ==================================================================
    // 视图
    // ==================================================================

    var views = {};

    // ---- 概览 ----
    views.overview = function (host) {
        return api("/api/v1/status").then(function (st) {
            var sum = st.summary || {};
            var iface = st.interface || {};
            var web = st.web || {};
            var coll = st.collector || {};

            var stale = st._state_stale;
            var ageNode = el("span", { class: "pill " + (stale ? "pill-warn" : "pill-muted") },
                "状态更新于 " + dash(st.generated_at_str) +
                (st._state_age_sec !== null && st._state_age_sec !== undefined
                    ? "（" + fmtDuration(st._state_age_sec) + "前）" : ""));

            var peers = st.peers || [];
            var problemPeers = peers.filter(function (p) {
                return p.status === "offline" || p.status === "never";
            });

            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title", text: "概览" }),
                        el("p", { class: "page-sub" },
                            dash(st.hostname) + " · " + (iface.running ? "隧道运行中" : "隧道未运行"))),
                    el("div", { class: "page-actions" }, ageNode)),

                st._state_stale ? el("div", { class: "topo-note", style: { marginBottom: "14px" } },
                    "状态数据已经超过 5 分钟没更新。通常是采集服务停了 —— " +
                    "运行 systemctl status wireguard-manager-collector 看一下，" +
                    "或者点右上角“刷新状态”手动跑一轮。WireGuard 本身不受影响，" +
                    "隧道是内核在转发，面板只是旁观者。") : null,

                el("div", { class: "grid grid-4 section" },
                    stat("在线 Peer", sum.online, "共 " + (sum.peers_total || 0) + " 个"),
                    stat("空闲", sum.idle, "握手 3 分钟 ~ 15 分钟"),
                    stat("离线", sum.offline, (sum.never || 0) + " 个从未连接", sum.offline ? "sm" : null),
                    stat("已禁用", sum.disabled, null)),

                el("div", { class: "grid grid-2 section" },
                    card([
                        el("div", { class: "section-head" },
                            el("h2", { class: "section-title", text: "接口" })),
                        kvList([
                            ["接口名", iface.name],
                            ["运行状态", iface.running
                                ? el("span", { class: "pill pill-ok" }, el("span", { class: "dot dot-pulse" }), "UP")
                                : el("span", { class: "pill pill-err" }, el("span", { class: "dot" }), "DOWN")],
                            ["监听端口", iface.listen_port ? "UDP/" + iface.listen_port : "—"],
                            ["对外地址", iface.endpoint],
                            ["VPN 网段", iface.vpn_network4],
                            ["本机 VPN IP", iface.server_ip4],
                            ["公网 NAT", iface.internet_nat ? "开启" : "关闭"],
                            ["防火墙后端", iface.fw_backend],
                            ["客户端 / 站点", (sum.clients || 0) + " / " + (sum.sites || 0)]
                        ]),
                        el("div", { style: { marginTop: "12px" } },
                            el("a", { class: "btn btn-sm", href: "#/system", text: "系统详情" }))
                    ]),
                    card([
                        el("div", { class: "section-head" },
                            el("h2", { class: "section-title", text: "累计流量" }),
                            el("a", { class: "section-sub", href: "#/traffic", text: "看趋势 →" })),
                        kvList([
                            ["接收 RX", fmtBytes(sum.rx_bytes_total)],
                            ["发送 TX", fmtBytes(sum.tx_bytes_total)]
                        ]),
                        el("div", { class: "section-head", style: { marginTop: "14px" } },
                            el("h2", { class: "section-title", text: "面板服务" })),
                        kvList([
                            ["Web 服务", web.running
                                ? el("span", { class: "pill pill-ok" }, "运行中")
                                : el("span", { class: "pill pill-warn" }, "未运行")],
                            ["监听地址", web.listen],
                            ["采集进程", coll.running
                                ? el("span", { class: "pill pill-ok" }, "运行中")
                                : el("span", { class: "pill pill-err" }, "未运行")],
                            ["采集间隔", coll.interval_sec ? coll.interval_sec + " 秒" : "—"]
                        ])
                    ])),

                problemPeers.length ? section("需要关注", "离线或从未连接过的 Peer",
                    [el("a", { class: "btn btn-sm", href: "#/health", text: "看诊断建议" })],
                    card(problemPeers.map(function (p) {
                        return el("a", { class: "check lv-error", href: "#/peers/" + encodeURIComponent(p.name),
                                         style: { color: "inherit", display: "flex" } },
                            el("div", { class: "check-mark", text: "✕" }),
                            el("div", { class: "check-body" },
                                el("div", { class: "check-title" }, p.name + " ", kindPill(p.kind)),
                                el("div", { class: "check-detail",
                                    text: p.status === "offline"
                                        ? "最后握手 " + fmtAgo(p.handshake_ago_sec)
                                        : "从未建立过握手" })));
                    }), false)) : null
            ]);
        });
    };

    // ---- Peer 列表 ----
    views.peers = function (host) {
        var filterKind = state.peerKind || "";
        var filterStatus = state.peerStatus || "";

        var qs = [];
        if (filterKind) qs.push("kind=" + encodeURIComponent(filterKind));
        if (filterStatus) qs.push("status=" + encodeURIComponent(filterStatus));
        var path = "/api/v1/peers" + (qs.length ? "?" + qs.join("&") : "");

        return api(path).then(function (data) {
            var peers = data.peers || [];

            function tab(label, key, value) {
                return el("button", {
                    class: "tab" + (state[key] === value ? " active" : ""),
                    type: "button", text: label,
                    onclick: function () { state[key] = value; refresh(); }
                });
            }

            var rows = peers.map(function (p) {
                return {
                    clickable: true,
                    onClick: function () { location.hash = "#/peers/" + encodeURIComponent(p.name); },
                    cols: [
                        { node: el("span", { class: "mono", text: p.name }) },
                        { node: kindPill(p.kind) },
                        { node: statusPill(p.status) },
                        { text: dash(p.vpn_ip4), class: "mono" },
                        { text: p.handshake_ago_sec === null || p.handshake_ago_sec === undefined
                                ? "从未" : fmtAgo(p.handshake_ago_sec) },
                        { text: dash(p.endpoint), class: "mono" },
                        { text: fmtBytes(p.rx_bytes), num: true },
                        { text: fmtBytes(p.tx_bytes), num: true },
                        { class: "tbl-actions", node: el("div", { class: "page-actions",
                                style: { justifyContent: "flex-end" } },
                            el("button", { class: "btn btn-sm", type: "button",
                                text: p.enabled ? "禁用" : "启用",
                                onclick: function (ev) {
                                    ev.stopPropagation();
                                    togglePeer(p);
                                } }),
                            p.kind === "client" ? el("button", { class: "btn btn-sm", type: "button",
                                text: "下载配置",
                                onclick: function (ev) { ev.stopPropagation(); downloadConf(p.name); } }) : null,
                            el("button", { class: "btn btn-sm btn-danger", type: "button", text: "删除",
                                onclick: function (ev) { ev.stopPropagation(); deletePeer(p); } })) }
                    ]
                };
            });

            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title", text: "Peer / 连接" }),
                        el("p", { class: "page-sub", text: "共 " + peers.length + " 个（已按条件过滤）" })),
                    el("div", { class: "page-actions" },
                        el("button", { class: "btn btn-primary", type: "button", text: "新建客户端",
                                       onclick: addClientDialog }))),
                el("div", { class: "tabs" },
                    tab("全部类型", "peerKind", ""),
                    tab("客户端", "peerKind", "client"),
                    tab("站点", "peerKind", "site"),
                    el("span", { style: { width: "10px" } }),
                    tab("全部状态", "peerStatus", ""),
                    tab("在线", "peerStatus", "online"),
                    tab("离线", "peerStatus", "offline"),
                    tab("已禁用", "peerStatus", "disabled")),
                rows.length
                    ? table([
                        { label: "名称" }, { label: "类型" }, { label: "状态" },
                        { label: "VPN IP" }, { label: "最后握手" }, { label: "Endpoint" },
                        { label: "RX", num: true }, { label: "TX", num: true }, { label: "操作" }
                      ], rows)
                    : emptyBox("没有符合条件的 Peer。")
            ]);
        });
    };

    // ---- Peer 详情 ----
    views.peerDetail = function (host, name) {
        return api("/api/v1/peers/" + encodeURIComponent(name)).then(function (data) {
            var p = data.peer || {};
            var isClient = p.kind !== "site";
            var isSite = p.kind === "site";

            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title" },
                            el("span", { class: "mono", text: p.name || name }), " ",
                            kindPill(p.kind), " ", statusPill(p.status)),
                        el("p", { class: "page-sub" },
                            el("a", { href: "#/peers", text: "← 返回列表" }))),
                    el("div", { class: "page-actions" },
                        el("button", { class: "btn", type: "button", text: p.enabled ? "禁用" : "启用",
                                       onclick: function () { togglePeer(p); } }),
                        isClient ? el("button", { class: "btn", type: "button", text: "下载配置",
                                       onclick: function () { downloadConf(p.name); } }) : null,
                        isClient ? el("button", { class: "btn", type: "button", text: "查看二维码",
                                       onclick: function () { qrcodeDialog(p.name); } }) : null,
                        isClient ? el("button", { class: "btn", type: "button", text: "重新生成密钥",
                                       onclick: function () { rotateKeyDialog(p); } }) : null,
                        isSite ? el("button", { class: "btn", type: "button", text: "连通性测试",
                                       onclick: function () { siteTest(p.name); } }) : null,
                        el("button", { class: "btn btn-danger", type: "button", text: "删除",
                                       onclick: function () { deletePeer(p); } }))),

                el("div", { class: "grid grid-2 section" },
                    card([
                        el("h2", { class: "section-title", style: { marginTop: "0" }, text: "身份与地址" }),
                        kvList([
                            ["名称", el("span", { class: "mono", text: dash(p.name) })],
                            ["类型", isSite ? "站点（Site-to-Site）" : "客户端"],
                            ["启用", p.enabled ? "是" : "否"],
                            ["VPN IPv4", el("span", { class: "mono", text: dash(p.vpn_ip4) })],
                            ["VPN IPv6", p.vpn_ip6 ? el("span", { class: "mono", text: p.vpn_ip6 }) : "—"],
                            ["公钥", el("span", { class: "mono", title: p.public_key || "",
                                                  text: shortKey(p.public_key) })],
                            ["创建时间", dash(p.created)]
                        ])
                    ]),
                    card([
                        el("h2", { class: "section-title", style: { marginTop: "0" }, text: "运行时" }),
                        kvList([
                            ["已加载到内核", p.loaded ? "是" : el("span", { class: "pill pill-warn", text: "否" })],
                            ["状态", statusPill(p.status)],
                            ["最后握手", p.latest_handshake
                                ? fmtDateTime(p.latest_handshake) + "（" + fmtAgo(p.handshake_ago_sec) + "）"
                                : "从未握手"],
                            ["实际 Endpoint", p.endpoint
                                ? el("span", { class: "mono", text: p.endpoint }) : "—（还没收到过包）"],
                            ["AllowedIPs", el("span", { class: "mono", text: dash(p.peer_allowed_ips) })],
                            ["PersistentKeepalive", p.keepalive === "off"
                                ? el("span", { class: "pill pill-warn", text: "未设置" })
                                : p.keepalive + " 秒"],
                            ["RX / TX", fmtBytes(p.rx_bytes) + " / " + fmtBytes(p.tx_bytes)]
                        ])
                    ])),

                isSite ? card([
                    el("h2", { class: "section-title", style: { marginTop: "0" }, text: "站点拓扑" }),
                    kvList([
                        ["模式", p.mode === "routing" ? "routing（纯路由，不做 NAT）"
                              : p.mode === "nat" ? "nat（本机做 MASQUERADE）"
                              : p.mode === "conflict" ? "conflict（网段冲突降级：只通 VPN IP）" : dash(p.mode)],
                        ["本站 LAN", el("span", { class: "mono", text: dash(p.local_lan) })],
                        ["对端 LAN", el("span", { class: "mono", text: dash(p.remote_lan) })],
                        ["对端 VPN IP", el("span", { class: "mono", text: dash(p.vpn_ip4) })],
                        ["对端 Endpoint", el("span", { class: "mono", text: dash(p.remote_endpoint) })]
                    ]),
                    p.mode === "conflict" ? el("div", { class: "topo-note" },
                        "这条站点处于 conflict 降级模式：两端 LAN 网段重叠，只能通 VPN IP 本身，" +
                        "整个对端网段路由不过来。解决办法是给其中一端换网段，然后重建站点。") : null
                ], true) : card([
                    el("h2", { class: "section-title", style: { marginTop: "0" }, text: "客户端配置" }),
                    kvList([
                        ["客户端 AllowedIPs", el("span", { class: "mono", text: dash(p.client_allowed_ips) })],
                        ["含义", (p.client_allowed_ips || "").indexOf("0.0.0.0/0") >= 0
                            ? "全局代理：这台设备的所有流量都走 VPN"
                            : "只代理指定网段，其余流量走设备自己的默认路由"]
                    ])
                ], true),

                section("健康检查", "由 Health Engine 每轮采集时生成", null,
                    checksBlock(data.checks)),

                el("p", { class: "section-sub" },
                    "面板能对这个 Peer 做的操作只有上面这些。" +
                    "重启接口、轮换服务端密钥、清理防火墙这类会影响所有连接的操作，" +
                    "刻意没有暴露到面板上 —— 必须 SSH 登录后在 wgmgr 交互菜单里做。")
            ]);
        });
    };

    // ---- Site-to-Site ----
    views.sites = function (host) {
        return api("/api/v1/sites").then(function (data) {
            var hub = data.hub || {};
            var sites = data.sites || [];
            var conflicted = sites.filter(function (s) { return s.mode === "conflict"; });
            var natSites = sites.filter(function (s) { return s.mode === "nat"; });

            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title", text: "Site-to-Site 拓扑" }),
                        el("p", { class: "page-sub",
                            text: "以本机为中心的星型拓扑。默认推荐 routing 模式 —— 站点之间不做 MASQUERADE。" })),
                    el("div", { class: "page-actions" },
                        el("button", { class: "btn btn-primary", type: "button", text: "新建站点",
                                       onclick: addSiteDialog }))),

                card([
                    el("div", { class: "topo" },
                        el("div", { class: "topo-hub" },
                            el("div", { class: "topo-hub-name", text: dash(hub.name) }),
                            el("div", { class: "topo-hub-sub",
                                text: (hub.vpn_ip4 || "—") + " · " + (hub.vpn_network4 || "—") }),
                            el("div", { style: { marginTop: "6px" } },
                                hub.running
                                    ? el("span", { class: "pill pill-ok" }, el("span", { class: "dot dot-pulse" }), "UP")
                                    : el("span", { class: "pill pill-err" }, el("span", { class: "dot" }), "DOWN"))),
                        sites.length ? el("div", { class: "topo-trunk" }) : null,
                        sites.length ? el("div", { class: "topo-branch" },
                            sites.map(function (s) {
                                var color = s.status === "online" ? "var(--ok)"
                                    : s.status === "offline" ? "var(--err)"
                                    : s.status === "idle" ? "var(--idle)" : "var(--line)";
                                return el("a", { class: "topo-leaf",
                                    href: "#/peers/" + encodeURIComponent(s.name),
                                    style: { borderLeftColor: color, color: "inherit" } },
                                    el("div", { class: "topo-leaf-name" },
                                        s.name + " ", statusPill(s.status)),
                                    el("div", { class: "topo-leaf-row", text: "本站 " + dash(s.local_lan) }),
                                    el("div", { class: "topo-leaf-row", text: "对端 " + dash(s.remote_lan) }),
                                    el("div", { class: "topo-leaf-row",
                                        text: "模式 " + dash(s.mode) + " · 保活 " + dash(s.keepalive) }));
                            })) : null),
                    sites.length ? null : el("div", { class: "empty", text: "还没有站点。" })
                ]),

                conflicted.length ? el("div", { class: "topo-note" },
                    "有 " + conflicted.length + " 条站点处于 conflict 降级模式（" +
                    conflicted.map(function (s) { return s.name; }).join("、") +
                    "）：两端 LAN 网段重叠，只能通 VPN IP。要给其中一端换网段才能恢复整段互通。") : null,

                natSites.length ? el("div", { class: "topo-note",
                        style: { borderLeftColor: "var(--info)", background: "#12212e" } },
                    natSites.length + " 条站点走 NAT 模式。能用，但如果两端路由器都能加静态路由，" +
                    "改成 routing 更好排障：对端看到的源 IP 就是真实 LAN IP，抓包时不用先反推一层 NAT。") : null,

                section("站点明细", null, null, sites.length ? table([
                    { label: "名称" }, { label: "状态" }, { label: "本站 LAN" },
                    { label: "对端 LAN" }, { label: "模式" }, { label: "保活" },
                    { label: "最后握手" }, { label: "操作" }
                ], sites.map(function (s) {
                    return {
                        cols: [
                            { node: el("a", { class: "mono", href: "#/peers/" + encodeURIComponent(s.name),
                                              text: s.name }) },
                            { node: statusPill(s.status) },
                            { text: s.local_lan, class: "mono" },
                            { text: s.remote_lan, class: "mono" },
                            { text: s.mode },
                            { text: s.keepalive === "off" ? "未设置" : s.keepalive + "s" },
                            { text: s.handshake_ago_sec === null || s.handshake_ago_sec === undefined
                                    ? "从未" : fmtAgo(s.handshake_ago_sec) },
                            { class: "tbl-actions", node: el("div", { class: "page-actions",
                                    style: { justifyContent: "flex-end" } },
                                el("button", { class: "btn btn-sm", type: "button", text: "测试",
                                    onclick: function () { siteTest(s.name); } }),
                                el("button", { class: "btn btn-sm", type: "button",
                                    text: s.enabled ? "禁用" : "启用",
                                    onclick: function () { togglePeer(s); } }),
                                el("button", { class: "btn btn-sm btn-danger", type: "button", text: "删除",
                                    onclick: function () { deletePeer(s); } })) }
                        ]
                    };
                })) : emptyBox("还没有站点。"))
            ]);
        });
    };

    // ---- 流量 ----
    var RANGES = [
        ["24h", "24 小时"], ["today", "今天"], ["yesterday", "昨天"],
        ["7d", "7 天"], ["week", "本周"], ["30d", "30 天"], ["month", "本月"]
    ];

    views.traffic = function (host) {
        var range = state.trafficRange || "24h";
        return api("/api/v1/traffic?range=" + encodeURIComponent(range) + "&by_peer=1").then(function (r) {
            var total = r.total || {};

            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title", text: "流量统计" }),
                        el("p", { class: "page-sub",
                            text: dash(r.from_str) + " ~ " + dash(r.to_str) +
                                  " · " + (r.samples || 0) + " 个采样点 · 桶宽 " +
                                  fmtDuration(r.bucket_sec) }))),
                el("div", { class: "tabs" }, RANGES.map(function (pair) {
                    return el("button", { class: "tab" + (range === pair[0] ? " active" : ""),
                        type: "button", text: pair[1],
                        onclick: function () { state.trafficRange = pair[0]; refresh(); } });
                })),

                el("div", { class: "grid grid-2 section" },
                    stat("接收 RX", total.rx_h, fmtBytes(total.rx)),
                    stat("发送 TX", total.tx_h, fmtBytes(total.tx))),

                section("趋势", "柱高是每格增量，不是累计值", null,
                    (r.series && r.series.length)
                        ? card([trafficChart(r.series, r.bucket_sec)])
                        : emptyBox("这个范围内还没有足够的采样点。采集进程每 " +
                                   (state.interval || 30) + " 秒采一次，等几分钟再来看。")),

                section("周期汇总", "各自独立计算，所以加起来不等于“所选范围”", null,
                    (r.periods && r.periods.length) ? table([
                        { label: "周期" }, { label: "接收 RX", num: true },
                        { label: "发送 TX", num: true }, { label: "采样点", num: true }
                    ], r.periods.map(function (p) {
                        return { cols: [
                            { text: p.label },
                            { text: p.rx_h, num: true },
                            { text: p.tx_h, num: true },
                            { text: p.samples, num: true }
                        ] };
                    })) : emptyBox("暂无数据。")),

                section("按 Peer 拆分", "所选范围内", null,
                    (r.peers && r.peers.length) ? table([
                        { label: "名称" }, { label: "类型" },
                        { label: "接收 RX", num: true }, { label: "发送 TX", num: true }
                    ], r.peers.map(function (p) {
                        return { cols: [
                            { node: el("a", { class: "mono",
                                href: "#/peers/" + encodeURIComponent(p.name), text: p.name }) },
                            { node: kindPill(p.kind) },
                            { text: p.rx_h, num: true },
                            { text: p.tx_h, num: true }
                        ] };
                    })) : emptyBox("暂无按 Peer 的数据。"))
            ]);
        });
    };

    // ---- 健康检查 ----
    views.health = function (host) {
        return api("/api/v1/health").then(function (h) {
            var counts = h.counts || {};
            var system = (h.system || []).filter(function (c) {
                return c.level !== "pass" || state.showPassing;
            });

            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title", text: "诊断 / Health Check" }),
                        el("p", { class: "page-sub", text: dash(h.headline) })),
                    el("div", { class: "page-actions" },
                        el("span", { class: "pill " + (h.ok ? "pill-ok" : "pill-err") },
                            h.ok ? "整体正常" : "有问题"),
                        el("span", { class: "pill pill-err", text: (counts.error || 0) + " 错误" }),
                        el("span", { class: "pill pill-warn", text: (counts.warn || 0) + " 警告" }),
                        el("span", { class: "pill pill-info", text: (counts.info || 0) + " 提示" }),
                        el("span", { class: "pill pill-ok", text: (counts.pass || 0) + " 通过" }))),

                el("p", { class: "section-sub" },
                    "生成于 " + dash(h.generated_at_str) +
                    (h.state_age_sec !== null && h.state_age_sec !== undefined
                        ? "（" + fmtDuration(h.state_age_sec) + "前）" : "")),

                section("系统检查", state.showPassing ? "含已通过项" : "已折叠通过项",
                    [el("button", { class: "btn btn-sm", type: "button",
                        text: state.showPassing ? "只看异常" : "显示全部",
                        onclick: function () { state.showPassing = !state.showPassing; refresh(); } })],
                    card(system.length ? system.map(renderCheck) : [el("div", { class: "empty",
                        text: "全部通过。" })], false)),

                section("Peer 检查", "只列出有异常或有值得注意之处的 Peer", null,
                    (h.peers && h.peers.length)
                        ? (h.peers.map(function (pr) {
                            return el("div", { class: "peer-checks" },
                                el("div", { class: "peer-checks-head" },
                                    el("a", { class: "mono",
                                        href: "#/peers/" + encodeURIComponent(pr.name), text: pr.name }),
                                    kindPill(pr.kind), statusPill(pr.status)),
                                checksBlock(pr.checks));
                          }))
                        : emptyBox("所有 Peer 都没有异常。"))
            ]);
        });
    };

    function renderCheck(chk) {
        return el("div", { class: "check lv-" + (chk.level || "info") },
            el("div", { class: "check-mark", text: LEVEL_MARK[chk.level] || "ℹ" }),
            el("div", { class: "check-body" },
                el("div", { class: "check-title", text: chk.title || chk.id }),
                chk.detail ? el("div", { class: "check-detail", text: chk.detail }) : null,
                (chk.hints && chk.hints.length)
                    ? el("ul", { class: "check-hints" },
                        chk.hints.map(function (t) { return el("li", { text: t }); }))
                    : null));
    }

    // ---- 告警 ----
    var CHANNEL_LABEL = {
        telegram: "Telegram", bark: "Bark", wecom: "企业微信",
        dingtalk: "钉钉", webhook: "通用 Webhook", email: "Email"
    };

    views.alerts = function (host) {
        return api("/api/v1/alerts").then(function (data) {
            var conf = data.config || {};
            var configured = conf.configured || {};
            var events = data.events || [];
            var track = data.track || {};

            var trackRows = Object.keys(track).filter(function (k) {
                // "@" 开头的是内部键（比如 @interface 的抑制标记），不是 Peer
                return k.charAt(0) !== "@";
            }).map(function (name) {
                var t = track[name] || {};
                return { cols: [
                    { node: el("a", { class: "mono",
                        href: "#/peers/" + encodeURIComponent(name), text: name }) },
                    { node: kindPill(t.kind) },
                    { node: statusPill(t.status) },
                    { text: (t.miss || 0) + " 次" },
                    { node: t.alerted
                        ? el("span", { class: "pill pill-err", text: "已推送" })
                        : el("span", { class: "pill pill-muted", text: "未推送" }) },
                    { text: t.seen_at ? fmtAgo(Math.floor(Date.now() / 1000) - t.seen_at) : "—" }
                ] };
            });

            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title", text: "告警" }),
                        el("p", { class: "page-sub",
                            text: "连续 " + (conf.threshold || 3) + " 次判定离线才推送，避免一次采集抖动就刷屏。" })),
                    el("div", { class: "page-actions" },
                        el("button", { class: "btn", type: "button", text: "发送测试告警",
                                       onclick: sendTestAlert }))),

                el("div", { class: "grid grid-3 section" },
                    stat("总开关", conf.enabled ? "已开启" : "关闭",
                         conf.enabled ? null : "SSH 运行 wgmgr → 告警设置 打开"),
                    stat("监控范围", conf.watch, "all / sites / clients / 名称列表"),
                    stat("确认次数", conf.threshold, "防抖阈值")),

                section("渠道", "Token 和 Webhook 地址不会回传到浏览器，这里只显示“配没配”",
                    null,
                    card([el("div", { class: "grid grid-3" },
                        Object.keys(CHANNEL_LABEL).map(function (key) {
                            var on = !!configured[key];
                            var enabled = (conf.channels || []).indexOf(key) >= 0;
                            return el("div", { class: "card card-pad", style: { background: "var(--bg-soft)" } },
                                el("div", { style: { display: "flex", alignItems: "center", gap: "8px" } },
                                    el("strong", { text: CHANNEL_LABEL[key] }),
                                    on ? el("span", { class: "pill pill-ok", text: "已配置" })
                                       : el("span", { class: "pill pill-muted", text: "未配置" }),
                                    enabled ? el("span", { class: "pill pill-info", text: "已启用" }) : null));
                        }))]),
                        el("p", { class: "section-sub", style: { marginTop: "10px" } },
                            "渠道的凭据只能在服务器上用 wgmgr → 告警设置 里配置 —— " +
                            "面板不提供修改入口，因为它自己也不该把 token 显示出来。")),

                section("防抖跟踪", "每个 Peer 当前连续判定离线的次数；达到阈值才推送", null,
                    trackRows.length ? table([
                        { label: "Peer" }, { label: "类型" }, { label: "状态" },
                        { label: "连续未通过" }, { label: "是否已推送" }, { label: "最后出现" }
                    ], trackRows) : emptyBox("还没有任何 Peer 进入跟踪。")),

                section("最近告警事件", "最新 100 条，倒序", null,
                    events.length ? card(events.map(function (ev) {
                        return el("div", { class: "check " + (ev.ok ? "lv-pass" : "lv-error") },
                            el("div", { class: "check-mark", text: ev.ok ? "✓" : "✕" }),
                            el("div", { class: "check-body" },
                                el("div", { class: "check-title" },
                                    (ev.t_str || "") + "  ",
                                    el("span", { class: "mono", text: ev.peer || "-" }),
                                    " · " + (ev.kind || "") +
                                    ((ev.channels && ev.channels.length)
                                        ? " → " + ev.channels.join(", ") : "")),
                                ev.detail ? el("div", { class: "check-detail", text: ev.detail }) : null,
                                (ev.errors && ev.errors.length)
                                    ? el("div", { class: "check-detail",
                                          text: "发送失败：" + ev.errors.join("；") })
                                    : null));
                    }), false) : emptyBox("还没有发过告警。"))
            ]);
        });
    };

    // ---- 防火墙 ----
    views.firewall = function (host) {
        return Promise.all([api("/api/v1/firewall"), api("/api/v1/routes")]).then(function (res) {
            var fw = res[0] || {}, routes = res[1] || {};

            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title", text: "防火墙 / NAT / 路由" }),
                        el("p", { class: "page-sub",
                            text: "规则由采集进程以 root 抓取后落到 state/，面板本身是非特权进程，读不到内核规则。" })),
                    el("div", { class: "page-actions" },
                        el("button", { class: "btn", type: "button", text: "重新同步防火墙",
                                       onclick: function () {
                                           action("POST", "/api/v1/firewall/sync", {}, "防火墙已重新同步");
                                       } }))),

                el("div", { class: "grid grid-3 section" },
                    stat("后端", fw.backend, fw.available ? "快照于 " + dash(fw.generated_at_str) : fw.reason),
                    stat("UDP 端口监听", fw.port_listening ? "是" : "否"),
                    stat("NAT 规则存在", fw.nat_rule_present ? "是" : "否")),

                section("当前规则", "只包含脚本自己打了 wg-manager 标签的规则", null,
                    fw.available && fw.raw
                        ? card([el("pre", { class: "raw", text: fw.raw })])
                        : emptyBox(fw.reason || "还没有防火墙快照。")),

                section("脚本维护的静态路由", "写在 routes.conf 里，接口起来时下发", null,
                    (routes.routes || []).length ? table([
                        { label: "名称" }, { label: "目标网段" }, { label: "经由" }, { label: "备注" }
                    ], routes.routes.map(function (r) {
                        return { cols: [
                            { text: r.name, class: "mono" },
                            { text: r.subnet, class: "mono" },
                            { text: r.via, class: "mono" },
                            { text: r.comment }
                        ] };
                    })) : emptyBox("没有自定义静态路由。")),

                section("内核里实际的路由", "wg 接口上的路由表，和上面那份对不上就说明有人手改过", null,
                    (routes.kernel_routes || []).length
                        ? card([el("pre", { class: "raw", text: routes.kernel_routes.join("\n") })])
                        : emptyBox("接口上没有路由，或者接口没起来。"))
            ]);
        });
    };

    // ---- 日志 ----
    views.logs = function (host) {
        var n = state.logLines || 150;
        return api("/api/v1/logs?n=" + n).then(function (data) {
            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title", text: "操作日志" }),
                        el("p", { class: "page-sub",
                            text: data.available
                                ? "尾部 " + (data.count || 0) + " 行 · 快照于 " + dash(data.generated_at)
                                : (data.reason || "还没有日志快照") })),
                    el("div", { class: "page-actions" },
                        [50, 150, 500].map(function (v) {
                            return el("button", { class: "tab" + (n === v ? " active" : ""),
                                type: "button", text: v + " 行",
                                onclick: function () { state.logLines = v; refresh(); } });
                        }))),
                (data.lines || []).length
                    ? card([el("pre", { class: "raw" },
                        data.lines.map(function (line) {
                            return el("div", { class: "logline", text: line });
                        }))])
                    : emptyBox("日志是空的。")
            ]);
        });
    };

    // ---- 系统 ----
    views.system = function (host) {
        return api("/api/v1/system").then(function (data) {
            var sys = data.system || {}, web = data.web || {}, coll = data.collector || {};
            var memTotal = sys.mem_total_kb || 0, memAvail = sys.mem_avail_kb || 0;
            var memUsedPct = memTotal ? Math.round((1 - memAvail / memTotal) * 100) : null;

            appendAll(host, [
                el("div", { class: "page-head" },
                    el("div", {},
                        el("h1", { class: "page-title", text: "系统" }),
                        el("p", { class: "page-sub", text: dash(data.hostname) + " · " + dash(data.version) })),
                    el("div", { class: "page-actions" },
                        el("button", { class: "btn", type: "button", text: "立即备份",
                                       onclick: function () {
                                           action("POST", "/api/v1/backup", {}, "备份已创建");
                                       } }))),

                el("div", { class: "grid grid-4 section" },
                    stat("运行时间", sys.uptime_sec ? fmtDuration(sys.uptime_sec) : "—"),
                    stat("负载", (sys.loadavg || []).map(function (x) { return Number(x).toFixed(2); }).join(" / ")),
                    stat("内存占用", memUsedPct === null ? "—" : memUsedPct + "%",
                         memTotal ? fmtBytes(memAvail * 1024) + " 可用 / " + fmtBytes(memTotal * 1024) : null),
                    stat("根分区可用", sys.disk_avail_kb_root ? fmtBytes(sys.disk_avail_kb_root * 1024) : "—")),

                el("div", { class: "grid grid-2 section" },
                    card([
                        el("h2", { class: "section-title", style: { marginTop: "0" }, text: "环境" }),
                        kvList([
                            ["系统", dash(sys.os)],
                            ["内核", dash(sys.kernel)],
                            ["架构", dash(sys.arch)],
                            ["容器内", sys.in_container ? "是（Docker / LXC）" : "否"],
                            ["PVE 宿主机", sys.is_pve_host ? "是" : "否"],
                            ["装了 Docker", sys.has_docker ? "是" : "否"],
                            ["wg 命令", sys.wg_installed ? "已安装" : "缺失"]
                        ]),
                        sys.in_container || sys.is_pve_host || sys.has_docker
                            ? el("div", { class: "topo-note", style: { marginTop: "12px" } },
                                "这台机器上有别的组件在动防火墙/网络。脚本的 nftables 持久化只导出自己那几张表，" +
                                "绝不覆盖 /etc/nftables.conf —— 否则 Docker 和 PVE 的动态规则会被冻成僵尸规则，" +
                                "重启后容器全部断网。")
                            : null
                    ]),
                    card([
                        el("h2", { class: "section-title", style: { marginTop: "0" }, text: "转发与监听" }),
                        kvList([
                            ["IPv4 转发", boolNode(sys.ipv4_forward)],
                            ["IPv6 转发", boolNode(sys.ipv6_forward)],
                            ["UDP 端口监听", boolNode(sys.port_listening)],
                            ["NAT 规则", boolNode(sys.nat_rule_present)]
                        ]),
                        el("h2", { class: "section-title", style: { marginTop: "16px" }, text: "面板服务" }),
                        kvList([
                            ["已安装", boolNode(web.installed)],
                            ["运行中", boolNode(web.running)],
                            ["监听", dash(web.listen)],
                            ["程序目录", el("span", { class: "mono", text: dash(web.app_dir) })],
                            ["采集进程", boolNode(coll.running)],
                            ["采集间隔", coll.interval_sec ? coll.interval_sec + " 秒" : "—"]
                        ])
                    ]))
            ]);
        });
    };

    function boolNode(v) {
        return v ? el("span", { class: "pill pill-ok", text: "是" })
                 : el("span", { class: "pill pill-muted", text: "否" });
    }

    // ==================================================================
    // 动作
    // ==================================================================

    function action(method, path, body, okMessage) {
        return api(path, { method: method, body: body }).then(function (res) {
            if (okMessage) toast(okMessage, "ok");
            if (res && res.detail) {
                openModal({ title: "执行结果", wide: true, body: [
                    el("pre", { class: "raw", text: res.detail })
                ], buttons: [{ label: "关闭", onClick: closeModal }] });
            }
            refresh();
            return res;
        }).catch(function (exc) {
            toast(exc.message || String(exc), "err");
            throw exc;
        });
    }

    function togglePeer(p) {
        var next = p.enabled ? "disable" : "enable";
        action("POST", "/api/v1/peers/" + encodeURIComponent(p.name) + "/" + next, {},
               p.name + " 已" + (p.enabled ? "禁用" : "启用"))
            .catch(function () { /* toast 已经弹过了 */ });
    }

    function deletePeer(p) {
        confirmByName({
            name: p.name,
            title: "删除 " + p.name,
            confirmLabel: "永久删除",
            message: "这会删掉它的目录、密钥和 wg0.conf 里的 Peer 段落，不可恢复。" +
                     (p.kind === "site"
                        ? " 对端的路由和防火墙规则需要你自己去对端机器上清。"
                        : " 这台设备上的配置会立刻失效。"),
            onConfirm: function () {
                return api("/api/v1/peers/" + encodeURIComponent(p.name),
                           { method: "DELETE", body: { confirm: p.name } })
                    .then(function () { toast(p.name + " 已删除", "ok"); });
            }
        });
    }

    function rotateKeyDialog(p) {
        confirmByName({
            name: p.name,
            title: "重新生成 " + p.name + " 的密钥",
            confirmLabel: "轮换密钥",
            message: "会为这个客户端生成一对新的密钥并热更新到 wg0.conf。" +
                     "旧配置立刻失效，设备会掉线，直到重新导入新配置。" +
                     "轮换前脚本会自动打一次快照。",
            onConfirm: function () {
                return api("/api/v1/peers/" + encodeURIComponent(p.name) + "/rotate-key",
                           { method: "POST", body: { confirm: p.name } })
                    .then(function () {
                        toast(p.name + " 密钥已轮换，记得重新分发配置", "warn");
                        qrcodeDialog(p.name);
                    });
            }
        });
    }

    function downloadConf(name) {
        apiDownload("/api/v1/peers/" + encodeURIComponent(name) + "/config", name + ".conf")
            .then(function () { toast(name + ".conf 已下载（内含私钥，请妥善保管）", "warn"); })
            .catch(function (exc) { toast(exc.message || String(exc), "err"); });
    }

    function qrcodeDialog(name) {
        var img = el("img", {
            src: "/api/v1/peers/" + encodeURIComponent(name) + "/qrcode.png",
            alt: name + " 的配置二维码"
        });
        var note = el("p", { class: "section-sub", text: "用手机上的 WireGuard App 扫码导入。" });
        img.addEventListener("error", function () {
            clear(img.parentNode).appendChild(el("div", { class: "form-error",
                text: "二维码取不到。可能是当前绑定范围下禁止导出含私钥的配置" +
                      "（公网模式默认禁止），也可能是服务器没装 qrencode。" }));
        });
        openModal({
            title: name + " · 配置二维码",
            body: [el("div", { class: "qr-box" }, img), note],
            buttons: [
                { label: "下载 .conf", onClick: function () { downloadConf(name); } },
                { label: "关闭", class: "btn-primary", onClick: closeModal }
            ]
        });
    }

    function siteTest(name) {
        openModal({ title: "连通性测试 · " + name, wide: true,
            body: [el("div", { class: "loading" }, el("span", { class: "spinner" }), " 正在测试…")] });
        api("/api/v1/sites/" + encodeURIComponent(name) + "/test", { method: "POST", body: {} })
            .then(function (res) {
                openModal({ title: "连通性测试 · " + name, wide: true, body: [
                    el("div", { style: { marginBottom: "10px" } },
                        res.ok ? el("span", { class: "pill pill-ok", text: "测试通过" })
                               : el("span", { class: "pill pill-warn", text: "有项目未通过" })),
                    el("pre", { class: "raw", text: res.output || "（无输出）" })
                ], buttons: [{ label: "关闭", class: "btn-primary", onClick: closeModal }] });
                refresh();
            })
            .catch(function (exc) {
                closeModal();
                toast(exc.message || String(exc), "err");
            });
    }

    function sendTestAlert() {
        api("/api/v1/alerts/test", { method: "POST", body: {} })
            .then(function (res) {
                if (res.ok) {
                    toast("测试告警已发送到：" + (res.sent || []).join("、"), "ok");
                    // 测试发得出去 ≠ 真会告警：总开关是另一回事，
                    // 这里不说一句，很容易出现"测过了但从来没收到过告警"。
                    if (res.enabled === false) {
                        toast("注意：告警总开关还是关的（ALERT_ENABLED=no），" +
                              "真实告警不会推送。SSH 运行 wgmgr → 告警设置 打开。", "warn");
                    }
                } else {
                    toast("部分渠道发送失败：" + ((res.errors || []).join("；") || "未知原因"), "err");
                }
                refresh();
            })
            .catch(function (exc) { toast(exc.message || String(exc), "err"); });
    }

    // ---- 新建客户端 ----
    function addClientDialog() {
        var name = el("input", { class: "mono", type: "text", placeholder: "iphone",
                                 autocomplete: "off", spellcheck: "false", maxlength: "64" });
        var ip4 = el("input", { class: "mono", type: "text", placeholder: "留空自动分配",
                                autocomplete: "off", spellcheck: "false" });
        var allowed = el("input", { class: "mono", type: "text", placeholder: "0.0.0.0/0",
                                    autocomplete: "off", spellcheck: "false" });
        var err = el("p", { class: "form-error", hidden: true });
        var busy = false;

        openModal({
            title: "新建客户端",
            body: [
                err,
                el("label", { class: "field" },
                    el("span", { class: "field-label", text: "名称" }), name,
                    el("p", { class: "field-hint",
                        text: "字母、数字、点、下划线、连字符，1-64 位。会成为目录名。" })),
                el("label", { class: "field" },
                    el("span", { class: "field-label", text: "VPN IPv4（可选）" }), ip4,
                    el("p", { class: "field-hint", text: "留空就从 VPN 网段里自动挑一个没被占用的。" })),
                el("label", { class: "field" },
                    el("span", { class: "field-label", text: "客户端 AllowedIPs（可选）" }), allowed,
                    el("p", { class: "field-hint",
                        text: "0.0.0.0/0 = 这台设备所有流量都走 VPN（全局代理）；" +
                              "填具体网段则只代理那部分。留空用服务端默认值。" }))
            ],
            buttons: [
                { label: "取消", onClick: closeModal },
                { label: "创建", class: "btn-primary", onClick: function (close) {
                    if (busy) return;
                    var n = name.value.trim();
                    if (!n) { showFormError(err, "名称不能为空"); return; }
                    busy = true;
                    api("/api/v1/clients", { method: "POST", body: {
                        name: n, ip4: ip4.value.trim(), allowed_ips: allowed.value.trim()
                    } }).then(function (res) {
                        close();
                        toast("客户端 " + n + " 已创建", "ok");
                        refresh();
                        qrcodeDialog(n);
                    }).catch(function (exc) {
                        busy = false;
                        showFormError(err, exc.message || String(exc));
                    });
                } }
            ]
        });
    }

    // ---- 新建站点 ----
    function addSiteDialog() {
        var f = {};
        ["name", "remote_lan", "remote_wg_ip", "remote_pubkey", "local_lan",
         "remote_endpoint", "keepalive"].forEach(function (key) {
            f[key] = el("input", { class: "mono", type: key === "keepalive" ? "number" : "text",
                                   autocomplete: "off", spellcheck: "false" });
        });
        f.keepalive.placeholder = "25";
        f.keepalive.min = "0"; f.keepalive.max = "600";
        f.name.placeholder = "branch-a";
        f.remote_lan.placeholder = "192.168.20.0/24";
        f.remote_wg_ip.placeholder = "10.77.77.1";
        f.remote_pubkey.placeholder = "对端的公钥（Base64，44 字符）";
        f.local_lan.placeholder = "192.168.10.0/24";
        f.remote_endpoint.placeholder = "203.0.113.7:51820";

        var mode = el("select", {},
            el("option", { value: "routing", text: "routing —— 纯路由，两端都不做 NAT（推荐）" }),
            el("option", { value: "nat", text: "nat —— 本机做 MASQUERADE，对端路由器管不了时用" }));

        var err = el("p", { class: "form-error", hidden: true });
        var busy = false;

        openModal({
            title: "新建 Site-to-Site 站点",
            wide: true,
            body: [
                err,
                el("div", { class: "topo-note", style: { marginBottom: "14px" } },
                    "两端 LAN 网段不能重叠，否则会退化成 conflict 模式（只通 VPN IP）。" +
                    "创建前脚本会自己检查一次。"),
                el("div", { class: "form-row" },
                    el("label", { class: "field" },
                        el("span", { class: "field-label", text: "站点名称" }), f.name),
                    el("label", { class: "field" },
                        el("span", { class: "field-label", text: "对端 LAN 网段" }), f.remote_lan)),
                el("div", { class: "form-row" },
                    el("label", { class: "field" },
                        el("span", { class: "field-label", text: "对端 VPN IP" }), f.remote_wg_ip,
                        el("p", { class: "field-hint", text: "对端在它自己配置里用的那个隧道 IP。" })),
                    el("label", { class: "field" },
                        el("span", { class: "field-label", text: "本站 LAN 网段（可选）" }), f.local_lan)),
                el("label", { class: "field" },
                    el("span", { class: "field-label", text: "对端公钥" }), f.remote_pubkey,
                    el("p", { class: "field-hint", text: "在对端机器上运行 wg pubkey < private.key 得到。" })),
                el("div", { class: "form-row" },
                    el("label", { class: "field" },
                        el("span", { class: "field-label", text: "对端 Endpoint（可选）" }), f.remote_endpoint,
                        el("p", { class: "field-hint", text: "留空就是被动等对端先连过来。" })),
                    el("label", { class: "field" },
                        el("span", { class: "field-label", text: "PersistentKeepalive（秒）" }), f.keepalive,
                        el("p", { class: "field-hint",
                            text: "两端都在 NAT 后面时强烈建议填 25，否则映射过期后隧道会静默断掉。" }))),
                el("label", { class: "field" },
                    el("span", { class: "field-label", text: "模式" }), mode,
                    el("p", { class: "field-hint",
                        text: "routing 是 WireGuard 官方推荐做法：站点之间不做 MASQUERADE，" +
                              "对端看到的就是真实源 IP，排障直观。只有对端路由器加不了静态路由时才用 nat。" }))
            ],
            buttons: [
                { label: "取消", onClick: closeModal },
                { label: "创建站点", class: "btn-primary", onClick: function (close) {
                    if (busy) return;
                    busy = true;
                    api("/api/v1/sites", { method: "POST", body: {
                        name: f.name.value.trim(),
                        remote_lan: f.remote_lan.value.trim(),
                        remote_wg_ip: f.remote_wg_ip.value.trim(),
                        remote_pubkey: f.remote_pubkey.value.trim(),
                        local_lan: f.local_lan.value.trim(),
                        remote_endpoint: f.remote_endpoint.value.trim(),
                        keepalive: f.keepalive.value.trim(),
                        mode: mode.value
                    } }).then(function (res) {
                        close();
                        toast("站点 " + f.name.value.trim() + " 已创建（" + res.mode + " 模式）", "ok");
                        if (res.detail) {
                            openModal({ title: "创建结果 · 对端需要做的配置", wide: true, body: [
                                el("p", { class: "section-sub",
                                    text: "把下面这段抄到对端机器上。两边的配置是成对的，缺一不可。" }),
                                el("pre", { class: "raw", text: res.detail })
                            ], buttons: [{ label: "关闭", class: "btn-primary", onClick: closeModal }] });
                        }
                        refresh();
                    }).catch(function (exc) {
                        busy = false;
                        showFormError(err, exc.message || String(exc));
                    });
                } }
            ]
        });
    }

    function showFormError(node, message) {
        node.textContent = message;
        node.hidden = false;
    }

    // ==================================================================
    // 路由 / 导航
    // ==================================================================

    var NAV = [
        { key: "overview", hash: "#/overview", label: "概览", ico: "▦" },
        { key: "peers",    hash: "#/peers",    label: "Peer",  ico: "◈" },
        { key: "sites",    hash: "#/sites",    label: "站点",   ico: "⇄" },
        { key: "traffic",  hash: "#/traffic",  label: "流量",   ico: "∿" },
        { key: "health",   hash: "#/health",   label: "诊断",   ico: "✚" },
        { key: "alerts",   hash: "#/alerts",   label: "告警",   ico: "◔" },
        { key: "firewall", hash: "#/firewall", label: "防火墙", ico: "⛨" },
        { key: "logs",     hash: "#/logs",     label: "日志",   ico: "≡" },
        { key: "system",   hash: "#/system",   label: "系统",   ico: "⚙" }
    ];

    var state = {
        authed: false,
        user: "",
        nav: null,
        view: "",
        arg: "",
        peerKind: "",
        peerStatus: "",
        trafficRange: "24h",
        logLines: 150,
        showPassing: false,
        interval: 30,
        timer: null,
        token: 0
    };

    function parseHash() {
        var raw = location.hash || "#/overview";
        if (raw.charAt(0) === "#") raw = raw.slice(1);
        var parts = raw.split("/").filter(function (s) { return s !== ""; });
        var view = parts[0] || "overview";
        var arg = parts.slice(1).map(decodeURIComponent).join("/");
        // #/peers/<name> 归到 peers 这个导航项下面高亮
        var navKey = view === "peers" ? "peers" : view;
        if (!NAV.some(function (n) { return n.key === navKey; })) { view = "overview"; navKey = "overview"; arg = ""; }
        return { view: view, arg: arg, navKey: navKey };
    }

    function renderNav(activeKey, badgeCount) {
        if (!state.nav) state.nav = document.getElementById("nav");
        clear(state.nav);
        NAV.forEach(function (item) {
            var badge = (item.key === "health" && badgeCount > 0)
                ? el("span", { class: "nav-badge", text: String(badgeCount) }) : null;
            state.nav.appendChild(el("a", {
                class: "nav-item" + (item.key === activeKey ? " active" : ""),
                href: item.hash
            }, el("span", { class: "nav-ico", text: item.ico }),
               el("span", { text: item.label }),
               badge));
        });
    }

    function refresh() {
        if (!state.authed) return Promise.resolve();
        var route = parseHash();
        var live = document.getElementById("view");
        var myToken = ++state.token;

        var handler;
        if (route.view === "peers" && route.arg) handler = views.peerDetail;
        else handler = views[route.view] || views.overview;

        // 视图先画到一个游离节点上，等数据齐了再整体换进 #view。
        // 直接往 #view 里 append 的话，两次 refresh 重叠（登录时 hashchange
        // 和 showApp 各触发一次、或者点导航正好撞上 15 秒轮询）就会把同一个
        // 视图画两遍——内容翻倍不说，按钮也全是重复的。
        var scratch = el("div");
        clear(live).appendChild(loadingBox());
        renderNav(route.navKey, state.healthBadge || 0);

        return handler(scratch, route.arg).then(function () {
            if (myToken !== state.token) return;   // 已经有更新的请求了，这次的结果作废
            clear(live);
            while (scratch.firstChild) live.appendChild(scratch.firstChild);
        }).catch(function (exc) {
            if (myToken !== state.token) return;
            if (exc instanceof ApiError && exc.status === 401) return;
            clear(live).appendChild(el("div", { class: "card card-pad" },
                el("p", { class: "form-error", text: "加载失败：" + (exc.message || exc) }),
                el("p", { class: "section-sub" },
                    "状态文件可能还没生成。SSH 上去跑一次 wgmgr collect 看看报什么错。"),
                el("button", { class: "btn", type: "button", text: "重试", onclick: refresh })));
        });
    }

    // 顶栏那两个常驻指示器：接口状态 + state 年龄。单独拉一次 status，
    // 这样切换视图时它们不会跟着闪。
    function refreshTopbar() {
        if (!state.authed) return;
        api("/api/v1/status").then(function (st) {
            var iface = st.interface || {};
            var pill = document.getElementById("iface-pill");
            clear(pill);
            pill.className = "pill " + (iface.running ? "pill-ok" : "pill-err");
            pill.appendChild(el("span", { class: "dot" + (iface.running ? " dot-pulse" : "") }));
            pill.appendChild(document.createTextNode(
                (iface.name || "wg0") + (iface.running ? " UP" : " DOWN")));

            var age = document.getElementById("state-age");
            var secs = st._state_age_sec;
            age.className = "pill " + (st._state_stale ? "pill-warn" : "pill-muted");
            age.textContent = secs === null || secs === undefined
                ? "无状态数据"
                : "状态 " + fmtDuration(secs) + "前";
            age.title = "state/status.json 生成于 " + dash(st.generated_at_str);

            if (st.who) {
                state.user = st.who;
                document.getElementById("whoami").textContent = st.who;
            }
            if ((st.collector || {}).interval_sec) state.interval = st.collector.interval_sec;
        }).catch(function () { /* 401 已经在 api() 里处理了 */ });
    }

    function refreshHealthBadge() {
        if (!state.authed) return;
        api("/api/v1/health").then(function (h) {
            var c = h.counts || {};
            state.healthBadge = (c.error || 0) + (c.warn || 0);
            var route = parseHash();
            renderNav(route.navKey, state.healthBadge);
        }).catch(function () { /* 忽略 */ });
    }

    // ==================================================================
    // 会话
    // ==================================================================

    function showLogin(message) {
        state.authed = false;
        document.getElementById("app").hidden = true;
        document.getElementById("login").hidden = false;
        var err = document.getElementById("login-error");
        if (message) { err.textContent = message; err.hidden = false; }
        else err.hidden = true;
        document.getElementById("login-pass").value = "";
        setTimeout(function () { document.getElementById("login-user").focus(); }, 30);
    }

    function sessionExpired() {
        if (!state.authed) return;
        state.authed = false;
        closeModal();
        showLogin("会话已过期，请重新登录。");
    }

    function showApp() {
        state.authed = true;
        document.getElementById("login").hidden = true;
        document.getElementById("app").hidden = false;
        if (!location.hash) location.hash = "#/overview";
        refresh();
        refreshTopbar();
        refreshHealthBadge();
    }

    function bindLogin() {
        var form = document.getElementById("login-form");
        var btn = document.getElementById("login-btn");
        // CSP 的 form-action 'none' 会拦掉真的表单提交，所以必须 preventDefault。
        form.addEventListener("submit", function (ev) {
            ev.preventDefault();
            var user = document.getElementById("login-user").value.trim();
            var pass = document.getElementById("login-pass").value;
            if (!user || !pass) { showLogin("请输入用户名和口令。"); return; }
            btn.disabled = true;
            btn.textContent = "登录中…";
            api("/api/v1/login", { method: "POST", body: { username: user, password: pass } })
                .then(function (res) {
                    state.user = res.user || user;
                    document.getElementById("whoami").textContent = state.user;
                    btn.disabled = false;
                    btn.textContent = "登录";
                    showApp();
                })
                .catch(function (exc) {
                    btn.disabled = false;
                    btn.textContent = "登录";
                    showLogin(exc.message || "登录失败");
                });
        });
    }

    function bindTopbar() {
        document.getElementById("btn-logout").addEventListener("click", function () {
            api("/api/v1/logout", { method: "POST", body: {} })
                .catch(function () { /* 忽略 */ })
                .then(function () { showLogin(); toast("已退出", "info"); });
        });
        document.getElementById("btn-collect").addEventListener("click", function () {
            var btn = this;
            btn.disabled = true;
            api("/api/v1/collect", { method: "POST", body: {} })
                .then(function (res) {
                    toast("状态已刷新：" + dash(res.state), "ok");
                    refreshTopbar(); refreshHealthBadge(); refresh();
                })
                .catch(function (exc) { toast(exc.message || String(exc), "err"); })
                .then(function () { btn.disabled = false; });
        });
    }

    // ==================================================================
    // 启动
    // ==================================================================

    function startTimer() {
        if (state.timer) clearInterval(state.timer);
        state.timer = setInterval(function () {
            // 页面不可见时不刷：省流量，也避免回到标签页时一堆请求同时打过去。
            if (document.hidden) return;
            // 弹窗开着时不刷：重绘会把用户正在填的表单直接冲掉。
            if (modalOpen) return;
            refresh();
            refreshTopbar();
        }, REFRESH_MS);
    }

    function boot() {
        bindLogin();
        bindTopbar();
        window.addEventListener("hashchange", function () { if (state.authed) refresh(); });

        // 先探一次：Cookie 还在的话直接进主界面，不用重新登录。
        api("/api/v1/status").then(function (st) {
            if (st.who) state.user = st.who;
            showApp();
            startTimer();
        }).catch(function (exc) {
            if (exc instanceof ApiError && exc.status === 401) { showLogin(); return; }
            // 连不上服务端（服务没起、TLS 证书不对）：给一句人话，别显示空白页。
            showLogin("无法连接面板服务：" + (exc.message || exc));
        });
    }

    if (document.readyState === "loading") document.addEventListener("DOMContentLoaded", boot);
    else boot();
})();
