import base64
import json
import time
import socket
import requests
import yaml
from flask import Flask, request, Response

app = Flask(__name__)

# -----------------------------
# 国旗映射
# -----------------------------
FLAG_MAP = {
    "JP": "🇯🇵",
    "US": "🇺🇸",
    "HK": "🇭🇰",
    "SG": "🇸🇬",
    "TW": "🇹🇼",
    "KR": "🇰🇷",
    "DE": "🇩🇪",
    "GB": "🇬🇧",
    "FR": "🇫🇷",
    "AU": "🇦🇺",
}

# -----------------------------
# 订阅内容缓存（按 URL / Base64 缓存）
# -----------------------------
SUB_CACHE = {}
SUB_CACHE_TTL = 600  # 10 分钟

# -----------------------------
# 延迟缓存（按 host:port 缓存）
# -----------------------------
LATENCY_CACHE = {}
LATENCY_TTL = 600  # 10 分钟


def is_url(text: str) -> bool:
    return text.startswith("http://") or text.startswith("https://")


def download_sub_with_cache(key: str) -> str:
    now = time.time()
    if key in SUB_CACHE:
        ts, content = SUB_CACHE[key]
        if now - ts < SUB_CACHE_TTL:
            return content

    resp = requests.get(key, timeout=10)
    content = resp.text.strip()
    SUB_CACHE[key] = (now, content)
    return content


def get_country_code(host: str):
    try:
        ip = socket.gethostbyname(host)
        r = requests.get(f"https://ipapi.co/{ip}/country_code/", timeout=3)
        code = r.text.strip().upper()
        return code if len(code) == 2 else None
    except:
        return None


def get_flag(host: str) -> str:
    code = get_country_code(host)
    if not code:
        return ""
    return FLAG_MAP.get(code, f"🏳️({code})")


def tcp_latency(host: str, port: int) -> int:
    key = f"{host}:{port}"
    now = time.time()

    if key in LATENCY_CACHE:
        ts, value = LATENCY_CACHE[key]
        if now - ts < LATENCY_TTL:
            return value

    start = time.time()
    try:
        with socket.create_connection((host, int(port)), timeout=3):
            latency = int((time.time() - start) * 1000)
    except:
        latency = 9999

    LATENCY_CACHE[key] = (now, latency)
    return latency


def parse_v2ray_base64(text: str):
    try:
        raw = base64.b64decode(text + "==").decode("utf-8", errors="ignore")
    except:
        return []

    nodes = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

        # vmess://
        if line.startswith("vmess://"):
            try:
                data = json.loads(base64.b64decode(line[8:]).decode("utf-8"))
                nodes.append({
                    "name": data.get("ps", "vmess节点"),
                    "type": "vmess",
                    "server": data["add"],
                    "port": int(data["port"]),
                    "uuid": data["id"],
                    "tls": data.get("tls", "") == "tls"
                })
            except:
                continue

        # vless://
        elif line.startswith("vless://"):
            try:
                url = line[8:]
                if "#" in url:
                    url = url.split("#")[0]
                uuid, rest = url.split("@", 1)
                if "?" in rest:
                    server_port, _ = rest.split("?", 1)
                else:
                    server_port = rest
                server, port = server_port.split(":", 1)
                nodes.append({
                    "name": f"vless_{server}",
                    "type": "vless",
                    "server": server,
                    "port": int(port),
                    "uuid": uuid,
                    "tls": True
                })
            except:
                continue

        # trojan://
        elif line.startswith("trojan://"):
            try:
                url = line[9:]
                if "#" in url:
                    url = url.split("#")[0]
                password, rest = url.split("@", 1)
                server, port = rest.split(":", 1)
                nodes.append({
                    "name": f"trojan_{server}",
                    "type": "trojan",
                    "server": server,
                    "port": int(port),
                    "password": password,
                    "sni": ""
                })
            except:
                continue

    return nodes


def ensure_unique_names(nodes):
    used = {}
    for n in nodes:
        base = n["name"]
        if base not in used:
            used[base] = 1
        else:
            used[base] += 1
            base = f"{base}_{used[base]}"
        n["name"] = base
    return nodes


def build_clash_proxy(node):
    t = node["type"]
    base = {
        "name": node["name"],
        "server": node["server"],
        "port": node["port"],
    }

    if t == "vmess":
        base.update({
            "type": "vmess",
            "uuid": node["uuid"],
            "alterId": 0,
            "cipher": "auto",
            "tls": node["tls"],
            "network": "tcp",
        })
    elif t == "vless":
        base.update({
            "type": "vless",
            "uuid": node["uuid"],
            "flow": "",
            "udp": True,
            "tls": node["tls"],
            "network": "tcp",
        })
    elif t == "trojan":
        base.update({
            "type": "trojan",
            "password": node["password"],
            "sni": node["sni"],
            "udp": True,
        })
    return base


def generate_clash_yaml(nodes):
    proxies = [build_clash_proxy(n) for n in nodes]
    names = [n["name"] for n in nodes]

    config = {
        "proxies": proxies,
        "proxy-groups": [
            {
                "name": "🚀 节点选择",
                "type": "select",
                "proxies": names
            },
            {
                "name": "🌍 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": names
            }
        ],
        "rules": [
            "GEOIP,CN,DIRECT",
            "MATCH,🚀 节点选择"
        ]
    }

    return yaml.dump(config, allow_unicode=True, sort_keys=False)


@app.route("/sub")
def sub():
    """
    多订阅合并：
    - 支持 ?url=xxx&url=yyy
    - 支持 ?urls=xxx,yyy,zzz
    - 每个可以是 URL 或 Base64
    """
    urls = request.args.getlist("url")
    urls_param = request.args.get("urls", "").strip()

    if urls_param:
        urls.extend([u.strip() for u in urls_param.split(",") if u.strip()])

    if not urls:
        return "缺少参数 url 或 urls", 400

    all_nodes = []

    for item in urls:
        try:
            if is_url(item):
                base64_text = download_sub_with_cache(item)
            else:
                base64_text = item

            nodes = parse_v2ray_base64(base64_text)
            all_nodes.extend(nodes)
        except Exception:
            continue

    if not all_nodes:
        return "未解析到任何节点", 400

    # 加国旗 + 测速
    for n in all_nodes:
        flag = get_flag(n["server"])
        latency = tcp_latency(n["server"], n["port"])
        n["latency"] = latency
        label = f"{latency}ms" if latency < 9999 else "timeout"
        n["name"] = f"{flag} {n['name']} | {label}" if flag else f"{n['name']} | {label}"

    # 按延迟排序
    all_nodes.sort(key=lambda x: x["latency"])

    # 去重命名
    all_nodes = ensure_unique_names(all_nodes)

    yaml_text = generate_clash_yaml(all_nodes)
    return Response(yaml_text, mimetype="text/yaml")


if __name__ == "__main__":
    # 容器环境下会被外部端口映射
    app.run(host="0.0.0.0", port=5000)
