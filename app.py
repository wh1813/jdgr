import base64
import json
import time
import socket
import requests
import yaml
from flask import Flask, request, Response

app = Flask(__name__)

# ---------------------------------------------------------
# ★ 新增：ACME 证书验证路由（ClawCloud 必须）
# ---------------------------------------------------------
@app.route('/.well-known/acme-challenge/<path:filename>')
def acme_challenge(filename):
    return filename, 200


# ---------------------------------------------------------
# 原有功能：国旗映射
# ---------------------------------------------------------
FLAG_MAP = {
    "JP": "🇯🇵", "US": "🇺🇸", "HK": "🇭🇰", "SG": "🇸🇬",
    "TW": "🇹🇼", "KR": "🇰🇷", "DE": "🇩🇪", "GB": "🇬🇧",
    "FR": "🇫🇷", "AU": "🇦🇺",
}

SUB_CACHE = {}
SUB_CACHE_TTL = 600
LATENCY_CACHE = {}
LATENCY_TTL = 600


def load_local_subs():
    """读取 subs.txt 中的订阅地址"""
    try:
        with open("subs.txt", "r", encoding="utf-8") as f:
            return [line.strip() for line in f if line.strip()]
    except:
        return []


def is_url(text):
    return text.startswith("http://") or text.startswith("https://")


def download_sub_with_cache(key):
    now = time.time()
    if key in SUB_CACHE:
        ts, content = SUB_CACHE[key]
        if now - ts < SUB_CACHE_TTL:
            return content
    resp = requests.get(key, timeout=10)
    content = resp.text.strip()
    SUB_CACHE[key] = (now, content)
    return content


def get_country_code(host):
    try:
        ip = socket.gethostbyname(host)
        r = requests.get(f"https://ipapi.co/{ip}/country_code/", timeout=3)
        code = r.text.strip().upper()
        return code if len(code) == 2 else None
    except:
        return None


def get_flag(host):
    code = get_country_code(host)
    return FLAG_MAP.get(code, f"🏳️({code})") if code else ""


def tcp_latency(host, port):
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


def parse_v2ray_base64(text):
    try:
        raw = base64.b64decode(text + "==").decode("utf-8", errors="ignore")
    except:
        return []
    nodes = []
    for line in raw.splitlines():
        line = line.strip()
        if not line:
            continue

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

        elif line.startswith("vless://"):
            try:
                url = line[8:].split("#")[0]
                uuid, rest = url.split("@", 1)
                server_port = rest.split("?", 1)[0]
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

        elif line.startswith("trojan://"):
            try:
                url = line[9:].split("#")[0]
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
    base = {"name": node["name"], "server": node["server"], "port": node["port"]}

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
            {"name": "🚀 节点选择", "type": "select", "proxies": names},
            {
                "name": "🌍 自动选择",
                "type": "url-test",
                "url": "http://www.gstatic.com/generate_204",
                "interval": 300,
                "proxies": names
            }
        ],
        "rules": ["GEOIP,CN,DIRECT", "MATCH,🚀 节点选择"]
    }
    return yaml.dump(config, allow_unicode=True, sort_keys=False)


@app.route("/sub")
def sub():
    urls = request.args.getlist("url")
    urls_param = request.args.get("urls", "").strip()
    if urls_param:
        urls.extend([u.strip() for u in urls_param.split(",") if u.strip()])

    local_subs = load_local_subs()
    urls.extend(local_subs)

    if not urls:
        return "没有订阅地址", 400

    all_nodes = []

    for item in urls:
        try:
            if is_url(item):
                base64_text = download_sub_with_cache(item)
            else:
                base64_text = item
            nodes = parse_v2ray_base64(base64_text)
            all_nodes.extend(nodes)
        except:
            continue

    if not all_nodes:
        return "未解析到任何节点", 400

    for n in all_nodes:
        flag = get_flag(n["server"])
        latency = tcp_latency(n["server"], n["port"])
        label = f"{latency}ms" if latency < 9999 else "timeout"
        n["latency"] = latency
        n["name"] = f"{flag} {n['name']} | {label}"

    all_nodes.sort(key=lambda x: x["latency"])
    all_nodes = ensure_unique_names(all_nodes)

    yaml_text = generate_clash_yaml(all_nodes)
    return Response(yaml_text, mimetype="text/yaml")


@app.route("/")
def index():
    return "ClawCloud Subscription Server Running", 200


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000)
