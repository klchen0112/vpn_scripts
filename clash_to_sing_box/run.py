import requests
import yaml
import json
import copy
import argparse
import requests
import re

parser = argparse.ArgumentParser(description="")

parser.add_argument("--use_v6", help="whether to use ipv6", action="store_true")
parser.add_argument(
    "--config",
    help="which config use",
    type=str,
    default="simple",
    choices=["simple", "complex"],
)
parser.add_argument("--tun", help="use tun inbound", action="store_true")
parser.add_argument("--mixed", help="use mixed inbound", action="store_true")
parser.add_argument("--lan", help="use lan mode", action="store_true")
parser.add_argument("--docker", help="docker version", action="store_true")
parser.add_argument("--dns_private", help="direct dns", type=str, default="dhcp://auto")
parser.add_argument(
    "--dns_direct", help="direct dns", type=str, default="h3://dns.alidns.com/dns-query"
)
parser.add_argument(
    "--dns_remote",
    help="remote dns",
    type=str,
    default="https://cloudflare-dns.com/dns-query",
)
args = parser.parse_args()


URL_TEST_BASE = {
    "type": "urltest",
    "tag": "",
    "outbounds": [],
    "url": "https://www.gstatic.com/generate_204",
    "interval": "3m",
    "tolerance": 50,
}

local_RULES = {}


def process_proxy(proxy):
    if proxy["type"] == "ss":
        ss_server_base = {
            "type": "shadowsocks",
            "tag": "",
            "server": "",
            "server_port": "",
            "method": "",
            "password": "",
        }
        result = copy.deepcopy(ss_server_base)
        result["tag"] = proxy["name"]
        result["server"] = proxy["server"]
        result["server_port"] = int(proxy["port"])
        result["method"] = proxy["cipher"]
        result["password"] = proxy["password"]
        return result
    elif proxy["type"] == "trojan":
        trojan_server_base = {
            "type": "trojan",
            "tag": "",
            "server": "",
            "server_port": "",
            "password": "",
        }
        result = copy.deepcopy(trojan_server_base)
        result["tag"] = proxy["name"]
        result["server"] = proxy["server"]
        result["server_port"] = int(proxy["port"])
        result["password"] = proxy["password"]
        if "sni" in proxy:
            result["tls"] = {
                "enabled": True,
                "disable_sni": False,
                "server_name": proxy["sni"],
                "insecure": False,
            }
            if "skip-cert-verify" in proxy:
                result["tls"]["insecure"] = True
        if "network" in proxy:
            result["transport"] = {
                "type": "ws",
            }
        if "udp" in proxy:
            if not proxy["udp"]:
                result["network"] = "tcp"
        return result
    elif proxy["type"] == "vmess":
        vmess_server_base = {
            "type": "vmess",
            "tag": "",
            "server": "",
            "server_port": -1,
            "uuid": "",
            "alter_id": "",
        }
        result = copy.deepcopy(vmess_server_base)
        result["tag"] = proxy["name"]
        result["server"] = proxy["server"]
        result["server_port"] = int(proxy["port"])
        result["uuid"] = proxy["uuid"]
        result["alter_id"] = proxy["alterId"]
        result["security"] = proxy["cipher"]
        if proxy["network"] == "ws":
            result["transport"] = {
                "type": "ws",
                "path": proxy["ws-path"],
                "headers": {"Host": [proxy["ws-opts"]["headers"]["Host"]]},
            }
        elif proxy["network"] == "grpc":
            result["transport"] = {
                "type": "grpc",
                "service_name": proxy["grpc-opts"]["grpc-service-name"],
            }
        return result
    elif proxy["type"] == "hysteria2":
        hysteria2_server_base = {
            "type": "hysteria2",
            "tag": "",
            "server": "",
            "server_port": -1,
            "password": "",
            "tls": {
                "enabled": True,
                "insecure": False,
                "server_name": None,
            },
            "up_mbps": 100,
            "down_mbps": 100,
        }
        hysteria2_server_base["tag"] = proxy["name"]
        hysteria2_server_base["server"] = proxy["server"]
        hysteria2_server_base["server_port"] = int(proxy["port"])
        hysteria2_server_base["password"] = proxy["password"]
        hysteria2_server_base["up_mbps"] = proxy["up"]
        hysteria2_server_base["down_mbps"] = proxy["down"]
        return hysteria2_server_base
    else:
        raise ValueError("Wrong proxy type")


PLACE_PATTERNS = {
    "🇭🇰 香港": r"🇭🇰|香港|港|hongkong",
    "🇺🇸 美国": r"🇺🇸|美国|united states",
    "🇹🇼 台湾": r"🇹🇼|台湾",
    "🇯🇵 日本": r"🇯🇵|日本|JP",
    "🇰🇷 韩国": r"🇰🇷|韩国|KR",
    "🇸🇬 新加坡": r"🇸🇬|新加坡|SG",
    "🇷🇺 俄罗斯": r"🇷🇺|俄罗斯",
    "🇫🇷 法国": r"🇫🇷|法国",
    "🇬🇧 英国": r"🇬🇧|英国",
    "🇩🇪 德国": r"🇩🇪|德国",
    "🇨🇦 加拿大": r"🇨🇦|加拿大",
    "🇦🇺 澳大利亚": r"🇦🇺|澳大利亚|澳洲",
    "🇵🇭 菲律宾": r"🇵🇭|菲律宾",
    "🇹🇷 土耳其": r"🇹🇷|土耳其",
    "🇦🇷 阿根廷": r"🇦🇷|阿根廷",
    "🇺🇦 乌克兰": r"🇺🇦|乌克兰",
    "🇧🇷 巴西": r"🇧🇷|巴西",
    "🇮🇳 印度": r"🇮🇳|印度",
    "🇮🇩 印尼": r"🇮🇩|印尼",
    "🇮🇹 意大利": r"🇮🇹|意大利",
    "🇪🇬 埃及": r"🇪🇬|埃及",
    "🇲🇾 马来西亚": r"🇲🇾|马来西亚",
    "🇵🇰 巴基斯坦": r"🇵🇰|巴基斯坦",
    "🇨🇱 智利": r"🇨🇱|智利",
    "🇨🇴 哥伦比亚": r"🇨🇴|哥伦比亚",
    "🇳🇬 尼日利亚": r"🇳🇬|尼日利亚",
    "🇨🇦 加拿大": r"🇨🇦|加拿大",
    "🇸🇪 瑞典": r"🇸🇪|瑞典",
    "🇨🇭 瑞士": r"🇨🇭|瑞士",
}

LOG_SETTINGS = {
    "disabled": False,
    "level": "warn",
    # "output": "box.log",
    "timestamp": True,
}
GLOBAL_DETOUR = "✈️ Proxy"


def get_rule_set_url(rule_type: str, name: str):
    if rule_type == "geosite":
        url = f"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{name}.srs"
    elif rule_type == "geoip":
        url = f"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{name}.srs"
    elif rule_type == "inline":
        return {
            "tag": f"{rule_type}-{name}",
            "type": "inline",
            "rules": [local_RULES[f"{rule_type}-{name}"]],
        }
    else:
        raise ValueError("Wrong rule_type")
    return {
        "tag": f"{rule_type}-{name}",
        "type": "remote",
        "url": url,
        "download_detour": "节点选择",
        "format": "binary",
    }


def get_rule_set(rule_config):
    rule_sets = []

    find = False
    for key, value in rule_config.items():
        if "geosite" in value:
            for name in value["geosite"]:
                rule_sets.append(get_rule_set_url(rule_type="geosite", name=name))
                if name == "geolocation-!cn":
                    find = True
        if "geoip" in value:
            for name in value["geoip"]:
                rule_sets.append(get_rule_set_url(rule_type="geoip", name=name))
        if "inline" in value:
            for name in value["inline"]:
                rule_sets.append(get_rule_set_url(rule_type="inline", name=name))
    if not find:
        rule_sets.append(get_rule_set_url(rule_type="geosite", name="geolocation-!cn"))

    return rule_sets


def get_route_rules(rule_config):
    route_rules = []
    route_rules.append({"protocol": "dns", "outbound": "dns"})
    route_rules.append({"protocol": ["stun", "quic"], "outbound": "🛑 Block"})
    rule_types = ("geoip", "geosite", "inline")
    for key, value in rule_config.items():
        if key == GLOBAL_DETOUR:
            continue
        if "clash_mode" in value:
            outbound = value["outbound"]
            if not (
                isinstance(outbound, str)
                or (
                    isinstance(outbound, list)
                    and len(outbound) == 1
                    and isinstance(outbound[0], str)
                )
            ):
                raise ValueError(f"{key} {value}")
            route_rules.append(
                {"clash_mode": value["clash_mode"], "outbound": outbound}
            )
            continue
        elif "geosite" in value or "geoip" in value or "inline" in value:
            rule_set = []
            outbound = value["outbound"] if "outbound" in value else key
            for rule_type in rule_types:
                if rule_type in value:
                    for name in value[rule_type]:
                        rule_set.append(f"{rule_type}-{name}")
            route_rules.append(
                {
                    "rule_set": rule_set,
                    "outbound": outbound,
                }
            )
        elif "type" in value and value["type"] == "logical":
            route_rules.append(
                {
                    "type": "logical",
                    "mode": value["model"],
                    "rules": [{"protocol": "dns"}, {"port": 53}],
                    "outbound": "dns",
                }
            )
        elif "ip_is_private" in value:
            route_rules.append({"ip_is_private": True, "outbound": "direct"})
    return route_rules


def get_outbounds(rule_config, place_outbound):
    outbounds = []
    place_list = list(place_outbound.keys())

    all_bound_name = []
    for bounds in place_outbound.values():
        for bound in bounds:
            all_bound_name.append(bound["tag"])
    for key, value in rule_config.items():
        if key == GLOBAL_DETOUR:
            outbounds.append(
                {
                    "tag": key,
                    "type": "selector",
                    "outbounds": value["outbounds"],
                    "default": value["default"],
                }
            )
            outbounds.append(
                {
                    "tag": "自动选择",
                    "type": "urltest",
                    "outbounds": all_bound_name,
                    "url": "https://www.gstatic.com/generate_204",
                    "interval": "1m",
                    "tolerance": 50,
                }
            )
            outbounds.append(
                {
                    "tag": "地区选择",
                    "type": "selector",
                    "outbounds": place_list,
                }
            )
            outbounds.append(
                {
                    "tag": "节点选择",
                    "type": "selector",
                    "outbounds": all_bound_name,
                }
            )
            continue
        if "clash_mode" in value:
            continue
        if "type" not in value:
            continue
        if value["type"] in ["direct", "dns", "block"]:
            outbounds.append({"tag": key, "type": value["type"]})
        elif value["type"] == "selector":
            outbounds.append(
                {
                    "tag": key,
                    "type": "selector",
                    "outbounds": value["outbounds"],
                    "default": value["default"],
                }
            )
    for name, place_outbounds in place_outbound.items():
        url_place = copy.deepcopy(URL_TEST_BASE)
        url_place["tag"] = name
        for outbound in place_outbounds:
            url_place["outbounds"].append(outbound["tag"])
        outbounds.append(url_place)
    for bounds in place_outbound.values():
        outbounds.extend(bounds)
    return outbounds


# 如果 outbound不为1那么就流量转自key
rules = {
    "complex": {
        "dns-catch": {
            "type": "logical",
            "model": "or",
            "rules": [{"protocol": "dns"}, {"port": 53}],
            "outbound": "dns",
        },
        "ip_is_private": {"ip_is_private": True, "outbound": "🎯 Direct"},
        "clash_global": {"clash_mode": "Global", "outbound": "节点选择"},
        "clash_direct": {"clash_mode": "Direct", "outbound": "🎯 Direct"},
        "LOCAL_DOMAIN": {
            "inline": ["localdomain"],
            "outbound": "🎯 Direct",
        },
        "direct": {"type": "direct"},
        "dns": {"type": "dns"},
        "block": {"type": "block"},
        GLOBAL_DETOUR: {
            "type": "selector",
            "outbounds": ["地区测速", "地区选择", "节点选择", "direct"],
            "default": "地区测速",
        },
        "🎯 Direct": {
            "type": "selector",
            "outbounds": ["direct", GLOBAL_DETOUR],
            "default": "direct",
        },
        "🛑 Block": {
            "type": "selector",
            "outbounds": ["block", "direct", GLOBAL_DETOUR],
            "default": "block",
        },
        "󱤫 广告过滤": {
            "type": "selector",
            "geosite": ["category-ads-all"],
            "outbounds": ["🛑 Block", "🎯 Direct"],
            "default": "🛑 Block",
        },
        "🤖 AI": {
            "type": "selector",
            "geosite": ["openai"],
            "outbounds": ["🇺🇸 美国", "🎯 Direct"],
            "default": "🇺🇸 美国",
        },
        " Dev-CN": {
            "type": "selector",
            "geosite": ["category-dev-cn"],
            "outbounds": ["🎯 Direct", GLOBAL_DETOUR],
            "default": "🎯 Direct",
        },
        " Dev-Global": {
            "type": "selector",
            "geosite": ["category-dev", "category-container"],
            "outbounds": [GLOBAL_DETOUR, "🎯 Direct"],
            "default": GLOBAL_DETOUR,
        },
        "Schoolar CN": {
            "type": "selector",
            "geosite": ["category-scholar-cn", "category-education-cn"],
            "outbounds": ["🎯 Direct", GLOBAL_DETOUR],
            "default": "🎯 Direct",
        },
        "󰑴 Schoolar Global": {
            "type": "selector",
            "geosite": ["category-scholar-!cn"],
            "outbounds": [
                GLOBAL_DETOUR,
                "🎯 Direct",
            ],
            "default": GLOBAL_DETOUR,
        },
        "󰊭 Google CN": {
            "type": "selector",
            "geosite": ["google@cn"],
            "outbounds": [
                "🎯 Direct",
                GLOBAL_DETOUR,
            ],
            "default": "🎯 Direct",
        },
        "󰊭 Google": {
            "type": "selector",
            "geosite": ["google"],
            # "geoip": ["google"],
            "outbounds": [GLOBAL_DETOUR, "🎯 Direct"],
            "default": GLOBAL_DETOUR,
        },
        "Social Media CN": {
            "type": "selector",
            "geosite": ["category-social-media-cn"],
            "outbounds": ["🎯 Direct", GLOBAL_DETOUR],
            "default": "🎯 Direct",
        },
        " Social Media Global": {
            "type": "selector",
            "geosite": ["category-social-media-!cn", "category-communication"],
            # "geoip": ["telegram", "twitter", "facebook"],
            "outbounds": [
                GLOBAL_DETOUR,
                "🎯 Direct",
            ],
            "default": GLOBAL_DETOUR,
        },
        "󰒚 Shopping": {
            "type": "selector",
            "geosite": ["amazon"],
            "outbounds": [
                GLOBAL_DETOUR,
                "🎯 Direct",
            ],
            "default": GLOBAL_DETOUR,
        },
        "Ⓜ️ Microsoft CN": {
            "type": "selector",
            "geosite": ["microsoft@cn"],
            "outbounds": [
                "🎯 Direct",
                GLOBAL_DETOUR,
            ],
            "default": "🎯 Direct",
        },
        "Ⓜ️ Microsoft": {
            "type": "selector",
            "geosite": ["microsoft"],
            "outbounds": [
                GLOBAL_DETOUR,
                "🎯 Direct",
            ],
            "default": GLOBAL_DETOUR,
        },
        "🍎 Apple CN": {
            "type": "selector",
            "geosite": ["apple@cn"],
            "outbounds": [
                "🎯 Direct",
                GLOBAL_DETOUR,
            ],
            "default": "🎯 Direct",
        },
        "🍎 Apple": {
            "type": "selector",
            "geosite": ["apple"],
            "outbounds": [
                GLOBAL_DETOUR,
                "🎯 Direct",
            ],
            "default": GLOBAL_DETOUR,
        },
        "󱎓 Game CN": {
            "type": "selector",
            "geosite": ["category-games@cn", "category-game-accelerator-cn"],
            "outbounds": [
                "🎯 Direct",
                GLOBAL_DETOUR,
            ],
            "default": "🎯 Direct",
        },
        "🎮 Game Global": {
            "type": "selector",
            "geosite": ["category-games"],
            "outbounds": ["🇯🇵 日本", "🇭🇰 香港", GLOBAL_DETOUR, "🎯 Direct"],
            "default": GLOBAL_DETOUR,
        },
        "哔哩哔哩": {
            "type": "selector",
            "geosite": ["bilibili"],
            "outbounds": [
                "🎯 Direct",
                "🇹🇼 台湾",
                "🇭🇰 香港",
                GLOBAL_DETOUR,
            ],
            "default": "🎯 Direct",
        },
        "巴哈姆特": {
            "type": "selector",
            "geosite": ["bahamut", "bilibili@!cn"],
            "outbounds": [
                "🇹🇼 台湾",
                "🇭🇰 香港",
                GLOBAL_DETOUR,
                "🎯 Direct",
            ],
            "default": "🇹🇼 台湾",
        },
        "国内流媒体": {
            "type": "selector",
            "geosite": ["category-media-cn"],
            "outbounds": [
                "🎯 Direct",
                GLOBAL_DETOUR,
            ],
            "default": "🎯 Direct",
        },
        "󰝆 海外流媒体": {
            "type": "selector",
            # "geoip": ["netflix"],
            "geosite": [
                "category-media",
                "category-entertainment",
            ],
            "outbounds": [
                GLOBAL_DETOUR,
                "🎯 Direct",
            ],
            "default": GLOBAL_DETOUR,
        },
        "🟨 Porn": {
            "type": "selector",
            "geosite": ["category-porn"],
            "outbounds": [
                GLOBAL_DETOUR,
                "🎯 Direct",
            ],
            "default": GLOBAL_DETOUR,
        },
        # " Global": {
        #     "type": "selector",
        #     "geosite": ["geolocation-!cn"],
        #     "outbounds": [
        #         global_detour,
        #         "🎯 Direct",
        #     ],
        #     "default": global_detour,
        # },
        "🇨🇳 CNIP": {
            "type": "selector",
            "geoip": ["cn"],
            "geosite": ["geolocation-cn"],
            "own": ["local_domain_list"],
            "outbounds": [
                "🎯 Direct",
                GLOBAL_DETOUR,
            ],
            "default": "🎯 Direct",
        },
    },
    "simple": {
        "dns-catch": {
            "type": "logical",
            "model": "or",
            "rules": [{"protocol": "dns"}, {"port": 53}],
            "outbound": "dns",
        },
        "ip_is_private": {"ip_is_private": True, "outbound": "🎯 Direct"},
        "clash_global": {"clash_mode": "Global", "outbound": "节点选择"},
        "clash_direct": {"clash_mode": "Direct", "outbound": "🎯 Direct"},
        "LOCAL_DOMAIN": {
            "inline": ["localdomain"],
            "outbound": "🎯 Direct",
        },
        GLOBAL_DETOUR: {
            "type": "selector",
            "outbounds": ["地区测速", "地区选择", "节点选择", "direct"],
            "default": "地区测速",
        },
        "direct": {"type": "direct"},
        "dns": {"type": "dns"},
        "block": {"type": "block"},
        "🎯 Direct": {
            "type": "selector",
            "outbounds": ["direct", GLOBAL_DETOUR],
            "default": "direct",
        },
        "󱤫 广告过滤": {
            "type": "selector",
            "geosite": ["category-ads-all"],
            "outbounds": ["🛑 Block", "🎯 Direct"],
            "default": "🛑 Block",
        },
        "🛑 Block": {
            "type": "selector",
            "outbounds": ["block", "direct", GLOBAL_DETOUR],
            "default": "block",
        },
        "🇨🇳 CNIP": {
            "type": "selector",
            "geoip": ["cn"],
            "geosite": ["geolocation-cn"],
            "own": ["local_domain_list"],
            "outbounds": [
                "🎯 Direct",
                GLOBAL_DETOUR,
            ],
            "default": "🎯 Direct",
        },
    },
}


single_selecor = {
    "type": "selector",
    "tag": "节点选择",
    "outbound": [],
    #   "default": "proxy-c",
    # "interrupt_exist_connections": False,
}


def get_inbounds(
    use_tun: bool, use_mixed: bool, use_v6: bool, listen_lan: bool, docker
):
    result = []
    if use_mixed:
        result.append(
            {
                "type": "mixed",
                "listen": "0.0.0.0" if listen_lan else "127.0.0.1",
                "listen_port": 7890,
                "sniff": True,
                "sniff_override_destination": True,
                "users": [],
                "set_system_proxy": False if docker else True,
                "tcp_fast_open": True,
                "tcp_multi_path": True,
                "udp_fragment": True,
                "domain_strategy": "prefer_ipv4" if use_v6 else "ipv4_only",
            }
        )
    if use_tun and not docker:
        result.append(
            {
                "type": "tun",
                "tag": "tun",
                "inet4_address": "172.19.0.1/30",
                **({"inet6_address": "fdfd:9527::1/32"} if use_v6 else {}),
                "mtu": 9000,
                "auto_route": True,
                "strict_route": True,
                "sniff": True,
                "endpoint_independent_nat": False,
                "stack": "system",
                "platform": {
                    "http_proxy": {
                        "enabled": True,
                        "server": "127.0.0.1",
                        "server_port": 7890,
                    }
                },
            }
        )
    return result


def get_dns_configs(dns_private, dns_direct, dns_remote, use_v6):
    dns_config = {}

    # build servers
    dns_config["servers"] = [
        {
            "tag": "dns-remote",
            "address": dns_remote,
            "detour": GLOBAL_DETOUR,
            "address_resolver": "dns-private",
        },
        {
            "tag": "dns-direct",
            "address": dns_direct,
            "detour": "direct",
            "address_resolver": "dns-private",
        },
        {
            "tag": "dns-private",
            "address": dns_private,
            "detour": "direct",
        },
        {"tag": "dns-block", "address": "rcode://success"},
    ]

    # build rules
    dns_config["rules"] = [
        {"outbound": "any", "server": "dns-direct", "disable_cache": True},
        {"clash_mode": "Direct", "server": "dns-direct"},
        {
            "clash_mode": "Global",
            "server": "dns-remote",
        },
        {
            "domain": [
                "ghproxy.com",
                "cdn.jsdelivr.net",
                "testingcf.jsdelivr.net",
            ],
            "server": "dns-direct",
        },
        {
            "rule_set": "geosite-category-ads-all",
            # 追踪域名DNS解析被黑洞
            "domain_suffix": [
                "appcenter.ms",
                "app-measurement.com",
                "firebase.io",
                "crashlytics.com",
                "google-analytics.com",
            ],
            "server": "dns-block",
            "disable_cache": True,
        },
        {
            "rule_set": ["inline-localdomain"],
            "server": "dns-private",
        },
        {"rule_set": "geosite-geolocation-cn", "server": "dns-direct"},
        {
            "type": "logical",
            "mode": "and",
            "rules": [
                {"rule_set": "geosite-geolocation-!cn", "invert": True},
                {"rule_set": "geoip-cn"},
            ],
            "server": "google",
            "client_subnet": "114.114.114.114/24",
        },
    ]

    dns_config["final"] = "dns-remote"
    dns_config["independent_cache"] = True
    dns_config["strategy"] = "prefer_ipv4" if use_v6 else "ipv4_only"
    return dns_config


if __name__ == "__main__":

    black_list = ["机场", "订阅", "流量", "套餐", "重置", "电报群", "官网", "去除"]
    proxies = []
    with open("airport.txt", "r") as fp:
        headers = {"User-Agent": "clash-verge/v1.3.8"}
        result_dict = {"proxies": []}
        for line in fp.readlines():
            url = line.strip()
            if len(url) == 0:
                break
            # 发送HTTPS请求并获取响应
            response = requests.get(
                url=url, headers=headers
            )  # 用你的API端点替换这里的URL

            # 使用PyYAML解析响应的内容
            data = yaml.safe_load(response.text)
            for proxy in data["proxies"]:
                flag = True
                for bn in black_list:
                    if bn in proxy["name"]:
                        flag = False
                        break
                if flag:
                    proxies.append(proxy)
    #         # 现在，变量'data'包local_domain_list含了从HTTPS响应中解析出的数据

    local_domain_list = []
    with open("localdomain.txt", "r") as local_domain_file:
        for domain in local_domain_file.readlines():
            print(domain)
            local_domain_list.append(domain.strip())
    local_RULES["inline-localdomain"] = {
        "domain_suffix": local_domain_list,
        "domain": local_domain_list,
    }

    place_outbound = dict()

    for proxy in proxies:
        flag = True
        for place_name, place_pattern in PLACE_PATTERNS.items():
            if re.search(place_pattern, proxy["name"]):
                if place_name not in place_outbound:
                    place_outbound[place_name] = []
                place_outbound[place_name].append(
                    copy.deepcopy(process_proxy(proxy=proxy))
                )
                flag = False
                break
        if flag:
            print(proxy)
    result_json = {
        "log": LOG_SETTINGS,
        "experimental": {
            "clash_api": {
                "external_controller": (
                    "0.0.0.0:9090" if args.lan else "127.0.0.1:9090"
                ),
                "external_ui": "ui",
                "default_mode": "Enhanced",
                "external_ui_download_url": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/metacubexd/archive/gh-pages.zip",
                "external_ui_download_detour": "direct",
            },
            "cache_file": {"enabled": True, "store_fakeip": False},
        },
        "dns": get_dns_configs(
            dns_private=args.dns_private,
            dns_direct=args.dns_direct,
            dns_remote=args.dns_remote,
            use_v6=args.use_v6,
        ),
        "inbounds": get_inbounds(
            use_tun=args.tun,
            use_mixed=args.mixed,
            use_v6=args.use_v6,
            listen_lan=args.lan,
            docker=args.docker,
        ),
        "outbounds": get_outbounds(
            rule_config=(rules[args.config]),
            place_outbound=place_outbound,
        ),
        "route": {
            "auto_detect_interface": True,  # 如果您是Linux、Windows 和 macOS用户，请将此条注释撤销，使 final 其生效，以免造成问题（上一行记得加,）
            "final": GLOBAL_DETOUR,
            "rule_set": get_rule_set(
                (rules[args.config]),
            ),
            "rules": get_route_rules(rule_config=(rules[args.config])),
        },
    }
    with open(
        "result_{}{}{}{}{}.json".format(
            args.config,
            "_lan" if args.lan else "",
            "_v6" if args.use_v6 else "_v4",
            "_tun" if args.tun else "",
            "_mixed" if args.mixed else "",
        ),
        "w",
        encoding="utf-8",
    ) as result_file:
        result_file.write(json.dumps(result_json, ensure_ascii=False))
