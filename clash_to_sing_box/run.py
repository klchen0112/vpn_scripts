import requests
import yaml
import json
import copy
import argparse
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
parser.add_argument("--dns_private", help="direct dns", type=str, default="local")
parser.add_argument(
    "--dns_direct", help="direct dns", type=str, default="h3://dns.alidns.com/dns-query"
)
parser.add_argument(
    "--dns_remote",
    help="remote dns",
    type=str,
    default="https://cloudflare-dns.com/dns-query",
)
parser.add_argument(
    "--platform", type=str, choices=["linux", "darwin", "windows", "openwrt"]
)
parser.add_argument("--fakeip", type=bool, default=False)
args = parser.parse_args()


URL_TEST_BASE = {
    "type": "urltest",
    "tag": "",
    "outbounds": [],
    "url": "https://youtube.com/generate_204",
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
            }
            if "skip-cert-verify" in proxy:
                result["tls"]["insecure"] = proxy["skip-cert-verify"]
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
        if proxy.get("network", None) is None:
            print("can't deal ", proxy)
            pass
        elif proxy["network"] == "ws":
            result["transport"] = {
                "type": "ws",
                "path": proxy["ws-path"],
                "headers": proxy["ws-opts"]["headers"],
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
            # "up_mbps": 100,
            # "down_mbps": 100,
        }
        hysteria2_server_base["tag"] = proxy["name"]
        hysteria2_server_base["server"] = proxy["server"]
        hysteria2_server_base["server_port"] = int(proxy["port"])
        hysteria2_server_base["password"] = proxy["password"]
        if "sni" in proxy:
            hysteria2_server_base["tls"]["server_name"] = proxy["sni"]
        if "skip-cert-verify" in proxy:
            hysteria2_server_base["tls"]["insecure"] = proxy["skip-cert-verify"]
        if "up" in proxy:
            hysteria2_server_base["up_mbps"] = proxy["up"]
        if "down" in proxy:
            hysteria2_server_base["down_mbps"] = proxy["down"]
        return hysteria2_server_base
    elif proxy["type"] == "vless":
        return None
    else:
        raise ValueError("Wrong proxy type")


PLACE_PATTERNS = {
    "🇭🇰 香港": r"🇭🇰|香港|港|hongkong|Hong Kong",
    "🇺🇸 美国": r"🇺🇸|美国|united states|United States",
    "🇹🇼 台湾": r"🇹🇼|台湾|Taiwan",
    "🇯🇵 日本": r"🇯🇵|日本|JP|Japan",
    "🇰🇷 韩国": r"🇰🇷|韩国|KR|Korea",
    "🇸🇬 新加坡": r"🇸🇬|新加坡|SG|Singapore",
    "🇷🇺 俄罗斯": r"🇷🇺|俄罗斯|Russia",
    "🇫🇷 法国": r"🇫🇷|法国|French",
    "🇬🇧 英国": r"🇬🇧|英国|United Kingdom",
    "🇩🇪 德国": r"🇩🇪|德国|German",
    "🇨🇦 加拿大": r"🇨🇦|加拿大|Canada",
    "🇦🇺 澳大利亚": r"🇦🇺|澳大利亚|澳洲|Australia",
    "🇵🇭 菲律宾": r"🇵🇭|菲律宾",
    "🇹🇷 土耳其": r"🇹🇷|土耳其",
    "🇦🇷 阿根廷": r"🇦🇷|阿根廷",
    "🇺🇦 乌克兰": r"🇺🇦|乌克兰",
    "🇧🇷 巴西": r"🇧🇷|巴西",
    "🇮🇳 印度": r"🇮🇳|印度|India",
    "🇮🇩 印尼": r"🇮🇩|印尼",
    "🇮🇹 意大利": r"🇮🇹|意大利",
    "🇪🇬 埃及": r"🇪🇬|埃及",
    "🇲🇾 马来西亚": r"🇲🇾|马来西亚",
    "🇵🇰 巴基斯坦": r"🇵🇰|巴基斯坦",
    "🇨🇱 智利": r"🇨🇱|智利",
    "🇨🇴 哥伦比亚": r"🇨🇴|哥伦比亚",
    "🇳🇬 尼日利亚": r"🇳🇬|尼日利亚",
    "🇸🇪 瑞典": r"🇸🇪|瑞典",
    "🇨🇭 瑞士": r"🇨🇭|瑞士",
}

LOG_SETTINGS = {
    "disabled": False,
    "level": "warn",
    "output": "/var/log/sing-box.log",
    "timestamp": False,
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
            "rules": local_RULES[f"{rule_type}-{name}"],
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


def get_route_rules(rule_config, platform: str, use_fakeip):
    route_rules = []
    if platform == "openwrt":
        route_rules.append({"inbound": "dns-in", "outbound": "dns"})
    if not (platform == "openwrt" and use_fakeip):
        route_rules.append({"protocol": "dns", "outbound": "dns"})
    # route_rules.append({"protocol": ["stun", "quic"], "outbound": "🛑 Block"})
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
                    "mode": value["mode"],
                    "rules": value["rules"],
                    "outbound": value["outbound"],
                }
            )
        elif "ip_is_private" in value:
            route_rules.append({"ip_is_private": True, "outbound": "direct"})
    return route_rules


def get_outbounds(rule_config, place_outbound, use_fakeip: bool, platform: str):
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
            "outbounds": ["自动选择", "地区选择", "节点选择", "direct"],
            "default": "自动选择",
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
        " Dev-Global": {
            "type": "selector",
            "geosite": ["category-dev", "category-container"],
            "inline": ["nixos"],
            "outbounds": [GLOBAL_DETOUR, "🎯 Direct"],
            "default": GLOBAL_DETOUR,
        },
        " Dev-CN": {
            "type": "selector",
            "geosite": ["category-dev-cn"],
            "outbounds": ["🎯 Direct", GLOBAL_DETOUR],
            "default": "🎯 Direct",
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
            "inline": ["wechat"],
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
        "ip_is_private": {"ip_is_private": True, "outbound": "🎯 Direct"},
        "clash_global": {"clash_mode": "Global", "outbound": "节点选择"},
        "clash_direct": {"clash_mode": "Direct", "outbound": "🎯 Direct"},
        "LOCAL_DOMAIN": {
            "inline": ["localdomain"],
            "outbound": "🎯 Direct",
        },
        GLOBAL_DETOUR: {
            "type": "selector",
            "outbounds": ["自动选择", "地区选择", "节点选择", "direct"],
            "default": "自动选择",
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
    use_tun: bool,
    use_mixed: bool,
    use_v6: bool,
    listen_lan: bool,
    docker: bool,
    use_fakeip: bool,
    platform: str,
):
    result = []
    if use_fakeip and platform == "openwrt":
        result.append(
            {"type": "direct", "tag": "dns-in", "listen": "::", "listen_port": 6666}
        )
    if use_mixed:
        result.append(
            {
                "type": "mixed",
                "tag": "mixed",
                "listen": "0.0.0.0" if listen_lan else "127.0.0.1",
                "listen_port": 7890,
                "sniff": True,
                "sniff_override_destination": False,
                "users": [],
                "set_system_proxy": False if docker or use_tun else True,
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
                "address": ["172.16.0.0/30"] + (["fd00::0/126"] if use_v6 else []),
                "mtu": 9000,
                "auto_route": True,
                "strict_route": True,
                "sniff": True,
                "endpoint_independent_nat": False,
                "stack": "system",
                "platform": {
                    "http_proxy": {
                        "enabled": False,
                        "server": "127.0.0.1",
                        "server_port": 7890,
                    }
                },
            }
        )
    return result


def get_dns_configs(
    dns_private, dns_direct, dns_remote, use_v6: bool, use_fakeip: bool, platform
):
    dns_config = {}

    # build servers
    dns_config["servers"] = [
        {
            "tag": "dns-remote",
            "address": dns_remote,
            "detour": GLOBAL_DETOUR if platform != "openwrt" else "direct",
            "address_resolver": "dns-resolver",
        },
        {
            "tag": "dns-direct",
            "address": dns_direct,
            "detour": "direct",
            "address_resolver": "dns-resolver",
        },
        {
            "tag": "dns-resolver",
            "address": "223.5.5.5",
            "detour": "direct",
        },
        {
            "tag": "dns-private",
            "address": dns_private,
            "detour": "direct",
        },
        {"tag": "dns-success", "address": "rcode://success"},
        {"tag": "dns-refused", "address": "rcode://refused"},
    ]
    if use_fakeip:
        dns_config["servers"].append({"tag": "dns-fakeip", "address": "fakeip"})

    # build rules
    if use_fakeip:
        dns_config["rules"] = (
            [
                {"outbound": "any", "server": "dns-resolver", "disable_cache": True},
            ]
            + (
                [
                    {
                        "type": "logical",
                        "mode": "and",
                        "rules": [
                            {
                                "rule_set": [
                                    "geosite-geolocation-cn",
                                    "geosite-category-games@cn",
                                ],
                                "invert": True,
                            },
                            {"query_type": ["A", "AAAA"]},
                        ],
                        "server": "dns-fakeip",
                    },
                ]
                if args.platform != "openwrt"
                else [
                    {
                        "inbound": "dns-in",
                        "server": "dns-fakeip",
                        "disable_cache": False,
                        "rewrite_ttl": 1,
                    },
                ]
            )
            + [
                {
                    "type": "logical",
                    "mode": "and",
                    "rules": [
                        {
                            "rule_set": [
                                "geosite-geolocation-cn",
                                "geosite-category-games@cn",
                            ],
                            "invert": True,
                        },
                        {"query_type": ["CNAME"]},
                    ],
                    "server": "dns-remote",
                },
                {
                    "query_type": [
                        "CNAME",
                        "A",
                        "AAAA",
                    ],
                    "invert": True,
                    "server": "dns-refused",
                    "disable_cache": True,
                },
            ]
        )
        dns_config["final"] = "dns-direct"
    else:
        dns_config["rules"] = [
            {"outbound": "any", "server": "dns-resolver", "disable_cache": True},
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
                "server": "dns-success",
                "disable_cache": True,
                "rewrite_ttl": 0,
            },
            {
                "rule_set": ["inline-localdomain"],
                "server": "dns-private",
            },
            {
                "rule_set": "geosite-geolocation-cn",
                "query_type": ["A", "AAAA"],
                "server": "dns-direct",
            },
            {
                "type": "logical",
                "mode": "and",
                "rules": [
                    {"rule_set": "geosite-geolocation-cn", "invert": True},
                    {"rule_set": "geoip-cn"},
                ],
                "server": "dns-remote",
                "client_subnet": "114.114.114.114/24",  # Any China client IP address
            },
        ]
        dns_config["final"] = "dns-remote"

    dns_config["strategy"] = "prefer_ipv4" if use_v6 else "ipv4_only"
    if use_fakeip:
        dns_config["fakeip"] = {
            "enabled": True,
            "inet4_range": "198.18.0.0/15",
            **({"inet6_range": "fc00::/18"} if use_v6 else {}),
        }
    return dns_config


if __name__ == "__main__":
    black_list = ["机场", "订阅", "流量", "套餐", "重置", "电报群", "官网", "去除"]
    proxies = []
    place_outbound = dict()

    with open("airport.txt", "r") as fp:
        headers = {"User-Agent": "clash-verge/v1.3.8"}
        result_dict = {"proxies": []}
        for line in fp.readlines():
            line = line.strip()
            if len(line) == 0:
                continue
            url, agent = line.split(" ")
            headers["User-Agent"] = agent
            if len(url) == 0:
                break
            # 发送HTTPS请求并获取响应
            response = requests.get(
                url=url, headers=headers
            )  # 用你的API端点替换这里的URL
            if agent == "sing-box":
                data = json.loads(response.text)
                outbounds = data["outbounds"]
                # print(outbounds)
                for outbound in outbounds:
                    if outbound["type"] in ["selector", "dns", "direct"]:
                        continue
                    flag = True
                    for bn in black_list:
                        if bn in outbound["tag"]:
                            flag = False
                            break
                    if flag:
                        for place_name, place_pattern in PLACE_PATTERNS.items():
                            if re.search(place_pattern, outbound["tag"]):
                                if place_name not in place_outbound:
                                    place_outbound[place_name] = []
                                place_outbound[place_name].append(outbound)
                                flag = False
                                break

            elif agent == "clash":
                # 使用PyYAML解析响应的内容
                data = yaml.safe_load(response.text)
                for proxy in data["proxies"]:
                    flag = True
                    for bn in black_list:
                        if bn in proxy["name"]:
                            flag = False
                            break
                    if flag:
                        for place_name, place_pattern in PLACE_PATTERNS.items():
                            if re.search(place_pattern, proxy["name"]):
                                ret = process_proxy(proxy=proxy)
                                if ret is None:
                                    continue
                                if place_name not in place_outbound:
                                    place_outbound[place_name] = []
                                place_outbound[place_name].append(ret)
                                flag = False
                                break

    local_domain_list = []
    with open("localdomain.txt", "r") as local_domain_file:
        for domain in local_domain_file.readlines():
            print(domain)
            local_domain_list.append(domain.strip())
    local_RULES["inline-localdomain"] = [
        {
            "domain_suffix": local_domain_list,
        }
    ]
    local_RULES["inline-nixos"] = [
        {
            "domain_suffix": ["nixos.org", "garnix.io", "cachix.org"],
        }
    ]
    local_RULES["inline-wechat"] = [
        {
            "domain": [
                "dl.wechat.com",
                "sgfindershort.wechat.com",
                "sgilinkshort.wechat.com",
                "sglong.wechat.com",
                "sgminorshort.wechat.com",
                "sgquic.wechat.com",
                "sgshort.wechat.com",
                "tencentmap.wechat.com.com",
                "qlogo.cn",
                "qpic.cn",
                "servicewechat.com",
                "tenpay.com",
                "wechat.com",
                "wechatlegal.net",
                "wechatpay.com",
                "weixin.com",
                "weixin.qq.com",
                "weixinbridge.com",
                "weixinsxy.com",
                "wxapp.tc.qq.com",
            ]
        },
        {
            "domain_suffix": [
                ".qlogo.cn",
                ".qpic.cn",
                ".servicewechat.com",
                ".tenpay.com",
                ".wechat.com",
                ".wechatlegal.net",
                ".wechatpay.com",
                ".weixin.com",
                ".weixin.qq.com",
                ".weixinbridge.com",
                ".weixinsxy.com",
                ".wxapp.tc.qq.com",
            ]
        },
        {
            "ip_cidr": [
                "101.32.104.4/32",
                "101.32.104.41/32",
                "101.32.104.56/32",
                "101.32.118.25/32",
                "101.32.133.16/32",
                "101.32.133.209/32",
                "101.32.133.53/32",
                "129.226.107.244/32",
                "129.226.3.47/32",
                "162.62.163.63/32",
            ]
        },
    ]
    local_RULES["inline-proccess"] = [{"process_name": ["tailscale", "tailscaled"]}]

    result_json = {
        "log": LOG_SETTINGS,
        "experimental": {
            "clash_api": {
                "external_controller": (
                    "0.0.0.0:9090" if args.lan else "127.0.0.1:9090"
                ),
                "external_ui": "dashboard",
                "default_mode": "Enhanced",
            },
            "cache_file": {
                "enabled": True,
                "store_fakeip": args.fakeip,
                "store_rdrc": True,
            },
        },
        "dns": get_dns_configs(
            dns_private=args.dns_private,
            dns_direct=args.dns_direct,
            dns_remote=args.dns_remote,
            use_v6=args.use_v6,
            use_fakeip=args.fakeip,
            platform=args.platform,
        ),
        "inbounds": get_inbounds(
            use_tun=args.tun,
            use_mixed=args.mixed,
            use_v6=args.use_v6,
            listen_lan=args.lan,
            docker=args.docker,
            use_fakeip=args.fakeip,
            platform=args.platform,
        ),
        "outbounds": get_outbounds(
            rule_config=(rules[args.config]),
            place_outbound=place_outbound,
            use_fakeip=args.fakeip,
            platform=args.platform,
        ),
        "route": {
            "auto_detect_interface": True,  # 如果您是Linux、Windows 和 macOS用户，请将此条注释撤销，使 final 其生效，以免造成问题（上一行记得加,）
            "final": GLOBAL_DETOUR,
            "rule_set": get_rule_set(
                (rules[args.config]),
            ),
            "rules": get_route_rules(
                rule_config=(rules[args.config]),
                platform=args.platform,
                use_fakeip=args.fakeip,
            ),
        },
    }
    with open(
        "result_{}{}{}{}{}{}.json".format(
            args.config,
            "_lan" if args.lan else "",
            "_v6" if args.use_v6 else "_v4",
            "_tun" if args.tun else "",
            "_mixed" if args.mixed else "",
            "_fakeip" if args.fakeip else "_realip",
        ),
        "w",
        encoding="utf-8",
    ) as result_file:
        result_file.write(json.dumps(result_json, ensure_ascii=False, indent=2))
