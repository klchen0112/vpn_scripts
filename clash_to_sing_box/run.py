import yaml
import json
import copy
import argparse

parser = argparse.ArgumentParser(description="")

parser.add_argument("-z", "--zju", help="wether use zju", action="store_true")
parser.add_argument("--six", help="ipv6", action="store_true")
parser.add_argument("--simple", help="use simple version", action="store_true")
parser.add_argument("--tun", help="use tun", action="store_true")
parser.add_argument("--mixed", help="use tun", action="store_true")
parser.add_argument("--lan", help="use tun", action="store_true")
args = parser.parse_args()

use_zju = args.zju


url_test_base = {
    "type": "urltest",
    "tag": "",
    "outbounds": [],
    "url": "https://www.gstatic.com/generate_204",
    "interval": "1m",
    "tolerance": 50,
}


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
        result["server_port"] = proxy["port"]
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
        result["server_port"] = proxy["port"]
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
        result["server_port"] = proxy["port"]
        result["uuid"] = proxy["uuid"]
        result["alter_id"] = proxy["alterId"]
        result["security"] = proxy["cipher"]
        if proxy["network"] == "ws":
            result["transport"] = {
                "type": "ws",
            }
        elif proxy["network"] == "grpc":
            result["transport"] = {
                "type": "grpc",
                "service_name": proxy["grpc-opts"]["grpc-service-name"],
            }
        return result
    else:
        raise ValueError("Wrong proxy type")


place_back = [
    "香港",
    "美国",
    "台湾",
    "日本",
    "韩国",
    "新加坡",
    "俄罗斯",
    "法国",
    "英国",
    "德国",
    "澳大利亚",
    "菲律宾",
    "土耳其",
    "阿根廷",
    "乌克兰",
    "巴西",
    "印度",
    "意大利",
    "埃及",
    "马来西亚",
    "巴基斯坦",
    "智利",
    "哥伦比亚",
    "尼日利亚",
]

zju_dns = "10.10.0.21"
zju_domains = []

log_settings = {
    "disabled": False,
    "level": "warn",
    # "output": "box.log",
    "timestamp": True,
}
global_detour = "✈️ Proxy"


def get_rule_set_url(rule_type: str, name: str):
    if rule_type == "own":
        url = f"https://raw.githubusercontent.com/klchen0112/vpn_scripts/master/singbox/{name}.json"
    elif rule_type == "geosite":
        url = f"https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geosite/{name}.srs"
    elif rule_type == "geoip":
        url = f"https://cdn.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@sing/geo/geoip/{name}.srs"
    else:
        raise ValueError("Wrong rule_type")
    return {
        "tag": f"{rule_type}-{name}",
        "type": "remote",
        "url": url,
        "download_detour": global_detour if rule_type == "own" else "direct",
        "format": "source" if rule_type == "own" else "binary",
    }


def get_rule_set(rule_config):
    rule_sets = []
    for key, value in rule_config.items():
        if "geosite" in value:
            for name in value["geosite"]:
                rule_sets.append(get_rule_set_url(rule_type="geosite", name=name))
        if "geoip" in value:
            for name in value["geoip"]:
                rule_sets.append(get_rule_set_url(rule_type="geoip", name=name))
        if "own" in value:
            for name in value["own"]:
                rule_sets.append(get_rule_set_url(rule_type="own", name=name))
    return rule_sets


def get_route_rules(rule_config):
    route_rules = []
    route_rules.append({"protocol": "dns", "outbound": "dns"})
    route_rules.append({"protocol": ["stun", "quic"], "outbound": "🛑 Block"})
    rule_types = ("geoip", "geosite", "own")
    for key, value in rule_config.items():
        if key == global_detour:
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
        elif "geosite" in value or "geoip" in value or "own" in value:
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
        elif "ip_is_private" in value:
            route_rules.append(
                {"ip_is_private": value["ip_is_private"], "outbound": value["outbound"]}
            )
    return route_rules


def get_outbounds(rule_config, place_outbound):
    outbounds = []
    place_list = list(place_outbound.keys())

    all_bound_name = []
    for bounds in place_outbound.values():
        for bound in bounds:
            all_bound_name.append(bound["tag"])
    for key, value in rule_config.items():
        if key == global_detour:
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
                    "tag": "地区测速",
                    "type": "urltest",
                    "outbounds": place_list,
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
            # print(key)
            outbounds.append(
                {
                    "tag": key,
                    "type": "selector",
                    "outbounds": value["outbounds"],
                    "default": value["default"],
                }
            )
    for name, place_outbounds in place_outbound.items():
        url_place = copy.deepcopy(url_test_base)
        url_place["tag"] = name
        for outbound in place_outbounds:
            # print(outbound)
            url_place["outbounds"].append(outbound["tag"])
        # print(url_place)
        outbounds.append(url_place)
    for bounds in place_outbound.values():
        outbounds.extend(bounds)
    return outbounds


# 如果 outbound不为1那么就流量转自key
rules_with_rule_set = {
    global_detour: {
        "type": "selector",
        "outbounds": ["地区测速", "地区选择", "节点选择", "direct"],
        "default": "地区测速",
    },
    "clash_global": {"clash_mode": "global", "outbound": global_detour},
    "clash_direct": {"clash_mode": "direct", "outbound": "🎯 Direct"},
    "direct": {"type": "direct"},
    "dns": {"type": "dns"},
    "block": {"type": "block"},
    "ip_is_private": {"ip_is_private": True, "outbound": "🎯 Direct"},
    "🎯 Direct": {
        "type": "selector",
        "outbounds": ["direct", global_detour],
        "default": "direct",
    },
    "🛑 Block": {
        "type": "selector",
        "outbounds": ["block", "direct", global_detour],
        "default": "block",
    },
    "󱤫 广告过滤": {
        "type": "selector",
        "geosite": ["category-ads-all"],
        "outbounds": ["🛑 Block", "🎯 Direct"],
        "default": "🛑 Block",
    },
    "🤖 OpenAI": {
        "type": "selector",
        "geosite": ["openai"],
        "outbounds": ["美国", global_detour, "🎯 Direct"],
        "default": "美国",
    },
    " Dev-CN": {
        "type": "selector",
        "geosite": ["category-dev-cn"],
        "outbounds": ["🎯 Direct", global_detour],
        "default": "🎯 Direct",
    },
    " Dev-Global": {
        "type": "selector",
        "geosite": ["category-dev", "category-container"],
        "outbounds": [global_detour, "🎯 Direct"],
        "default": global_detour,
    },
    "Schoolar CN": {
        "type": "selector",
        "geosite": ["category-scholar-cn", "category-education-cn"],
        "outbounds": ["🎯 Direct", global_detour],
        "default": "🎯 Direct",
    },
    "󰑴 Schoolar Global": {
        "type": "selector",
        "geosite": ["category-scholar-!cn"],
        "outbounds": [
            global_detour,
            "🎯 Direct",
        ],
        "default": global_detour,
    },
    "ZJU": {
        "own": ["zju"],
        "outbound": "🎯 Direct",
    },
    "󰊭 Google CN": {
        "type": "selector",
        "geosite": ["google@cn"],
        "outbounds": [
            "🎯 Direct",
            global_detour,
        ],
        "default": "🎯 Direct",
    },
    "󰊭 Google": {
        "type": "selector",
        "geosite": ["google"],
        # "geoip": ["google"],
        "outbounds": [global_detour, "🎯 Direct"],
        "default": global_detour,
    },
    "Social Media CN": {
        "type": "selector",
        "geosite": ["category-social-media-cn"],
        "outbounds": ["🎯 Direct", global_detour],
        "default": "🎯 Direct",
    },
    " Social Media Global": {
        "type": "selector",
        "geosite": ["category-social-media-!cn", "category-communication"],
        # "geoip": ["telegram", "twitter", "facebook"],
        "outbounds": [
            global_detour,
            "🎯 Direct",
        ],
        "default": global_detour,
    },
    "󰒚 Shopping": {
        "type": "selector",
        "geosite": ["amazon"],
        "outbounds": [
            global_detour,
            "🎯 Direct",
        ],
        "default": global_detour,
    },
    "Ⓜ️ Microsoft CN": {
        "type": "selector",
        "geosite": ["microsoft@cn"],
        "outbounds": [
            "🎯 Direct",
            global_detour,
        ],
        "default": "🎯 Direct",
    },
    "Ⓜ️ Microsoft": {
        "type": "selector",
        "geosite": ["microsoft"],
        "outbounds": [
            global_detour,
            "🎯 Direct",
        ],
        "default": global_detour,
    },
    "🍎 Apple CN": {
        "type": "selector",
        "geosite": ["apple@cn"],
        "outbounds": [
            "🎯 Direct",
            global_detour,
        ],
        "default": "🎯 Direct",
    },
    "🍎 Apple": {
        "type": "selector",
        "geosite": ["apple"],
        "outbounds": [
            global_detour,
            "🎯 Direct",
        ],
        "default": global_detour,
    },
    "Game CN": {
        "type": "selector",
        "geosite": ["category-games@cn", "category-game-accelerator-cn"],
        "outbounds": [
            "🎯 Direct",
            global_detour,
        ],
        "default": "🎯 Direct",
    },
    "󱎓 Game Global": {
        "type": "selector",
        "geosite": ["category-games"],
        "outbounds": ["日本", "香港", "台湾", global_detour, "🎯 Direct"],
        "default": global_detour,
    },
    "哔哩哔哩": {
        "type": "selector",
        "geosite": ["bilibili"],
        "outbounds": [
            "🎯 Direct",
            "台湾",
            "香港",
            global_detour,
        ],
        "default": "🎯 Direct",
    },
    "巴哈姆特": {
        "type": "selector",
        "geosite": ["bahamut", "bilibili@!cn"],
        "outbounds": [
            "台湾",
            "香港",
            global_detour,
            "🎯 Direct",
        ],
        "default": "台湾",
    },
    "国内流媒体": {
        "type": "selector",
        "geosite": ["category-media-cn"],
        "outbounds": [
            "🎯 Direct",
            global_detour,
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
            global_detour,
            "🎯 Direct",
        ],
        "default": global_detour,
    },
    "🟨 Porn": {
        "type": "selector",
        "geosite": ["category-porn"],
        "outbounds": [
            global_detour,
            "🎯 Direct",
        ],
        "default": global_detour,
    },
    " Global": {
        "type": "selector",
        "geosite": ["geolocation-!cn", "tld-!cn"],
        "outbounds": [
            global_detour,
            "🎯 Direct",
        ],
        "default": global_detour,
    },
    "🇨🇳 CNIP": {
        "type": "selector",
        "geoip": ["cn"],
        "geosite": ["cn"],
        "outbounds": [
            "🎯 Direct",
            global_detour,
        ],
        "default": "🎯 Direct",
    },
}
simple_version_rules = {
    global_detour: {
        "type": "selector",
        "outbounds": ["地区测速", "地区选择", "节点选择"],
        "default": "地区测速",
    },
    "clash_global": {"clash_mode": "global", "outbound": global_detour},
    "clash_direct": {"clash_mode": "direct", "outbound": "🎯 Direct"},
    "direct": {"type": "direct"},
    "dns": {"type": "dns"},
    "block": {"type": "block"},
    "ip_is_private": {"ip_is_private": True, "outbound": "🎯 Direct"},
    "🎯 Direct": {
        "type": "selector",
        "outbounds": ["direct", global_detour],
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
        "outbounds": ["block", "direct", global_detour],
        "default": "block",
    },
    "ZJU": {
        "own": ["zju"],
        "outbound": "🎯 Direct",
    },
    "🇨🇳 CNIP": {
        "type": "selector",
        "geoip": ["cn"],
        "geosite": ["cn"],
        "outbounds": [
            "🎯 Direct",
            global_detour,
        ],
        "default": "🎯 Direct",
    },
}


single_selecor = {
    "type": "selector",
    "tag": "节点选择",
    "outbound": [],
    #   "default": "proxy-c",
    # "interrupt_exist_connections": False,
}


def get_inbounds(use_tun, use_mixed, use_v6, listen_lan):
    result = []
    if use_mixed:
        result.append(
            {
                "type": "mixed",
                "listen": "0.0.0.0" if listen_lan else "127.0.0.1",
                "listen_port": 7890,
                "sniff": True,
                "users": [],
                "set_system_proxy": True,
            }
        )
    if use_tun:
        result.append(
            {
                "type": "tun",
                # "tag": "tun0",
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


with open("mixed.yaml", "r", encoding="utf-8") as file, open(
    "result{}{}.json".format(
        "_zju" if use_zju else "", "_simple" if args.simple else ""
    ),
    "w",
    encoding="utf-8",
) as result_file:
    if not args.zju:
        rules_with_rule_set.pop("ZJU")
        simple_version_rules.pop("ZJU")

    data = yaml.load(file.read(), Loader=yaml.FullLoader)
    place_outbound = dict()

    for proxy in data["proxies"]:
        for place_name in place_back:
            if place_name in proxy["name"]:
                if place_name not in place_outbound:
                    place_outbound[place_name] = []
                place_outbound[place_name].append(
                    copy.deepcopy(process_proxy(proxy=proxy))
                )

    result_json = {
        "log": log_settings,
        "experimental": {
            "clash_api": {
                "external_controller": "0.0.0.0:9090" if args.lan else "127.0.0.1:9090",
                "external_ui": "ui",
                "default_mode": "rule",
                "external_ui_download_url": "https://mirror.ghproxy.com/https://github.com/MetaCubeX/metacubexd/archive/gh-pages.zip",
                "external_ui_download_detour": "direct",
            },
            "cache_file": {"enabled": True, "store_fakeip": False},
        },
        "dns": {
            "servers": [
                {
                    "tag": "dns-remote",
                    "address": "tls://8.8.8.8",
                    "detour": global_detour,
                },
                {
                    "tag": "dns-direct",
                    "address": "https://223.5.5.5/dns-query",
                    "detour": "direct",
                },
            ]
            + (
                []
                if not use_zju
                else [
                    {
                        # zju 所用的dns
                        "tag": "dns-zju",
                        "address": zju_dns,
                        "detour": "direct",
                    },
                ]
            )
            + [
                {"tag": "dns-block", "address": "rcode://success"},
                {"tag": "dns-fakeip", "address": "fakeip"},
            ],
            "rules": [
                {
                    "domain": ["ghproxy.com", "cdn.jsdelivr.net"],
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
            ]
            + (
                []
                if not use_zju
                else [
                    {
                        "rule_set": "own-zju",
                        "server": "dns-zju",
                    },
                ]
            )
            + [
                {"outbound": "any", "server": "dns-direct"},
                {"rule_set": "geosite-cn", "server": "dns-direct"},
                {"clash_mode": "direct", "server": "dns-direct"},
                {"clash_mode": "global", "server": "dns-remote"},
                {"query_type": ["A", "AAAA"], "rewrite_ttl": 1, "server": "dns-fakeip"},
            ],
            "final": "dns-remote",
            "fakeip": {
                "enabled": True,
                "inet4_range": "198.18.0.0/15",
                **({"inet6_range": "fc00::/18"} if args.six else {}),
            },
            # "independent_cache": True,
            "strategy": "prefer_ipv4" if args.six else "ipv4_only",
        },
        "inbounds": get_inbounds(
            use_tun=args.tun, use_mixed=args.mixed, use_v6=args.six, listen_lan=args.lan
        ),
        "outbounds": get_outbounds(
            rule_config=simple_version_rules if args.simple else rules_with_rule_set,
            place_outbound=place_outbound,
        ),
        "route": {
            "auto_detect_interface": True,  # 如果您是Linux、Windows 和 macOS用户，请将此条注释撤销，使 final 其生效，以免造成问题（上一行记得加,）
            "final": global_detour,
            "rule_set": get_rule_set(
                simple_version_rules if args.simple else rules_with_rule_set,
            ),
            "rules": get_route_rules(
                rule_config=simple_version_rules
                if args.simple
                else rules_with_rule_set,
            ),
        },
    }

    result_file.write(json.dumps(result_json, ensure_ascii=False))
