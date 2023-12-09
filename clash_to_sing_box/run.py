import yaml
import json
import copy
import argparse

parser = argparse.ArgumentParser(description="")

parser.add_argument("-z", "--zju", help="wether use zju", action="store_true")
parser.add_argument("--six", help="ipv6", action="store_true")

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
        url = f"https://raw.githubusercontent.com/klchen0112/vpn_scripts/master/singbox/{name}.srs"
    elif rule_type == "geosite":
        url = f"https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-{name}.srs"
    elif rule_type == "geoip":
        url = f"https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-{name}.srs"
    else:
        raise ValueError("Wrong rule_type")
    return {
        "tag": f"{rule_type}-{name}",
        "type": "remote",
        "url": url,
        "download_detour": global_detour,
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
            outbound = value["outbound"]
            for rule_type in rule_types:
                if rule_type in value:
                    for name in value[rule_type]:
                        rule_set.append(f"{rule_type}-{name}")
            route_rules.append(
                {
                    "rule_set": rule_set,
                    "outbound": key if isinstance(outbound, list) else outbound,
                }
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
                    "outbound": value["outbound"],
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
            outbounds.append(
                {"tag": key, "type": "selector", "outbounds": value["outbound"]}
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
        "outbound": ["地区测速", "地区选择", "节点选择", "🎯 Direct"],
    },
    "clash_global": {"clash_mode": "global", "outbound": global_detour},
    "clash_direct": {"clash_mode": "direct", "outbound": "🎯 Direct"},
    "direct": {"type": "direct"},
    "dns": {"type": "dns"},
    "block": {"type": "block"},
    "🎯 Direct": {"type": "selector", "outbound": ["direct", "proxy"]},
    "🛑 Block": {"type": "selector", "outbound": ["block", "direct", "proxy"]},
    "󱤫 广告过滤": {
        "type": "selector",
        "geosite": ["category-ads-all"],
        "outbound": "🛑 block",
    },
    "🤖 OpenAI": {"type": "selector", "geosite": ["openai"], "outbound": "🤖 OpenAI"},
    " Dev-CN": {
        "type": "selector",
        "geosite": ["category-dev-cn"],
        "outbound": ["🎯 Direct", global_detour],
    },
    " Dev-Global": {
        "type": "selector",
        "geosite": ["category-dev", "category-container"],
        "outbound": [" Dev-Global", "🎯 Direct"],
    },
    "Schoolar CN": {
        "type": "selector",
        "geosite": ["category-scholar-cn", "category-education-cn"],
        "outbound": ["🎯 Direct", global_detour],
    },
    "󰑴 Schoolar Global": {
        "type": "selector",
        "geosite": ["category-scholar-!cn"],
        "outbound": [
            global_detour,
            "🎯 Direct",
        ],
    },
    "ZJU": {"own": ["zju"], "outbound": "🎯 Direct"},
    "󰊭 Google": {
        "type": "selector",
        "geosite": ["google"],
        "geoip": ["google"],
        "outbound": [global_detour, "🎯 Direct"],
    },
    "Social Media CN": {
        "type": "selector",
        "geosite": ["category-social-media-cn"],
        "outbound": ["🎯 Direct", global_detour],
    },
    " Social Media Global": {
        "type": "selector",
        "geosite": ["category-social-media-!cn", "category-communication"],
        "geoip": ["telegram", "twitter", "facebook"],
        "outbound": [
            global_detour,
            "🎯 Direct",
        ],
    },
    "󰒚 Shopping": {
        "type": "selector",
        "geosite": ["amazon"],
        "outbound": [
            global_detour,
            "🎯 Direct",
        ],
    },
    "Ⓜ️ Microsoft": {
        "type": "selector",
        "geosite": ["microsoft"],
        "outbound": [
            global_detour,
            "🎯 Direct",
        ],
    },
    "Game CN": {
        "type": "selector",
        "geosite": ["category-games@cn"],
        "outbound": [
            "🎯 Direct",
            global_detour,
        ],
    },
    "󱎓 Game Global": {
        "type": "selector",
        "geosite": ["category-games"],
        "outbound": ["日本", "香港", "台湾", global_detour, "🎯 Direct"],
    },
    "哔哩哔哩": {
        "type": "selector",
        "geosite": ["bilibili"],
        "outbound": [
            "🎯 Direct",
            global_detour,
        ],
    },
    "巴哈姆特": {
        "type": "selector",
        "geosite": ["bahamut"],
        "outbound": [
            global_detour,
            "🎯 Direct",
        ],
    },
    "国内流媒体": {
        "type": "selector",
        "geosite": ["category-media-cn"],
        "outbound": [
            "🎯 Direct",
            global_detour,
        ],
    },
    "󰝆 海外流媒体": {
        "type": "selector",
        "geoip": ["netflix"],
        "geosite": [
            "category-media",
            "category-entertainment",
        ],
        "outbound": [
            global_detour,
            "🎯 Direct",
        ],
    },
    " Global": {
        "type": "selector",
        "geosite": ["geolocation-!cn", "tld-!cn"],
        "outbound": [
            global_detour,
            "🎯 Direct",
        ],
    },
    "🇨🇳 CNIP": {
        "type": "selector",
        "geoip": ["private", "cn"],
        "outbound": [
            "🎯 Direct",
            global_detour,
        ],
    },
}


single_selecor = {
    "type": "selector",
    "tag": "节点选择",
    "outbound": [],
    #   "default": "proxy-c",
    # "interrupt_exist_connections": False,
}


with open("mixed.yaml", "r", encoding="utf-8") as file, open(
    "result{}.json".format("_zju" if use_zju else ""), "w", encoding="utf-8"
) as result_file:
    if not args.zju:
        rules_with_rule_set.pop("ZJU")

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
                "external_controller": "127.0.0.1:9090",
                "external_ui": "ui",
                "default_mode": "rule",
            },
            "cache_file": {"enabled": True, "store_fakeip": False},
        },
        "dns": {
            "servers": [
                {
                    "tag": "dns-google-tls",
                    "address": "tls://8.8.8.8",
                    "detour": "proxy",
                },
                {
                    "tag": "dns-ali-doh",
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
                    "server": "dns-ali-doh",
                },
                {"domain_suffix": [], "server": "dns-ali-doh"},
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
                {"outbound": "any", "server": "dns-ali-doh", "disable_cache": True},
                {"rule_set": "geosite-cn", "server": "dns-ali-doh"},
                {"clash_mode": "direct", "server": "dns-ali-doh"},
                {"clash_mode": "global", "server": "dns-google-tls"},
                {"rule_set": "geosite-geolocation-!cn", "server": "dns-google-tls"},
                {"query_type": ["A", "AAAA"], "server": "dns-fakeip"},
                # {"outbound": ["any"], "server": "remote"},
            ],
            "final": "dns-google-tls",
            "fakeip": {
                "enabled": True,
                "inet4_range": "198.18.0.0/15",
                **({"inet6_range": "fc00::/18"} if args.six else {}),
            },
            "independent_cache": True,
            "strategy": "ipv4_only",
        },
        "inbounds": [
            {
                "type": "tun",
                "tag": "tun0",
                "inet4_address": "172.19.0.1/30",
                **({"inet6_range": "fdfd:9527::1/32"} if args.six else {}),
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
            },
            {
                "type": "mixed",
                "listen": "127.0.0.1",
                "listen_port": 7890,
                "sniff": True,
                "users": [],
            },
        ],
        "outbound": get_outbounds(
            rule_config=rules_with_rule_set, place_outbound=place_outbound
        ),
        "route": {
            # "auto_detect_interface": true, 如果您是Linux、Windows 和 macOS用户，请将此条注释撤销，使 final 其生效，以免造成问题（上一行记得加,）
            "final": "proxy",
            "rule_set": get_rule_set(rules_with_rule_set),
            "rules": get_route_rules(rule_config=rules_with_rule_set),
        },
    }

    result_file.write(json.dumps(result_json, ensure_ascii=False))
