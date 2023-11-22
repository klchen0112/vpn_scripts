import yaml
import json
import copy
import argparse

parser = argparse.ArgumentParser(description="")

parser.add_argument("-z", "--zju", help="wether use zju", action="store_true")
parser.add_argument("-s", "--speed", help="高速节点", type=str)
parser.add_argument("--six", help="ipv6", action="store_true")

args = parser.parse_args()

use_zju = args.zju
high_speed = args.speed

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
            "tls": {
                "enabled": True,
                "disable_sni": False,
                "server_name": "",
                "insecure": False,
            },
        }
        result = copy.deepcopy(trojan_server_base)
        result["tag"] = proxy["name"]
        result["server"] = proxy["server"]
        result["server_port"] = proxy["port"]
        result["password"] = proxy["password"]
        if "sni" in proxy:
            result["tls"]["server_name"] = proxy["sni"]
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
zju_domains = [
    "zju.edu.cn",
    "cc98.org",
    "nexushd.org",
    "icsr.wiki",
    "zjusec.com",
    "zjusec.net",
    "zjusec.top",
    "zjusct.io",
    "zjueva.net",
    "zjuqsc.com",
    "worldcup.myth.cx",
    "illinois.edu",
    "acm.org",
    "cnki.net",
    "gtadata.com",
    "jstor.org",
    "webofscience.com",
    "inoteexpress.com",
    "pnas.org",
    "cnpereading.com",
    "sciencemag.org",
    "cas.org",
    "webofknowledge.com",
    "pkulaw.com",
    "sslibrary.com",
    "serialssolutions.com",
    "duxiu.com",
    "wanfangdata.com.cn",
    "koolearn.com",
    "cssci.nju.edu.cn",
    "science.org",
    "oup.com",
    "ajtmh.org",
    "futuremedicine.com",
    "tandfonline.com",
    "genetics.org",
    "healthaffairs.org",
    "rsna.org",
    "iospress.com",
    "allenpress.com",
    "asabe.org",
    "geoscienceworld.org",
    "sagepub.com",
    "ajnr.org",
    "ajhp.org",
    "annals.org",
    "esajournals.org",
    "informs.org",
    "cshlpress.com",
    "nrcresearchpress.cn",
    "royalsocietypublishing.org",
    "oxfordjournals.org",
    "aspbjournals.org",
    "sciencesocieties.org",
    "degruyter.com",
    "cshprotocols.org",
    "liebertonline.com",
    "polymerjournals.com",
    "csiro.au",
    "iop.org",
    "electrochem.org",
    "ametsoc.org",
    "portlandpress.com",
    "nrcresearchpress.com",
    "arabidopsis.org",
    "springerlink.com",
    "highwire.org",
    "ovid.com",
    "rsc.org",
    "bmj.org",
    "aip.org",
    "springer.com",
    "iwaponline.com",
    "rsnajnls.org",
    "karger.com",
    "wiley.com",
    "plantcell.org",
    "jamanetwork.com",
    "nejm.org",
    "icevirtuallibrary.com",
]

log_settings = {
    "disabled": False,
    "level": "warn",
    # "output": "box.log",
    "timestamp": True,
}
dns_settings = {
    "servers": [
        {"tag": "dns-remote", "address": "tls://8.8.8.8", "detour": "✈️ Proxy"},
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
        {"domain": ["ghproxy.com", "cdn.jsdelivr.net"], "server": "dns-direct"},
        {"domain_suffix": ["globalssh.cn", "open.ga"], "server": "dns-direct"},
        {
            "geosite": "category-ads-all",
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
                "domain_suffix": zju_domains,
                "server": "dns-zju",
            },
        ]
    )
    + [
        {"outbound": "any", "server": "dns-direct", "disable_cache": True},
        {"geosite": "cn", "server": "dns-direct"},
        {"clash_mode": "direct", "server": "dns-direct"},
        {"clash_mode": "global", "server": "dns-remote"},
        {"geosite": "geolocation-!cn", "server": "dns-remote"},
        {"query_type": ["A", "AAAA"], "server": "dns-fakeip"},
        # {"outbound": ["any"], "server": "remote"},
    ],
    "final": "dns-remote",
    "fakeip": {
        "enabled": True,
        "inet4_range": "198.18.0.0/15",
        **({"inet6_range": "fc00::/18"} if args.six else {}),
    },
    "independent_cache": True,
    "strategy": "ipv4_only",
}
inbounds_settings = [
    {
        "type": "tun",
        "tag": "tun0",
        "inet4_address": "172.19.0.1/30",
        **({"inet6_range": "fdfd:9527::1/32"} if args.six else {}),
        "auto_route": True,
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
      "users": []
    }
]

outbounds_settings = [
    {
        "tag": "✈️ Proxy",
        "type": "selector",
        "outbounds": (["高速节点"] if high_speed is not None else [])
        + ["auto", "地区选择", "节点选择", "direct"],
    },
    {
        "tag": "广告过滤",
        "type": "selector",
        "outbounds": ["block", "direct", "✈️ Proxy"],
        "default": "block",
    },
    {
        "tag": "学术",
        "type": "selector",
        "outbounds": ["✈️ Proxy", "节点选择", "direct"],
    },
    {
        "tag": "OpenAI",
        "type": "selector",
        "outbounds": [
            "美国",
            "✈️ Proxy",
        ],
    },
    {
        "tag": "Developer",
        "type": "selector",
        "outbounds": [
            "✈️ Proxy",
            "direct",
        ],
    },
    {
        "tag": "OneDrive",
        "type": "selector",
        "outbounds": ["auto", "✈️ Proxy", "direct"],
    },
    {
        "tag": "Microsoft",
        "type": "selector",
        "outbounds": [
            "direct",
            "✈️ Proxy",
        ],
    },
    {
        "tag": "Social",
        "type": "selector",
        "outbounds": ["auto", "✈️ Proxy", "direct"],
    },
    {
        "tag": "Shopping",
        "type": "selector",
        "outbounds": ["✈️ Proxy", "direct"],
    },
    {
        "tag": "哔哩哔哩",
        "type": "selector",
        "outbounds": [
            "direct",
            "台湾",
            "香港",
            "✈️ Proxy",
        ],
    },
    {
        "tag": "巴哈姆特",
        "type": "selector",
        "outbounds": [
            "台湾",
            "香港",
            "✈️ Proxy",
        ],
    },
    {
        "tag": "Apple",
        "type": "selector",
        "outbounds": [
            "direct",
            "✈️ Proxy",
        ],
    },
    {
        "tag": "Game",
        "type": "selector",
        "outbounds": [
            "日本",
            "香港",
            "台湾",
            "✈️ Proxy",
            "direct",
        ],
    },
    {
        "tag": "Streaming",
        "type": "selector",
        "outbounds": ["auto", "✈️ Proxy", "direct"],
    },
    {
        "tag": "Google",
        "type": "selector",
        "outbounds": ["✈️ Proxy", "direct"],
    },
    {"tag": "Speedtest", "type": "selector", "outbounds": ["direct", "✈️ Proxy"]},
    {
        "type": "selector",
        "tag": "🎯 direct",
        "outbounds": ["direct", "block", "✈️ Proxy"],
        "default": "direct",
    },
    {
        "type": "direct",
        "tag": "direct",
    },
    {"type": "dns", "tag": "dns"},
    {"type": "block", "tag": "block"},
]

route_settings = {
    "auto_detect_interface": True,
    "final": "✈️ Proxy",
    "geoip": {
        "download_url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geoip.db",
        "download_detour": "direct",
    },
    "geosite": {
        "download_url": "https://testingcf.jsdelivr.net/gh/MetaCubeX/meta-rules-dat@release/geosite.db",
        "download_detour": "direct",
    },
    "rules": [
        {"clash_mode": "global", "outbound": "✈️ Proxy"},
        {"clash_mode": "direct", "outbound": "🎯 direct"},
        {
            "type": "logical",
            "mode": "or",
            "rules": [
                {
                    "protocol": "dns",
                    "port": [53],
                }
            ],
            "outbound": "dns",
        },
        {"network": "udp", "port": 443, "outbound": "block"},
        {"geosite": "category-ads-all", "outbound": "广告过滤"},
        {
            "domain": [
                "clash.razord.top",
                "yacd.metacubex.one",
                "yacd.haishan.me",
                "d.metacubex.one",
            ],
            "outbound": "direct",
        },
    ]
    + (
        []
        if not use_zju
        else [
            {
                "domain_suffix": zju_domains,
                "outbound": "direct",
            },
        ]
    )
    + [
        {
            "domain_suffix": [
                "canvas-user-content.com",
                "iclicker.com",
                "emerald.com",
                "ieee.org",
                "proquest.com",
                "sciencedirect.com",
                "nature.com",
                "acs.org",
                "taylorfrancis.com",
                "osapublishing.org",
                "clarivate.com",
                "gale.com",
                "worldscientific.com",
                "siam.org",
                "ascelibrary.org",
                "scitation.org",
                "wiley.com",
            ],
            "geosite": "category-scholar-!cn",
            "outbound": "学术",
        },
        {
            "domain_keyword": ["speedtest"],
            "domain_suffix": ["cdnst.net", "ziffstatic.com"],
            "outbound": "Speedtest",
        },
        {"geosite": "openai", "outbound": "OpenAI"},
        {"geosite": "category-dev-cn", "outbound": "direct"},
        {
            "geosite": ["category-dev", "category-container"],
            "outbound": "Developer",
        },
        {"geosite": ["google"], "outbound": "Google"},
        {
            "geosite": ["category-social-media-cn"],
            "outbound": "direct",
        },
        {
            "geosite": ["category-social-media-!cn", "category-communication"],
            "outbound": "Social",
        },
        {"geosite": "amazon", "outbound": "Shopping"},
        {"geosite": "apple", "outbound": "Apple"},
        {"geosite": "microsoft", "outbound": "Microsoft"},
        {"geosite": "category-games@cn", "outbound": "direct"},
        {"geosite": "category-games", "outbound": "Game"},
        {
            "geosite": "bilibili",
            "outbound": "哔哩哔哩",
        },
        {
            "geosite": "bahamut",
            "outbound": "巴哈姆特",
        },
        {
            "geosite": [
                "tiktok",
                "youtube",
                "netflix",
                "hbo",
                "disney",
                "primevideo",
                "category-media",
                "category-entertainment",
            ],
            "outbound": "Streaming",
        },
        {"geosite": ["geolocation-!cn", "tld-!cn"], "outbound": "✈️ Proxy"},
    ]
    + (
        []
        if not use_zju
        else [
            {
                "ip_cidr": ["10.0.0.0/8"],
                "outbound": "direct",
            },
        ]
    )
    + [
        {"geoip": "google", "outbound": "Google"},
        {
            "geoip": ["telegram", "twitter", "facebook"],
            "outbound": "Social",
        },
        {
            "geoip": "netflix",
            "outbound": "Streaming",
        },
        {
            "geoip": ["private", "cn"],
            "outbound": "direct",
        },
    ],
}

result_json = {
    "log": log_settings,
    "experimental": {
        "clash_api": {
            "external_controller": "127.0.0.1:9090",
            "external_ui": "ui",
            "default_mode": "rule",
            "store_selected": True,
        }
    },
    "dns": dns_settings,
    "inbounds": inbounds_settings,
    "outbounds": outbounds_settings,
    "route": route_settings,
}

single_selecor = {
    "type": "selector",
    "tag": "节点选择",
    "outbounds": [],
    #   "default": "proxy-c",
    # "interrupt_exist_connections": False,
}

with open("mixed.yaml", "r", encoding="utf-8") as file, open(
    "result{}.json".format("_zju" if use_zju else ""), "w", encoding="utf-8"
) as result_file:
    data = yaml.load(file.read(), Loader=yaml.FullLoader)
    place_list = set()

    for proxy in data["proxies"]:
        for place_name in place_back:
            if place_name in proxy["name"]:
                place_list.add(place_name)
    place_list = list(place_list)

    result_json["outbounds"].append(
        {
            "type": "urltest",
            "tag": "auto",
            "outbounds": copy.deepcopy(place_list),
            "url": "https://www.gstatic.com/generate_204",
            "interval": "1m",
            "tolerance": 50,
        }
    )
    result_json["outbounds"].append(
        {
            "tag": "地区选择",
            "type": "selector",
            "outbounds": copy.deepcopy(place_list),
        },
    )

    url_test_dict = {name: copy.deepcopy(url_test_base) for name in place_list}
    if high_speed is not None:
        url_test_dict["高速节点"] = copy.deepcopy(url_test_base)
        url_test_dict["高速节点"]["tag"] = "高速节点"
    for name in place_list:
        url_test_dict[name]["tag"] = name
    for proxy in data["proxies"]:
        single_selecor["outbounds"].append(proxy["name"])
        if high_speed is not None and high_speed in proxy["name"]:
            url_test_dict["高速节点"]["outbounds"].append(proxy["name"])
            continue
        for place_name in place_list:
            if place_name in proxy["name"]:
                url_test_dict[place_name]["outbounds"].append(proxy["name"])
                break
    result_json["outbounds"].append(single_selecor)
    for url_test in url_test_dict.values():
        result_json["outbounds"].append(url_test)
    for proxy in data["proxies"]:
        result_json["outbounds"].append(process_proxy(proxy=proxy))
    result_file.write(json.dumps(result_json, ensure_ascii=False))
