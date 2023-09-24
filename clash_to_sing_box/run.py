import yaml
import json
import copy


url_test_base = {
    "type": "urltest",
    "tag": "",
    "outbounds": [],
    "url": "https://www.gstatic.com/generate_204",
    "interval": "1m",
    "tolerance": 50,
}
server_base = {
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

place_list = [
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
]

bitz_json = {
    "log": {
        "disabled": False,
        "level": "warn",
        "output": "box.log",
        "timestamp": True,
    },
    "dns": {
        "servers": [
            {"tag": "proxyDns", "address": "tls://8.8.8.8", "detour": "proxy"},
            {
                "tag": "localDns",
                "address": "https://223.5.5.5/dns-query",
                "detour": "direct",
            },
            {
                "tag": "zjuDns",
                "address": "10.10.0.21",
                "detour": "direct",
            },
            {"tag": "block", "address": "rcode://success"},
            {"tag": "remote", "address": "fakeip", "detour": "proxy"},
        ],
        "rules": [
            {"domain": ["ghproxy.com", "cdn.jsdelivr.net"], "server": "localDns"},
            {
                "geosite": "category-ads-all",
                "server": "block",
                "disable_cache": True,
            },
            {"outbound": "any", "server": "localDns", "disable_cache": True},
            {
                "domain_suffix": [
                    "zju.edu.cn"
                    "cc98.org"
                    "nexushd.org"
                    "icsr.wiki"
                    "zjusec.com"
                    "zjusec.net"
                    "zjusec.top"
                    "zjusct.io"
                    "zjueva.net"
                    "zjuqsc.com"
                    "worldcup.myth.cx"
                    "illinois.edu"
                    "acm.org"
                    "cnki.net"
                    "gtadata.com"
                    "jstor.org"
                    "webofscience.com"
                    "inoteexpress.com"
                    "pnas.org"
                    "cnpereading.com"
                    "sciencemag.org"
                    "cas.org"
                    "webofknowledge.com"
                    "pkulaw.com"
                    "sslibrary.com"
                    "serialssolutions.com"
                    "duxiu.com"
                    "wanfangdata.com.cn"
                    "koolearn.com"
                    "cssci.nju.edu.cn"
                    "science.org"
                    "oup.com"
                    "ajtmh.org"
                    "futuremedicine.com"
                    "tandfonline.com"
                    "genetics.org"
                    "healthaffairs.org"
                    "rsna.org"
                    "iospress.com"
                    "allenpress.com"
                    "asabe.org"
                    "geoscienceworld.org"
                    "sagepub.com"
                    "ajnr.org"
                    "ajhp.org"
                    "annals.org"
                    "esajournals.org"
                    "informs.org"
                    "cshlpress.com"
                    "nrcresearchpress.cn"
                    "royalsocietypublishing.org"
                    "oxfordjournals.org"
                    "aspbjournals.org"
                    "sciencesocieties.org"
                    "degruyter.com"
                    "cshprotocols.org"
                    "liebertonline.com"
                    "polymerjournals.com"
                    "csiro.au"
                    "iop.org"
                    "electrochem.org"
                    "ametsoc.org"
                    "portlandpress.com"
                    "nrcresearchpress.com"
                    "arabidopsis.org"
                    "springerlink.com"
                    "highwire.org"
                    "ovid.com"
                    "rsc.org"
                    "bmj.org"
                    "aip.org"
                    "springer.com"
                    "iwaponline.com"
                    "rsnajnls.org"
                    "karger.com"
                    "wiley.com"
                    "plantcell.org"
                    "jamanetwork.com"
                    "nejm.org"
                ],
                "server": "zjuDns",
            },
            {"geosite": ["cn", "private"], "server": "localDns"},
            {"clash_mode": "direct", "server": "localDnsDns"},
            {"clash_mode": "global", "server": "proxyDns"},
            {"geosite": "geolocation-!cn", "server": "proxyDns"},
            {"query_type": ["A", "AAAA"], "server": "remote"},
        ],
        "fakeip": {
            "enabled": True,
            "inet4_range": "198.18.0.0/15",
            "inet6_range": "fc00::/18",
        },
        "independent_cache": True,
        "strategy": "ipv4_only",
    },
    "inbounds": [
        {
            "type": "tun",
            "inet4_address": "172.19.0.1/30",
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
                    "server_port": 2080,
                }
            },
        },
        {
            "type": "mixed",
            "listen": "127.0.0.1",
            "listen_port": 2080,
            "sniff": True,
            "sniff_override_destination": False,
            "domain_strategy": "ipv4_only",
        },
    ],
    "outbounds": [
        {
            "tag": "proxy",
            "type": "selector",
            "outbounds": ["auto", "地区选择", "节点选择", "direct"],
        },
        {
            "type": "urltest",
            "tag": "auto",
            "outbounds": copy.deepcopy(place_list),
            "url": "https://www.gstatic.com/generate_204",
            "interval": "1m",
            "tolerance": 50,
        },
        {
            "tag": "地区选择",
            "type": "selector",
            "outbounds": copy.deepcopy(place_list),
        },
        {
            "tag": "OpenAI",
            "type": "selector",
            "outbounds": [
                "美国",
            ],
        },
        {
            "tag": "OneDrive",
            "type": "selector",
            "outbounds": ["proxy", "direct"],
        },
        {
            "tag": "Microsoft",
            "type": "selector",
            "outbounds": [
                "direct",
                "proxy",
            ],
        },
        {
            "tag": "Social",
            "type": "selector",
            "outbounds": ["proxy", "direct"],
        },
        {
            "tag": "Shopping",
            "type": "selector",
            "outbounds": ["proxy", "direct"],
        },
        {
            "tag": "哔哩哔哩",
            "type": "selector",
            "outbounds": [
                "direct",
                "台湾",
                "香港",
                "proxy",
            ],
        },
        {
            "tag": "哔哩东南亚",
            "type": "selector",
            "outbounds": [
                "香港",
                "台湾",
                "proxy",
            ],
        },
        {
            "tag": "巴哈姆特",
            "type": "selector",
            "outbounds": [
                "台湾",
                "香港",
                "proxy",
            ],
        },
        {
            "tag": "动画疯",
            "type": "selector",
            "outbounds": ["台湾", "direct"],
        },
        {
            "tag": "Apple",
            "type": "selector",
            "outbounds": [
                "direct",
                "proxy",
            ],
        },
        {
            "tag": "Game",
            "type": "selector",
            "outbounds": [
                "日本",
                "香港",
                "台湾",
                "proxy",
                "direct",
            ],
        },
        {
            "tag": "Streaming",
            "type": "selector",
            "outbounds": ["proxy", "direct"],
        },
        {
            "tag": "Google",
            "type": "selector",
            "outbounds": ["proxy", "direct"],
        },
        {"tag": "Speedtest", "type": "selector", "outbounds": ["direct", "proxy"]},
        {"type": "direct", "tag": "direct"},
        {"type": "dns", "tag": "dns"},
        {"type": "block", "tag": "block"},
    ],
    "route": {
        "auto_detect_interface": True,
        "final": "proxy",
        "geoip": {
            "download_url": "https://ghproxy.com/github.com/SagerNet/sing-geoip/releases/latest/download/geoip.db",
            "download_detour": "direct",
        },
        "geosite": {
            "download_url": "https://ghproxy.com/github.com/SagerNet/sing-geosite/releases/latest/download/geosite.db",
            "download_detour": "direct",
        },
        "rules": [
            {"protocol": "dns", "outbound": "dns"},
            {"network": "udp", "port": 443, "outbound": "block"},
            {"geosite": "category-ads-all", "outbound": "block"},
            {"clash_mode": "direct", "outbound": "direct"},
            {"clash_mode": "global", "outbound": "proxy"},
            {
                "domain": ["clash.razord.top", "yacd.metacubex.one", "yacd.haishan.me"],
                "outbound": "direct",
            },
            {
                "ip_cidr": ["10.0.0.0/8"],
                "domain": [
                    "zju.edu.cn"
                    "cc98.org"
                    "nexushd.org"
                    "icsr.wiki"
                    "zjusec.com"
                    "zjusec.net"
                    "zjusec.top"
                    "zjusct.io"
                    "zjueva.net"
                    "zjuqsc.com"
                    "worldcup.myth.cx"
                    "illinois.edu"
                    "acm.org"
                    "cnki.net"
                    "gtadata.com"
                    "jstor.org"
                    "webofscience.com"
                    "inoteexpress.com"
                    "pnas.org"
                    "cnpereading.com"
                    "sciencemag.org"
                    "cas.org"
                    "webofknowledge.com"
                    "pkulaw.com"
                    "sslibrary.com"
                    "serialssolutions.com"
                    "duxiu.com"
                    "wanfangdata.com.cn"
                    "koolearn.com"
                    "cssci.nju.edu.cn"
                    "science.org"
                    "oup.com"
                    "ajtmh.org"
                    "futuremedicine.com"
                    "tandfonline.com"
                    "genetics.org"
                    "healthaffairs.org"
                    "rsna.org"
                    "iospress.com"
                    "allenpress.com"
                    "asabe.org"
                    "geoscienceworld.org"
                    "sagepub.com"
                    "ajnr.org"
                    "ajhp.org"
                    "annals.org"
                    "esajournals.org"
                    "informs.org"
                    "cshlpress.com"
                    "nrcresearchpress.cn"
                    "royalsocietypublishing.org"
                    "oxfordjournals.org"
                    "aspbjournals.org"
                    "sciencesocieties.org"
                    "degruyter.com"
                    "cshprotocols.org"
                    "liebertonline.com"
                    "polymerjournals.com"
                    "csiro.au"
                    "iop.org"
                    "electrochem.org"
                    "ametsoc.org"
                    "portlandpress.com"
                    "nrcresearchpress.com"
                    "arabidopsis.org"
                    "springerlink.com"
                    "highwire.org"
                    "ovid.com"
                    "rsc.org"
                    "bmj.org"
                    "aip.org"
                    "springer.com"
                    "iwaponline.com"
                    "rsnajnls.org"
                    "karger.com"
                    "wiley.com"
                    "plantcell.org"
                    "jamanetwork.com"
                    "nejm.org"
                ],
                "outbound": "direct",
            },
            {
                "domain_keyword": ["speedtest"],
                "domain_suffix": ["cdnst.net", "ziffstatic.com"],
                "outbound": "Speedtest",
            },
            {"geosite": "openai", "outbound": "OpenAI"},
            {"geoip": "google", "geosite": ["google", "github"], "outbound": "Google"},
            {
                "geoip": ["telegram", "twitter", "facebook"],
                "geosite": ["telegram", "twitter", "facebook", "instagram", "discord"],
                "outbound": "Social",
            },
            {"geosite": "amazon", "outbound": "Shopping"},
            {"geosite": "apple", "outbound": "Apple"},
            {"geosite": "microsoft", "outbound": "Microsoft"},
            {"geosite": "category-games", "outbound": "Game"},
            {
                "geosite": "bilibili",
                "outbound": "哔哩哔哩",
            },
            {
                "domain": [
                    "0gr4uqmtt8y41hcjsgrzdrc31.ourdvsss.com",
                    "0gr4uqmtt8y41hcjsgrzdrc3s.ourdvsss.com",
                    "0gr4uqmtt8y41hcjsgrzdrc3z.ourdvsss.com",
                    "0gr4uqmtt8y41hcjsgrzdrctt.ourdvsss.com",
                    "0gr4uqmtt8y41hcjsgrzdrctu.ourdvsss.com",
                    "0gr4uqmtt8y41hcjz8yzdnc31.ourdvsss.com",
                    "0gr4uqmtt8y41hcjz8yzdnc3t.ourdvsss.com",
                    "0gr4uqmtt8y41hcjzgazdrpba.ourdvsss.com",
                    "0gr4uqmtt8y41hcjzgazdrpbz.ourdvsss.com",
                    "0gr4uqmtt8y41hcjzgazdrpjt.ourdvsss.com",
                    "0gr5dgmttgha1hcj38yzdncb3.ourdvsss.com",
                    "112-81-125-43.dhost.00cdn.com",
                    "113-219-145-1.ksyungslb.com",
                    "114-236-92-129.ksyungslb.com",
                    "180-101-74-1.ksyungslb.com",
                    "1geadrmttge3nhcjwgazdope.ourdvsss.com",
                    "1geadrmttge3nhcjwgwzdqqe.ourdvsss.com",
                    "1gr3uomttgr31hcjo8yzdnco.ourdvsss.com",
                    "1gr3uomttgr31hcjo8yzdnpy.ourdvsss.com",
                    "1gr3uomttgr31hcjtgezdkcy.ourdvsss.com",
                    "1gr4uqmtt8y41hcjigazdqca.ourdvsss.com",
                    "1gr4uqmtt8y41hcjigazdqce.ourdvsss.com",
                    "1gr4uqmtt8y41hcjigazdqco.ourdvsss.com",
                    "1gr4uqmtt8y41hcjigazdqpo.ourdvsss.com",
                    "1gr4uqmtt8y41hcjzgwzdkqe.ourdvsss.com",
                    "1gr5dgmttgha1hcj38yzdcca.ourdvsss.com",
                    "1gr5dgmttgha1hcj38yzdcco.ourdvsss.com",
                    "1gr5dgmttgha1hcj38yzdkca.ourdvsss.com",
                    "1gr5dgmttgha1hcj38yzdkco.ourdvsss.com",
                    "1gr5dgmttgha1hcj38yzdkpe.ourdvsss.com",
                    "1gr5dgmttgha1hcj38yzdkpy.ourdvsss.com",
                    "1gr5dgmttgha1hcj38yzdkqy.ourdvsss.com",
                    "1gr5dgmttgha1hcj3gczdcpa.ourdvsss.com",
                    "1gr5dgmttgha1hcj3gczdcpe.ourdvsss.com",
                    "1gr5dgmttgha1hcj3gczdcpo.ourdvsss.com",
                    "1gr5dgmttgha1hcj3gczdcqy.ourdvsss.com",
                    "1gr5dgmttgha1hcttgrzdnpo.ourdvsss.com",
                    "1graukmttga4nhcjtgozdgce.ourdvsss.com",
                    "218-91-225-1.ksyungslb.com",
                    "219-155-150-1.ksyungslb.com",
                    "222-188-6-1.ksyungslb.com",
                    "36-104-134-1.ksyungslb.com",
                    "36-25-252-1.ksyungslb.com",
                    "3ge3drmttga5nhcbqge3ur.ourdvsss.com",
                    "3geauymtsgrzdnqbofa5do.ourdvsss.com",
                    "3geauymtsgrzdnqbofa5dy.ourdvsss.com",
                    "3geauymtsgrzdrcbzfahue.ourdvsss.com",
                    "3geauymtsgrzdrcbzfahuk.ourdvsss.com",
                    "4go41hcjtgazdoctqge4o.ourdvsss.com",
                    "p-bstarstatic.akamaized.net",
                    "p.bstarstatic.com",
                    "upos-bstar-mirrorakam.akamaized.net",
                    "upos-bstar1-mirrorakam.akamaized.net",
                ],
                "domain_suffix": [
                    "acg.tv",
                    "acgvideo.com",
                    "animetamashi.cn",
                    "animetamashi.com",
                    "anitama.cn",
                    "anitama.net",
                    "b23.tv",
                    "baka.im",
                    "bigfun.cn",
                    "bigfunapp.cn",
                    "bili22.cn",
                    "bili2233.cn",
                    "bili23.cn",
                    "bili33.cn",
                    "biliapi.com",
                    "biliapi.net",
                    "bilibili.cc",
                    "bilibili.cn",
                    "bilibili.co",
                    "bilibili.com",
                    "bilibili.net",
                    "bilibili.tv",
                    "bilibiligame.cn",
                    "bilibiligame.co",
                    "bilibiligame.net",
                    "bilibilipay.cn",
                    "bilibilipay.com",
                    "bilicdn1.com",
                    "bilicdn2.com",
                    "bilicdn3.com",
                    "bilicdn4.com",
                    "bilicdn5.com",
                    "bilicomics.com",
                    "biligame.cn",
                    "biligame.co",
                    "biligame.com",
                    "biligame.net",
                    "biligo.com",
                    "biliimg.com",
                    "biliintl.com",
                    "biliplus.com",
                    "bilivideo.cn",
                    "bilivideo.com",
                    "bilivideo.net",
                    "corari.com",
                    "dreamcast.hk",
                    "dyhgames.com",
                    "hdslb.com",
                    "hdslb.com.w.kunlunhuf.com",
                    "hdslb.com.w.kunlunpi.com",
                    "hdslb.net",
                    "hdslb.org",
                    "im9.com",
                    "maoercdn.com",
                    "mcbbs.net",
                    "mincdn.com",
                    "sharejoytech.com",
                    "smtcdns.net",
                    "upos-hz-mirrorakam.akamaized.net",
                    "uposdash-302-bilivideo.yfcdn.net",
                    "yo9.com",
                ],
                "ip_cidr": [
                    "106.75.74.76/32",
                    "111.206.25.147/32",
                    "119.3.238.64/32",
                    "120.92.108.182/32",
                    "120.92.113.99/32",
                    "120.92.153.217/32",
                    "134.175.207.130/32",
                    "203.107.1.0/24",
                ],
                "geosite": "biliintl",
                "outbound": "哔哩东南亚",
            },
            {
                "geosite": "bahamut",
                "outbound": "巴哈姆特",
            },
            {
                "geoip": "netflix",
                "geosite": ["youtube", "netflix", "hbo", "disney", "primevideo"],
                "outbound": "Streaming",
            },
            {"geosite": "geolocation-!cn", "outbound": "proxy"},
            {
                "geosite": ["private", "cn"],
                "geoip": ["private", "cn", "LAN"],
                "outbound": "direct",
            },
        ],
    },
    "experimental": {
        "clash_api": {
            "external_controller": "127.0.0.1:9090",
            "external_ui": "ui",
            "external_ui_download_url": "",
            "external_ui_download_detour": "",
            "secret": "",
            "default_mode": "rule",
            "store_selected": True,
            "cache_file": "",
            "cache_id": "",
        }
    },
}


url_test_dict = {name: copy.deepcopy(url_test_base) for name in place_list}
for name in place_list:
    url_test_dict[name]["tag"] = name

single_selecor = {
    "type": "selector",
    "tag": "节点选择",
    "outbounds": [],
    #   "default": "proxy-c",
    # "interrupt_exist_connections": False,
}

with open("mixed.yaml", "r", encoding="utf-8") as file, open(
    "bitz.json", "w", encoding="utf-8"
) as bitz_file:
    data = yaml.load(file.read(), Loader=yaml.FullLoader)
    for proxy in data["proxies"]:
        single_selecor["outbounds"].append(proxy["name"])
        for place_name in place_list:
            if place_name in proxy["name"]:
                url_test_dict[place_name]["outbounds"].append(proxy["name"])
                server_now = copy.deepcopy(server_base)
                server_now["tag"] = proxy["name"]
                server_now["server"] = proxy["server"]
                server_now["server_port"] = proxy["port"]
                server_now["password"] = proxy["password"]
                bitz_json["outbounds"].append(server_now)

                break
    for url_test in url_test_dict.values():
        bitz_json["outbounds"].append(url_test)
    bitz_json["outbounds"].append(single_selecor)
    bitz_file.write(json.dumps(bitz_json, ensure_ascii=False))
