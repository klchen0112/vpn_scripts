# 导入所需的库
import requests
import yaml

black_list = ["机场","订阅","流量","套餐","重置","电报群","官网","去除"]
with open("airport.txt","r") as fp:
    headers = {'User-Agent': 'clash-verge/v1.3.8'}
    result_dict = {
        'proxies': []
    }
    for line in fp.readlines():
        url = line.strip()
        if len(url) == 0:
            break
        # 发送HTTPS请求并获取响应
        response = requests.get(url=url,headers=headers)  # 用你的API端点替换这里的URL

        # 使用PyYAML解析响应的内容
        data = yaml.safe_load(response.text)
        for proxy in data['proxies']:
            flag = True
            for bn in black_list:
                if bn in proxy['name']:
                    flag = False
                    break
            if flag:
                result_dict['proxies'].append(proxy)
        # 现在，变量'data'包含了从HTTPS响应中解析出的数据
    with open("mixed.yaml","w", encoding='utf-8') as rf:
        yaml.dump(result_dict,rf, allow_unicode=True, encoding='utf-8')
