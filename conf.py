# -*- coding: UTF-8 -*-

import re


# 最小和最大掩码，IP 数量计算公式：2 ** (32 - mask)
minMask = 8
maxMask = 27
# 封禁一个段要求这个段中的 IP 达到的比例
minRatio = 0.10
# 日志文件所在目录及其配置
logs = {
    'log/app1': {
        # 按修改时间降序排序后，取前几个文件中的日志
        'count': 2,
        # 匹配用的正则: 第几个 group 是 IP 地址
        'regex': {
            re.compile(r'(([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])(\.([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])){3}): authentication error$'): 1
        }
    },
    'log/app2': {
        'count': 2,
        'regex': {
            re.compile(r'invalid request from (([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])(\.([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])){3}):\d+'): 1
        }
    }
}
# 配置文件
confFile = 'conf/ips.txt'
# 重置时额外添加的规则
resetIptablesRules = """
/sbin/iptables -A INPUT -i eth0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,URG RST -j DROP
"""


# 如果需要改变封禁命令的端口、注释、或其他任何东西，请修改这个方法
def gen_ban_cmd(ip, mode):
    """
    生成 iptables 的 cmd
    :param ip: 目标 IP
    :param mode: 模式，add 或 remove
    :return: 生成的命令的迭代器
    """
    if mode == 'add':
        yield '/sbin/iptables -A INPUT -s %s -i eth0 -p tcp -m multiport --dports 7373,7374,7375 -m comment --comment autoban -j DROP' % ip
        yield '/sbin/iptables -A INPUT -s %s -i eth0 -p udp -m multiport --dports 7373,7374,7375 -m comment --comment autoban -j DROP' % ip
    elif mode == 'remove':
        yield '/sbin/iptables -D INPUT -s %s -i eth0 -p tcp -m multiport --dports 7373,7374,7375 -m comment --comment autoban -j DROP' % ip
        yield '/sbin/iptables -D INPUT -s %s -i eth0 -p udp -m multiport --dports 7373,7374,7375 -m comment --comment autoban -j DROP' % ip
