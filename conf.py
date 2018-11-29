# -*- coding: UTF-8 -*-

import re


# 封禁一个段要求这个段中的 IP 达到的比例
# None: 不按这个段进行封禁
# > 1: 达到这个数量则封禁
# < 1: 达到这个比例则进行封禁
masks = [
    None,        # /0:  4,294,967,296
    None,        # /1:  2,147,483,648
    None,        # /2:  1,073,741,824
    None,        # /3:  536,870,912
    None,        # /4:  268,435,456
    None,        # /5:  134,217,728
    None,        # /6:  67,108,864
    None,        # /7:  33,554,432
    0.10,        # /8:  16,777,216
    0.10,        # /9:  8,388,608
    0.10,        # /10: 4,194,304
    0.10,        # /11: 2,097,152
    0.10,        # /12: 1,048,576
    0.10,        # /13: 524,288
    0.10,        # /14: 262,144
    0.10,        # /15: 131,072
    0.10,        # /16: 65,536
    0.10,        # /17: 32,768
    0.10,        # /18: 16,384
    0.10,        # /19: 8,192
    0.10,        # /20: 4,096
    0.10,        # /21: 2,048
    0.10,        # /22: 1,024
    0.10,        # /23: 512
    0.10,        # /24: 256
    0.10,        # /25: 128
    0.10,        # /26: 64
    0.10,        # /27: 32
    None,        # /28: 16
    None,        # /29: 8
    None,        # /30: 4
    None,        # /31: 2
    None         # /32: 1
]
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
            re.compile(r'invalid request from (([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])(\.([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])){3}):\d+.*invalid user$'): 1
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
