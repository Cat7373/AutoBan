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
    },
    'log/app3': {
        'count': 2,
        'regex': {
            re.compile(r'Disconnected from invalid user [^\s]* (([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])(\.([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])){3}) port \d+'): 1,
            re.compile(r'Connection closed by invalid user [^\s]* (([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])(\.([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])){3}) port \d+'): 1
        }
    }
}
# 配置文件
confFile = 'conf/ips.txt'
# 重置时生成的规则脚本，其中 %s 是用于存放生成的 ip 列表用的
# 开头的行作为注释，不会被执行，# 前面可以有任意数量的空格，不会影响注释的判定，但不能有其他字符
nfResetRule = """
flush ruleset

define autobanIps = { %s }

add table autoban
add chain autoban input { type filter hook input priority 0; }
# TODO TCP 只拦截握手包，其余全部拦截
add rule autoban input meta oifname eth0 ip saddr $autobanIps drop
"""
# 生成的规则存放的临时文件
tmpRuleFile = '/tmp/autoban_rule_file.nft'
