# -*- coding: UTF-8 -*-

import re


# 最小和最大掩码，IP 数量计算公式：2 ** (32 - mask)
minMask = 8
maxMask = 27
# 封禁一个段要求这个段中的 IP 达到的比例
minRatio = 0.10
# 日志文件所在目录
logDir = 'log'
# 配置文件
confFile = 'conf/ips.txt'
# 从日志中匹配 IP 地址的正则
r = re.compile('(([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])(\.([1-9]?\d|1\d{2}|2[0-4]\d|25[0-5])){3}): authentication error$')
# 封禁的端口 # TODO 支持多个
banPort = 7373
# 扩展规则
extraIptablesRules = """
/sbin/iptables -F
/sbin/iptables -A INPUT -i eth0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,URG RST -j DROP
"""
