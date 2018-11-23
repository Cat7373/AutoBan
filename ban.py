#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import os
import re
from funcs import *

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
# 封禁的端口
banPort = 7373
# 扩展规则
extraIptablesRules = """
/sbin/iptables -F
/sbin/iptables -A INPUT -i eth0 -p tcp -m tcp --tcp-flags FIN,SYN,RST,PSH,URG RST -j DROP
"""


def get_last_log_file(log_dir):
    file_names = [os.path.join(log_dir, fileName) for fileName in os.listdir(log_dir)]
    create_times = [(fileName, os.path.getctime(fileName)) for fileName in file_names]
    create_times = sorted(create_times, key=lambda t: t[1], reverse=True)
    if len(create_times) > 0:
        return create_times[0][0]
    return None


def exec_cmd(cmd):
    print('exec: %s' % cmd)
    os.system(cmd)


# TODO 重构
def main():
    # 读取日志中的 IP
    # TODO 目录为空时报错
    log_file_name = get_last_log_file(logDir)
    log_ips = [r.search(line) for line in read_lines(log_file_name)]
    log_ips = filter(lambda m: m is not None, log_ips)
    log_ips = map(lambda m: m.group(1), log_ips)
    log_ips = [ip for ip in log_ips]
    print('log ips: %s' % log_ips)

    # 读取配置文件中的 IP
    # TODO 不再在 git 仓库中包含空白的配置文件，不存在时这里先不做读取，如果有从日志中读到 IP，后面会自动创建的
    conf_ips = [ip for ip in read_lines(confFile)]
    print('conf ips: %s' % conf_ips)

    # 合并去重排序
    # TODO 未变动时不再做必要的更新
    ips = sorted(filter(lambda ip: len(ip) > 0, list(set(log_ips + conf_ips))), key=ip2int)

    # 写入配置文件
    # TODO 目录不存在时自动创建
    with open(confFile, 'w') as f:
        for ip in ips:
            f.write(ip)
            f.write('\n')

    # 计算封禁规则
    ips = [ip for ip in map(ip2int, ips)]
    mask_bans = []
    for mask in range(minMask, maxMask + 1):
        # 应该抛弃多少位
        shr = 32 - mask
        # 超过多少个 IP 应该封段
        min_ip_count = int(2 ** (32 - mask) * minRatio)
        # 各个段的 IP 数
        mask_ip_count = {}
        for ip in ips:
            key = ip >> shr
            val = mask_ip_count.get(key)
            if val is None:
                val = 0
            mask_ip_count[key] = val + 1
        # 超过阈值的进行处理
        for (k, v) in mask_ip_count.items():
            if v < min_ip_count:
                continue
            mask_bans.append((k, mask))
            remove_ips = filter(lambda ip: ip >> shr == k, ips)
            for ip in remove_ips:
                ips.remove(ip)

    print('maskBans: %s' % ['%s/%d' % (int2ip(t[0] << (32 - t[1])), t[1]) for t in mask_bans])
    print('ipBans: %s' % [int2ip(ip) for ip in ips])

    # 应用到 iptables 中
    # TODO 仅做必要的更新
    #  入参为 --init-rules 时做全量添加
    #  入参为 --reset-rules 时同时执行 iptables -F
    print('exec iptables rule cmds:')
    for cmd in filter(lambda c: len(c) > 0, extraIptablesRules.split('\n')):
        exec_cmd(cmd)
    for t in mask_bans:
        exec_cmd('/sbin/iptables -A INPUT -s %s/%d -i eth0 -p tcp -m tcp --dport %d -m comment --comment autoban -j DROP' % (int2ip(t[0] << (32 - t[1])), t[1], banPort))
        exec_cmd('/sbin/iptables -A INPUT -s %s/%d -i eth0 -p udp -m udp --dport %d -m comment --comment autoban -j DROP' % (int2ip(t[0] << (32 - t[1])), t[1], banPort))
    for ip in ips:
        exec_cmd('/sbin/iptables -A INPUT -s %s -i eth0 -p tcp -m tcp --dport %d -m comment --comment autoban -j DROP' % (int2ip(ip), banPort))
        exec_cmd('/sbin/iptables -A INPUT -s %s -i eth0 -p udp -m udp --dport %d -m comment --comment autoban -j DROP' % (int2ip(ip), banPort))


if __name__ == '__main__':
    main()
