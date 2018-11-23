#!/usr/bin/env python3
# -*- coding: UTF-8 -*-


import sys
from funcs import *
import conf


# 执行 shell 命令
def exec_cmd(cmd):
    print('exec: %s' % cmd)
    os.system(cmd)


# 读取日志中的 IP
def read_log_ips():
    log_file_name = get_last_create_file(conf.logDir)
    if log_file_name is None:
        return []
    else:
        log_ips = [conf.r.search(line) for line in read_lines(log_file_name)]
        log_ips = filter(lambda m: m is not None, log_ips)
        log_ips = map(lambda m: m.group(1), log_ips)
        return [ip for ip in log_ips]


# 读取配置文件中的 IP
def read_conf_ips():
    return [ip for ip in read_lines(conf.confFile)]


# 计算封禁的 IP 规则
def calc_iptables_ban_rules(ips):
    ban_ips = [ip for ip in map(ip2int, ips)]
    mask_bans = []
    for mask in range(conf.minMask, conf.maxMask + 1):
        # 应该抛弃多少位
        shr = 32 - mask
        # 超过多少个 IP 应该封段
        min_ip_count = int(2 ** (32 - mask) * conf.minRatio)
        # 各个段的 IP 数
        mask_ip_count = {}
        for ip in ban_ips:
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
            remove_ips = filter(lambda ip: ip >> shr == k, ban_ips)
            for ip in remove_ips:
                ban_ips.remove(ip)
    for ip in ban_ips:
        mask_bans += (ip, 32)
    return ['%s/%d' % (int2ip(t[0] << (32 - t[1])), t[1]) for t in mask_bans]


# 对比新老规则，做必要的规则修改
def update_rules(old_rules, new_rules):
    # 应删除的规则
    remove_rules = sub_list(old_rules, new_rules)
    # 应添加的规则
    add_rules = sub_list(new_rules, old_rules)

    for ip in remove_rules:
        exec_cmd('/sbin/iptables -D INPUT -s %s -i eth0 -p tcp -m tcp --dport %d -m comment --comment autoban -j DROP' % (int2ip(ip), conf.banPort))
        exec_cmd('/sbin/iptables -D INPUT -s %s -i eth0 -p udp -m udp --dport %d -m comment --comment autoban -j DROP' % (int2ip(ip), conf.banPort))
    for ip in add_rules:
        exec_cmd('/sbin/iptables -A INPUT -s %s -i eth0 -p tcp -m tcp --dport %d -m comment --comment autoban -j DROP' % (int2ip(ip), conf.banPort))
        exec_cmd('/sbin/iptables -A INPUT -s %s -i eth0 -p udp -m udp --dport %d -m comment --comment autoban -j DROP' % (int2ip(ip), conf.banPort))


def main():
    # 读取日志中的 IP
    log_ips = read_log_ips()
    print('log ips: %s' % log_ips)

    # 读取配置文件中的 IP
    conf_ips = read_conf_ips()
    print('conf ips: %s' % conf_ips)

    # 合并去重排序
    new_ips = sorted(filter(lambda s: len(s) > 0, list(set(log_ips + conf_ips))), key=ip2int)

    # 写入配置文件
    write_lines(conf.confFile, new_ips)

    # 计算封禁规则
    ban_ips = calc_iptables_ban_rules(new_ips)
    print('ban_ips: %s' % ban_ips)

    # 应用到 iptables 中
    print('exec iptables rule cmds:')
    if len(sys.argv) > 1:
        if sys.argv[1] == '--init-rules':
            # 全量添加
            conf_ips = []
        elif sys.argv[1] == '--reset-rules':
            # 重置 + 全量添加
            conf_ips = []
            exec_cmd('/sbin/iptables -F')
            for cmd in filter(lambda c: len(c) > 0, conf.resetIptablesRules.split('\n')):
                exec_cmd(cmd)
    update_rules(calc_iptables_ban_rules(conf_ips), ban_ips)


if __name__ == '__main__':
    main()
