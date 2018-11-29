#!/usr/bin/env python3
# -*- coding: UTF-8 -*-


from funcs import *
import conf
from optparse import OptionParser
import logging


options = None


# 执行 shell 命令
def exec_cmd(cmd):
    global options

    logging.debug('exec: %s' % cmd)
    if not options.test:
        os.system(cmd)


# 读取日志中的 IP
def read_log_ips():
    for log_dir in conf.logs:
        dir_conf = conf.logs[log_dir]

        # 读出符合条件的文件
        for log_file_name in get_last_modify_file(log_dir, dir_conf['count']):
            for line in read_lines(log_file_name):
                for (r, g) in dir_conf['regex'].items():
                    m = r.search(line)
                    if m is not None:
                        ip = m.group(g)
                        yield ip
                        break


# 读取配置文件中的 IP
def read_conf_ips():
    return [ip for ip in read_lines(conf.confFile)]


# 计算封禁的 IP 规则
def calc_iptables_ban_rules(ips):
    ban_ips = [ip2int(ip) for ip in ips]
    mask_bans = []
    for mask in range(len(conf.masks)):
        # 应该抛弃多少位
        shr = 32 - mask
        # 当前段中的总 IP 数量
        mask_ip_count = 2 ** (32 - mask)
        # 超过多少个 IP 应该封段
        min_ip_count = conf.masks[mask]
        if min_ip_count is None:
            continue
        assert min_ip_count < mask_ip_count
        assert min_ip_count > 0
        if min_ip_count < 1:
            min_ip_count = max(int(mask_ip_count * min_ip_count), 1)

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
        mask_bans.append((ip, 32))
    return ['%s/%d' % (int2ip(t[0] << (32 - t[1])), t[1]) for t in mask_bans]


# 对比新老规则，做必要的规则修改
def update_rules(old_rules, new_rules):
    # 应删除的规则
    remove_rules = sub_list(old_rules, new_rules)
    # 应添加的规则
    add_rules = sub_list(new_rules, old_rules)

    for ip in remove_rules:
        for cmd in conf.gen_ban_cmd(ip, 'remove'):
            exec_cmd(cmd)
    for ip in add_rules:
        for cmd in conf.gen_ban_cmd(ip, 'add'):
            exec_cmd(cmd)


# TODO IPv6?
def main():
    global options

    # 读取日志中的 IP
    log_ips = [ip for ip in read_log_ips()]
    logging.debug('log ips: %s' % log_ips)

    # 读取配置文件中的 IP
    conf_ips = read_conf_ips()
    logging.debug('conf ips: %s' % conf_ips)

    # 合并去重排序
    new_ips = sorted(filter(lambda s: len(s) > 0, list(set(log_ips + conf_ips))), key=ip2int)

    # 写入配置文件
    if not options.test:
        write_lines(conf.confFile, new_ips)

    # 计算封禁规则
    ban_ips = calc_iptables_ban_rules(new_ips)
    logging.debug('ban_ips: %s' % ban_ips)

    # 应用到 iptables 中
    logging.debug('exec iptables rule cmds:')
    if options.init_rules:
        # 全量添加
        conf_ips = []
    if options.reset_rules:
        # 重置 + 全量添加
        conf_ips = []
        exec_cmd('/sbin/iptables -F')
        for cmd in filter(lambda c: len(c) > 0, conf.resetIptablesRules.split('\n')):
            exec_cmd(cmd)
    update_rules(calc_iptables_ban_rules(conf_ips), ban_ips)

    logging.info('done.')


def init():
    global options
    parser = OptionParser()
    parser.add_option('-t', '--test', action='store_true', dest='test', default=False, help='测试运行，不实际做任何修改')
    parser.add_option('-i', '--init-rules', action='store_true', dest='init_rules', default=False, help='初始化 iptables 规则')
    parser.add_option('-r', '--reset-rules', action='store_true', dest='reset_rules', default=False, help='重置 iptables 规则')
    parser.add_option('--debug', action='store_true', dest='debug', default=False, help='开启调试日志输出')
    (options, _) = parser.parse_args()

    logging_level = logging.INFO
    if options.debug:
        logging_level = logging.DEBUG
    logging.basicConfig(level=logging_level,
                        format='[%(asctime)s] [%(levelname)s]: %(message)s',
                        datefmt='%H:%M:%S')


if __name__ == '__main__':
    init()
    main()
