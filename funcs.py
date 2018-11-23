#!/usr/bin/env python3
# -*- coding: UTF-8 -*-


def int2ip(num):
    """
    将数字转换为 IPv4 地址
    @param num 输入的数字
    @return 转换的 IPv4 地址字符串
    """
    ip = ''
    for i in range(4):
        ip = '.' + str(num & 255) + ip
        num >>= 8
    return ip[1:]


def ip2int(ip):
    """
    将 IPv4 地址转换为数字
    @param ip IPv4 地址
    @return 转换的数字
    """
    mul = 3
    num = 0
    for n in ip.split('.'):
        num += int(n) * (256 ** mul)
        mul -= 1
    return num


def read_lines(file_name):
    """
    按行读取文件
    @param file_name 被读取的文件的文件名
    @yield 每一行的内容
    """
    with open(file_name) as f:
        while True:
            line = f.readline()
            if not line:
                return
            yield line[:-1]


def __unit_test():
    """
    单元测试
    """
    assert ip2int('11.22.33.44') == 185999660
    assert int2ip(185999660) == '11.22.33.44'

    print('done.')


if __name__ == '__main__':
    __unit_test()
