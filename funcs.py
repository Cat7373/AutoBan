#!/usr/bin/env python3
# -*- coding: UTF-8 -*-

import os


def int2ip(num):
    """
    将数字转换为 IPv4 地址
    :param num 输入的数字
    :return 转换的 IPv4 地址字符串
    """
    ip = ''
    for i in range(4):
        ip = '.' + str(num & 255) + ip
        num >>= 8
    return ip[1:]


def ip2int(ip):
    """
    将 IPv4 地址转换为数字
    :param ip IPv4 地址
    :return 转换的数字
    """
    mul = 3
    num = 0
    for n in ip.split('.'):
        num += int(n) * (256 ** mul)
        mul -= 1
    return num


def sub_list(subtracted, subtraction):
    """
    list 减法(求差集)
    :param subtracted: 被减数(list)
    :param subtraction: 减数(list)
    :return: 差集
    """
    return [e for e in subtracted if e not in subtraction]


def read_lines(file_name):
    """
    按行读取文件
    :param file_name 被读取的文件的文件名
    :return 每一行的内容的迭代器
    """
    if not os.path.exists(file_name):
        return
    with open(file_name) as f:
        while True:
            line = f.readline()
            if not line:
                return
            yield line[:-1]  # 去掉 \n


def write_lines(file_name, lines):
    """
    按行写入文件(如文件已存在则会覆盖)
    :param file_name: 被写入的文件的文件名
    :param lines: 要写入的行列表(行尾不应有 \n)
    """
    # 目录不存在时自动创建
    dir_name = os.path.dirname(file_name)
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
    # 写出数据
    with open(file_name, 'w') as f:
        for line in lines:
            f.write(line)
            f.write('\n')


def get_last_create_file(dir_name):
    """
    获取目录中最晚创建的文件
    :param dir_name: 目录的全路径
    :return: 这个目录中最晚创建的文件，如果这是个空目录，则返回 None
    """
    file_names = [os.path.join(dir_name, fileName) for fileName in os.listdir(dir_name)]
    if len(file_names) is 0:
        return None
    create_times = [(fileName, os.path.getctime(fileName)) for fileName in file_names]
    create_times = max(create_times, key=lambda t: t[1])
    return create_times[0][0]


def __unit_test():
    """
    单元测试
    """
    assert ip2int('11.22.33.44') == 185999660
    assert int2ip(185999660) == '11.22.33.44'
    assert sub_list([1, 2, 3], [2, 3, 4]) == [1]
    assert sub_list([2, 3, 4], [1, 2, 3]) == [4]

    print('done.')


if __name__ == '__main__':
    __unit_test()
