import sys

from dpkt_parse_pcap import *
import os


def find_pcap_files(path: str, pcap_list: list):
    # 获取指定路径下的所有文件和子文件夹
    for root, dirs, files in os.walk(path):
        for file in files:
            if file.endswith(".pcap"):
                pcap_file_path = os.path.join(root, file)
                pcap_list.append(pcap_file_path)


def dpkt_parse_multi_pcap(mode: str, pcap_path: str):
    if pcap_path:
        if not os.path.exists(pcap_path):
            print(f"{pcap_path} 路径不存在！")
            return
        print("当前读取文件目录：", pcap_path)
        pcap_list = []  # 因为要递归，所以要把变量放在外面先定义。
        find_pcap_files(pcap_path, pcap_list)
        print("报文总数：", len(pcap_list))
        if mode == '-t':
            for pcap in pcap_list:
                print("当前解析报文：", pcap)
                parse_pcap(pcap)

            # -t 模式下汇总解析内容存放在与指定路径相同目录下
            save_path = os.path.join(pcap_path, os.path.basename(pcap_path.rstrip('/').rstrip('\\')))
            print(save_path)
            write_parse_result(save_path)
            print("-t success")
            print("----------------------")
            print(f"结果已保存在：{pcap_path}\n")

        elif mode == '-o':
            for pcap in pcap_list:
                print("当前解析报文：", pcap)
                parse_pcap(pcap)
                # -o 模式下每个报文解析完就将解析结果存放在对应报文目录下
                write_parse_result(os.path.splitext(pcap)[0])
            print("-o success\n")


if __name__ == "__main__":
    argv = sys.argv
    if len(argv) < 3:
        exit("请输入需要解析报文的文件夹路径。使用示例：\n dpkt_parse_multi_pcap.py [-t|-o] pcap_path")
    parse_mode = argv[1]
    pcap_path = argv[2]
    dpkt_parse_multi_pcap(parse_mode, pcap_path)
