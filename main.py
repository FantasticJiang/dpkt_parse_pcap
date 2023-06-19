import dpkt
import socket
from .utils import *


# 协议特征字段
HTTP_HEADER = {}
HTTP_HOST = {}
HTTP_UA = {}
HTTP_URL = {}
HTTP_REFERER = {}
HTTP_XRW = {}
HTTP_BUNDLEID = {}
HTTP_Q_UA2 = {}
HTTP_SPECIAL_FIELDS = [HTTP_REFERER, HTTP_XRW, HTTP_BUNDLEID, HTTP_Q_UA2]
TLS_SNI = {}
TLS_CN = {}
TCP_PAYLOAD = {}
UDP_PAYLOAD = {}
other_tcp_payload_len = 30
udp_payload_len = 30




def parse_pcap(input_path: str):
    try:
        pcap_file = open(input_path, 'rb')
        input_pcap = dpkt.pcap.Reader(pcap_file)
        packet_count = 0
        # 连接状态判断辅助变量
        tcp_port_dict = {}
        udp_port_dict = {}
        for ts, buf in input_pcap:
            packet_count += 1
            eth = dpkt.ethernet.Ethernet(buf)
            if not isinstance(eth.data, dpkt.ip.IP):
                print("skip non IP packet.")
                continue
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                sport = tcp.sport
                dst = tcp.dport
                # 如果本包tcp负载大于0，则根据本包所属连接是否已解析过采取不同处理
                if len(tcp.data) > 0:
                    pass
                # 如果本包tcp负载为0，则进行握手标志位判断
                else:
                    pass
            elif isinstance(ip.data, dpkt.udp.UDP):
                parse_udp(ip.data)
            else:
                print("skip none tcp and udp packet.")
                continue

            if packet_count == 50:
                break
    except:
        pass
    finally:
        pcap_file.close()


def parse_tcp(tcp: dpkt.tcp.TCP):
    if len(tcp.data) == 0:
        return

    # dpkt似乎没有方法可以在读到一个packet时得知其具有的应用层协议还是仅tcp协议，解析HTTP/HTTPS目前想到的两种方式可能只能是（1）判断tcp.data是否含有HTTP/HTTPS特有的内容；（2）异常处理，先将tcp.data直接当成HTTP解析，抛出异常时当成HTTPS解析，还抛出异常则当无应用层的TCP协议解析。
    try:
        request = dpkt.http.Request(tcp.data)
        print(f'HTTP request: {repr(request)}')
    except:
        pass

    pass


def parse_http_request(http: dpkt.http.Request, dport: int):



def parse_udp(udp: dpkt.udp.UDP):

    pass


if __name__ == "__main__":
    input_pcap_file = './steam_1186http.pcap'
    parse_pcap(input_pcap_file)