import socket
import dpkt
from utils import *

# 协议特征字段
HTTP_HEADER = {}
HTTP_HOST = {}
HTTP_UA = {}
HTTP_URL = {}
HTTP_REFERER = {}
HTTP_XRW = {}
HTTP_BUNDLEID = {}
HTTP_USER_IDENTITY = {}
HTTP_Q_UA2 = {}
HTTP_X_UMENG_SDK = {}
HTTP_SPECIAL_FIELDS = [HTTP_REFERER, HTTP_XRW, HTTP_BUNDLEID, HTTP_USER_IDENTITY, HTTP_Q_UA2, HTTP_X_UMENG_SDK]
TLS_SNI = {}
TLS_CN = {}
TCP_PAYLOAD = {}
UDP_PAYLOAD = {}
QUIC_SNI = {}
DNS_QUERY = {}
other_tcp_payload_len = 30
udp_payload_len = 30


def write_parse_result(filename: str):
    # HTTP
    write_dict_to_file(HTTP_HOST, filename, '_host.log')
    write_dict_to_file(HTTP_UA, filename, '_ua.log')
    write_dict_to_file(HTTP_URL, filename, '_url.log')
    if HTTP_REFERER or HTTP_XRW or HTTP_BUNDLEID or HTTP_USER_IDENTITY or HTTP_Q_UA2 or HTTP_X_UMENG_SDK:
        write_dict_to_file(HTTP_SPECIAL_FIELDS, filename, '_special_fields.log')
    # HTTPS
    write_dict_to_file(TLS_SNI, filename, '_ser_name.log')
    write_dict_to_file(TLS_CN, filename, '_cn.log')

    # QUIC
    if QUIC_SNI:
        write_dict_to_file(QUIC_SNI, filename, '_quic_sni.log')

    write_dict_to_file(TCP_PAYLOAD, filename, '_tcp_flow.log')
    write_dict_to_file(UDP_PAYLOAD, filename, '_udp_flow.log')
    write_dict_to_file(DNS_QUERY, filename, 'dns_query.log')



def parse_pcap(input_path: str):
    try:
        pcap_file = open(input_path, 'rb')
        input_pcap = dpkt.pcap.Reader(pcap_file)
        packet_count = 0
        # 连接状态判断辅助变量
        tcp_4tuple_dict = {}
        tcp_handshake_comlete = {}
        udp_4tuple_dict = {}
        for ts, buf in input_pcap:
            packet_count += 1
            eth = dpkt.ethernet.Ethernet(buf)
            # 这样写的话不支持IPv6，后续要改
            if not isinstance(eth.data, dpkt.ip.IP):
                print("skip non IP packet.")
                continue
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            # TCP
            if isinstance(ip.data, dpkt.tcp.TCP):
                tcp = ip.data
                sport = tcp.sport
                dport = tcp.dport
                src2dst = (src, sport, dst, dport)
                src2dst_rvs = (dst, dport, src, sport)
                # 如果本包tcp负载大于0，则根据本包所属连接是否完成握手、是否已解析过采取不同处理
                if len(tcp.data) > 0:
                    # 四元组已在字典中，表示已解析过一次。统计四元组包数量。（后续要加TLS reply方向特征解析）
                    if src2dst in tcp_4tuple_dict or src2dst_rvs in tcp_4tuple_dict:
                        try:
                            tcp_4tuple_dict[src2dst] += 1
                        except KeyError:
                            tcp_4tuple_dict[src2dst_rvs] += 1
                    # 四元组未在字典中，表示此流首次解析。若三次握手完成则解析。
                    else:
                        tcp_4tuple_dict[src2dst] = 1
                        if tcp_handshake_comlete[src2dst] >= 3:
                            parse_tcp(tcp)

                # 如果本包tcp负载为0，则进行握手标志位判断
                else:
                    if src2dst in tcp_handshake_comlete or src2dst_rvs in tcp_handshake_comlete:
                        try:
                            tcp_handshake_comlete[src2dst] += 1
                        except KeyError:
                            tcp_handshake_comlete[src2dst_rvs] += 1
                    else:
                        tcp_handshake_comlete[src2dst] = 1

            # UDP
            elif isinstance(ip.data, dpkt.udp.UDP):
                parse_udp(ip.data)
            else:
                print("skip none tcp and udp packet.")
                continue

            if packet_count%1000 == 0:
                print(f'已解析分组数：{packet_count}')

        # 解析完pcap文件中的所有分组，将特征字典写入log文件
        import os
        filename = os.path.splitext(input_path)[0]
        write_parse_result(filename)
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
        parse_http_request(request, tcp.dport)
    except:
        pass

    pass


def parse_http_request(http: dpkt.http.Request, dport: int):
    # dpkt.http.Request对象将HTTP请求的状态行（第一行）中method、uri、version单独作为成员变量，第二行开始的所有HTTP字段放入名为header的有序字典变量中。
    headers = http.headers
    headers['method'] = http.method
    headers['uri'] = http.uri
    # basic fields
    add_dict_kv(HTTP_HOST, headers['host']+f" [{dport}]")
    add_dict_kv(HTTP_UA, headers['user-agent']+f" [{dport}]")
    add_dict_kv(HTTP_URL, headers['method']+" "+headers['uri']+f" [{dport}]")
    # special fields (if exists)
    if 'referer' in headers:
        add_dict_kv(HTTP_REFERER, headers['referer']+f" [{dport}]")
    if 'bundleid' in headers:
        add_dict_kv(HTTP_BUNDLEID, headers['bundleid']+f" [{dport}]")
    if 'user-identity' in headers:
        add_dict_kv(HTTP_USER_IDENTITY, headers['user-identity']+f" [{dport}]")
    if 'x-requested-with' in headers:
        add_dict_kv(HTTP_XRW, headers['x-requested-with']+f" [{dport}]")
    if 'q-ua2' in headers:
        add_dict_kv(HTTP_Q_UA2, headers['q-ua2']+f" [{dport}]")
    # print(f'HTTP request: {repr(http)}')


def parse_udp(udp: dpkt.udp.UDP):

    pass


if __name__ == "__main__":
    input_pcap_file = './pcaps/http_user-identity.pcap'
    parse_pcap(input_pcap_file)