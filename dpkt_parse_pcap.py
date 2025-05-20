import socket
import dpkt
from dpkt import UnpackError, NeedData
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
TLS_SERVER_NAME = {}
TLS_CN = {}
TCP_PAYLOAD_HEAD = {}
TCP_PAYLOAD_TAIL = {}
UDP_PAYLOAD_HEAD = {}
UDP_PAYLOAD_TAIL = {}
QUIC_SNI = {}
DNS_QUERY = {}
other_tcp_payload_len = 30
udp_payload_len = 20

tls_caches: dict = {}
http_caches: dict = {}

# 状态判断辅助变量
tcp_4tuple_dict = {}  # 判断一条tcp流是否已解析过一次
tcp_handshake_complete = {}  # 判断tcp连接是否建立完成
tlsSNI_parsed_port_pair = {}  # 判断是否成功进入过TLS server_name解析流程，用于后续判断是否需要尝试解析common_name
port_pair_c2s = {}  # 判断包的流向
udp_4tuple_dict = {}  # 判断一条udp流是否已解析过一次
SYN_ACK = {}  # 判断一条流有抓到Server->Client的syn_ack包



def clear_temp_dict():
    tcp_4tuple_dict.clear()
    tcp_handshake_complete.clear()
    tlsSNI_parsed_port_pair.clear()
    port_pair_c2s.clear()
    udp_4tuple_dict.clear()
    tls_caches.clear()
    http_caches.clear()


def write_parse_result(filename: str):
    # HTTP
    write_dict_to_file(HTTP_HOST, filename, '_host.log')
    write_dict_to_file(HTTP_UA, filename, '_ua.log')
    write_dict_to_file(HTTP_URL, filename, '_url.log')
    if HTTP_REFERER or HTTP_XRW or HTTP_BUNDLEID or HTTP_USER_IDENTITY or HTTP_Q_UA2 or HTTP_X_UMENG_SDK:
        write_dict_to_file(HTTP_SPECIAL_FIELDS, filename, '_special_fields.log')
    # HTTPS
    write_dict_to_file(TLS_SERVER_NAME, filename, '_ser_name.log')
    write_dict_to_file(TLS_CN, filename, '_cn.log')

    # QUIC
    if QUIC_SNI:
        write_dict_to_file(QUIC_SNI, filename, '_quic_sni.log')

    write_dict_to_file(DNS_QUERY, filename, '_dns_query.log')
    write_dict_bysort(TCP_PAYLOAD_HEAD, filename, '_tcp_flow_head.log')
    write_dict_bysort(TCP_PAYLOAD_TAIL, filename, '_tcp_flow_tail.log')
    write_dict_bysort(UDP_PAYLOAD_HEAD, filename, '_udp_flow_head.log')
    write_dict_bysort(UDP_PAYLOAD_TAIL, filename, '_udp_flow_tail.log')

    clear_temp_dict()  # 清空状态辅助字典



def parse_pcap(input_path: str, qtuiobj=None):
    # try:
    pcap_file = open(input_path, 'rb')
    # 读取文件的magic字段，读完之后将文件指针重置到0位置
    magic_head = pcap_file.read(4)
    # print(magic_head)
    pcap_file.seek(0, 0)
    if magic_head == b'\n\r\r\n':
        input_pcap = dpkt.pcapng.Reader(pcap_file)
    elif magic_head == b'\xd4\xc3\xb2\xa1':
        input_pcap = dpkt.pcap.Reader(pcap_file)
    elif magic_head == b'\xa1\xb2\xc3\xd4':
        input_pcap = dpkt.pcap.Reader(pcap_file)
    else:
        print('It is not a pcapng or pcap file.')
        exit(1)
    packet_count = 0
    global tcp_4tuple_dict
    global tcp_handshake_complete
    global tlsSNI_parsed_port_pair
    for _, buf in input_pcap:
        packet_count += 1
        # print(packet_count)
        eth = dpkt.ethernet.Ethernet(buf)
        if eth.type == 2048:  # eth.type==0x0800(十进制2048)指代上层为IP报头
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            # TCP
            if isinstance(ip.data, dpkt.tcp.TCP):
                parse_tcp(ip.data, src, dst)
            # UDP
            elif isinstance(ip.data, dpkt.udp.UDP):
                parse_udp(ip.data, src, dst)
            else:
                print("skip none tcp and udp packet.")
                continue
        elif eth.type == 34525:  # eth.type == 0x86DD(十进制34525)表示上层是IPv6
            pass

        # 非IPv4和IPv6，判断是否是PCAPDroid等工具抓取、没有二层报头的报文。
        else:
            try:
                ip = dpkt.ip.IP(buf)  # 尝试将buf解析为IP报文
                if isinstance(ip.data, dpkt.tcp.TCP):  # 如果为True则认为是没有二层报头、传输层为TCP的IP报文
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)
                    parse_tcp(ip.data, src, dst)
                elif isinstance(ip.data, dpkt.udp.UDP):
                    src = socket.inet_ntoa(ip.src)
                    dst = socket.inet_ntoa(ip.dst)
                    parse_udp(ip.data, src, dst)
                else:
                    print("skip none IP packet.")
            except dpkt.dpkt.UnpackError:  # ARP等二层报尝试解析为IP包时会抛出UnpackError，此时跳过该报文继续解析
                continue

        if packet_count % 5000 == 0:
            if qtuiobj:
                qtuiobj.refresh_number(packet_count)
            print(f'已解析分组数：{packet_count}')
    if qtuiobj:
        qtuiobj.refresh_number(packet_count)
        # 解析完pcap文件中的所有分组，将特征字典写入log文件（在有UI的情况下才在parse内部写文件，如果是调用parse函数就先不写，留待调用处在需要时调用write_parse_result函数）
    # print(tcp_4tuple_dict)

    #部分HTTP请求可能涉及上万个TCP包组装，抓包可能抓不到最后的HTTP组装包，导致最后http_caches字典内还有HTTP缓存，需要作为TCP流输出结果。
    process_incomplete_caches(tls_caches, http_caches)
    import os
    filename = os.path.splitext(input_path)[0]
    write_parse_result(filename)
    # except:
    #     pass
    # finally:
    pcap_file.close()


def parse_tcp(tcp: dpkt.tcp.TCP, src: str, dst: str):
    global SYN_ACK
    sport = tcp.sport
    dport = tcp.dport
    if not (sport, dport) in port_pair_c2s and not (dport, sport) in port_pair_c2s:
        port_pair_c2s[(sport, dport)] = True
    src2dst = (src, sport, dst, dport)
    src2dst_rvs = (dst, dport, src, sport)
    # 如果本包tcp负载大于0，则根据本包所属连接是否完成握手、是否已解析过采取不同处理
    if len(tcp.data) > 0:
        # 四元组已在字典中，表示已解析过一次。统计四元组包数量。
        if src2dst in tcp_4tuple_dict or src2dst_rvs in tcp_4tuple_dict:
            try:
                tcp_4tuple_dict[src2dst] += 1
            except KeyError:
                tcp_4tuple_dict[src2dst_rvs] += 1
            # '\x55\x04\x03'这三个字节通常在 ASN.1 编码的 X.509 证书中标记公共名称（common name）
            if (dport, sport) in tlsSNI_parsed_port_pair and b'\x16\x03' == tcp.data[:2] and b'\x55\x04\x03' in tcp.data:
                try:
                    parse_tls_cn(tcp.data, sport)
                except Exception as e:
                    print(e)
            # 解析TLS分片包
            elif (sport, dst, dport) in tls_caches:
                parse_tcp_application_layer(tcp, dst)
            # 解析HTTP分片包
            elif (sport, dst, dport) in http_caches:
                parse_tcp_application_layer(tcp, dst)
        # 四元组未在字典中，表示此流首次解析。若三次握手完成则解析。
        else:
            tcp_4tuple_dict[src2dst] = 1
            try:
                if tcp_handshake_complete[src2dst] >= 20 and SYN_ACK[src2dst]:
                    parse_tcp_application_layer(tcp, dst)
            except KeyError:
                try:
                    if tcp_handshake_complete[src2dst_rvs] >= 20 and SYN_ACK[src2dst_rvs]:
                        parse_tcp_application_layer(tcp, src)
                except KeyError:
                    print(f"May encouter uncaptured TCP handshake,info:{src}:{sport}->{dst}:{dport}.Skip.")

    # 如果本包tcp负载为0，则进行握手标志位判断
    else:
        if src2dst in tcp_handshake_complete or src2dst_rvs in tcp_handshake_complete:
            try:
                tcp_handshake_complete[src2dst] += tcp.flags
                if tcp.flags >= 18:
                    SYN_ACK[src2dst] = True
            except KeyError:
                tcp_handshake_complete[src2dst_rvs] += tcp.flags
                if tcp.flags >= 18:
                    SYN_ACK[src2dst_rvs] = True
        else:
            tcp_handshake_complete[src2dst] = tcp.flags


def parse_tcp_application_layer(tcp: dpkt.tcp.TCP, server_ipaddr: str):
    global tls_caches
    global http_caches
    sport = tcp.sport
    dport = tcp.dport
    if len(tcp.data) == 0:
        return
    # 通过判断tcp载荷内容确定是否是TLS或HTTP，通过异常处理跳转解析普通TCP
    if b'\x16\x03' == tcp.data[:2] or (sport, server_ipaddr, dport) in tls_caches:
        if (sport, server_ipaddr, dport) in tls_caches:
            maybe_tls = tls_caches.pop((sport, server_ipaddr, dport)) + tcp.data
        else:
            maybe_tls = tcp.data
        try:
            tls = dpkt.ssl.TLS(maybe_tls)
            parse_tls_server(tls, dport)
        except NeedData:  # 分片TLS
            tls_caches[(sport, server_ipaddr, dport)] = tcp.data
        except UnpackError:  # 非TLS
            record_tcp_payload(maybe_tls, server_ipaddr, sport, dport)
    else:  # 解析HTTP或普通TCP
        if (sport, server_ipaddr, dport) in http_caches:
            maybe_http = http_caches.pop((sport, server_ipaddr, dport)) + tcp.data
        else:
            maybe_http = tcp.data
        try:
            http_request = dpkt.http.Request(maybe_http)
            parse_http_request(http_request, dport)
        except NeedData:  # 分片HTTP
            http_caches[(sport, server_ipaddr, dport)] = maybe_http
        except UnpackError:  # 非HTTP
            record_tcp_payload(maybe_http, server_ipaddr, sport, dport)



def parse_http_request(http: dpkt.http.Request, dport: int):
    # dpkt.http.Request对象将HTTP请求的状态行（第一行）中method、uri、version单独作为成员变量，第二行开始的所有HTTP字段放入名为header的有序字典变量中。
    headers = http.headers
    headers['method'] = http.method
    headers['uri'] = http.uri
    # basic fields
    add_dict_kv(HTTP_HOST, headers['host']+f" [{str(dport)}]")
    add_dict_kv(HTTP_URL, headers['method'] + " " + headers['uri'] + f" [{str(dport)}]")
    if 'user-agent' in headers:
        if isinstance(headers['user-agent'], str):
            add_dict_kv(HTTP_UA, headers['user-agent']+f" [{str(dport)}]")
        elif isinstance(headers['user-agent'], list):
            for ua in headers['user-agent']:
                add_dict_kv(HTTP_UA, ua+f" [{str(dport)}]")
    # special fields (if exists)
    if 'referer' in headers:
        add_dict_kv(HTTP_REFERER, headers['referer']+f" [{str(dport)}]")
    if 'bundleid' in headers:
        add_dict_kv(HTTP_BUNDLEID, headers['bundleid']+f" [{str(dport)}]")
    if 'user-identity' in headers:
        add_dict_kv(HTTP_USER_IDENTITY, headers['user-identity']+f" [{str(dport)}]")
    if 'x-requested-with' in headers:
        add_dict_kv(HTTP_XRW, headers['x-requested-with']+f" [{str(dport)}]")
    if 'q-ua2' in headers:
        add_dict_kv(HTTP_Q_UA2, headers['q-ua2']+f" [{str(dport)}]")
    # print(f'HTTP request: {repr(http)}')


def parse_tls_server(tls: dpkt.ssl.TLS, dport: int):
    handshake = dpkt.ssl.TLSHandshake(tls.records[0].data)
    client_hello = handshake.data
    for ext in client_hello.extensions:
        if ext[0] == 0:  # 扩展字段类型值，0为server_name
            ser_name = ext[1][5:].decode()
            ser_name_ = ser_name + f' [{str(dport)}]'
            add_dict_kv(TLS_SERVER_NAME, ser_name_)


def parse_tls_cn(tcpdata: bytes, dport: int):
    import re
    # '\x55\x04\x03'这三个字节通常在 ASN.1 编码的 X.509 证书中标记公共名称（common name）
    cn_pos_list = [i.start() for i in re.finditer(b'\x55\x04\x03', tcpdata)]
    for pos in cn_pos_list:
        cn_len = tcpdata[pos + 4]  # common name length
        commonName = tcpdata[pos+5 : pos+5+cn_len].decode(encoding='utf-8', errors='ignore')
        if ' ' not in commonName:
            commonName = commonName + f' [{str(dport)}]'
            add_dict_kv(TLS_CN, commonName)



def process_incomplete_caches(tls_caches, http_caches):
    if tls_caches:
        for key,value in tls_caches.items():
            sport, dst, dport = key
            record_tcp_payload(value, dst, sport, dport)
    if http_caches:
        for key,value in http_caches.items():
            sport, dst, dport = key
            record_tcp_payload(value, dst, sport, dport)



def record_tcp_payload(tcpdata: bytes, server_ipaddr: str, sport, dport):
    global port_pair_c2s
    tcp_payload_head = str(tcpdata[:other_tcp_payload_len])
    tcp_payload_tail = str(tcpdata[-other_tcp_payload_len:])
    if (sport, dport) in port_pair_c2s:
        tcp_payload_head += f"    {str(sport)}->{server_ipaddr}:{str(dport)}"
        tcp_payload_tail += f"    {str(sport)}->{server_ipaddr}:{str(dport)}"
    else:
        tcp_payload_head += f"    {server_ipaddr}:{str(dport)}->{str(sport)}[reply]"
        tcp_payload_tail += f"    {server_ipaddr}:{str(dport)}->{str(sport)}[reply]"
    add_dict_kv(TCP_PAYLOAD_HEAD, tcp_payload_head)
    add_dict_kv(TCP_PAYLOAD_TAIL, tcp_payload_tail)


def parse_udp(udp: dpkt.udp.UDP, src: str, dst: str):
    if udp.dport == 53:
        try:
            parse_dns(udp)
        except:
            parse_udp_payload(udp, src, dst)
    elif udp.sport != 53 and (src, udp.sport, dst, udp.dport) not in udp_4tuple_dict and (dst, udp.dport, src, udp.sport) not in udp_4tuple_dict:
        parse_udp_payload(udp, src, dst)
        udp_4tuple_dict[(src, udp.sport, dst, udp.dport)] = True
        udp_4tuple_dict[(dst, udp.dport, src, udp.sport)] = True


def parse_udp_payload(udp: dpkt.udp.UDP, srcaddr: str, dstaddr: str):
    udp_payload_head = str(udp.data[:udp_payload_len]) + f"    {str(udp.sport)}->{dstaddr}:{str(udp.dport)}"
    add_dict_kv(UDP_PAYLOAD_HEAD, udp_payload_head)
    udp_payload_tail = str(udp.data[-udp_payload_len:]) + f"    {str(udp.sport)}->{dstaddr}:{str(udp.dport)}"
    add_dict_kv(UDP_PAYLOAD_TAIL, udp_payload_tail)


def parse_dns(udp: dpkt.udp.UDP):
    dns = dpkt.dns.DNS(udp.data)
    query = dns.qd[0].name
    add_dict_kv(DNS_QUERY, query)


if __name__ == "__main__":
    input_pcap_file = r'E:\pcap_collection\测速工具抓包\花瓣测速\petalspeed.pcapng'
    import time
    start = time.time()
    parse_pcap(input_pcap_file)
    print(start)
    print(time.time())