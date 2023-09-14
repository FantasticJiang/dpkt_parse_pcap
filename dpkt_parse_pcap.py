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
TLS_SERVER_NAME = {}
TLS_CN = {}
TCP_PAYLOAD = {}
UDP_PAYLOAD = {}
QUIC_SNI = {}
DNS_QUERY = {}
other_tcp_payload_len = 30
udp_payload_len = 20

# 状态判断辅助变量
tcp_4tuple_dict = {}  # 判断一条tcp流是否已解析过一次
tcp_handshake_complete = {}  # 判断tcp连接是否建立完成
tlsSNI_parsed_port_pair = {}  # 判断是否成功进入过TLS server_name解析流程，用于后续判断是否需要尝试解析common_name
port_pair_c2s = {}  # 判断包的流向
udp_4tuple_dict = {}  # 判断一条udp流是否已解析过一次



def clear_temp_dict():
    tcp_4tuple_dict.clear()
    tcp_handshake_complete.clear()
    tlsSNI_parsed_port_pair.clear()
    port_pair_c2s.clear()
    udp_4tuple_dict.clear()


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
    write_dict_bysort(TCP_PAYLOAD, filename, '_tcp_flow.log')
    write_dict_bysort(UDP_PAYLOAD, filename, '_udp_flow.log')

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
        print(packet_count)
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
                    parse_tcp(ip.data, src, dst)
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
        import os
        filename = os.path.splitext(input_path)[0]
        write_parse_result(filename)
    # except:
    #     pass
    # finally:
    pcap_file.close()


def parse_tcp(tcp: dpkt.tcp.TCP, src: str, dst: str):
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
            if (dport, sport) in tlsSNI_parsed_port_pair and b'\x16\x03' == tcp.data[:2] and b'\x55\x04\x03' in tcp.data:
                try:
                    parse_tls_cn(tcp.data, sport)
                except Exception as e:
                    print(e)
        # 四元组未在字典中，表示此流首次解析。若三次握手完成则解析。
        else:
            tcp_4tuple_dict[src2dst] = 1
            try:
                if tcp_handshake_complete[src2dst] >= 3:
                    parse_tcp_application_layer(tcp)
            except KeyError:
                try:
                    if tcp_handshake_complete[src2dst_rvs] >= 3:
                        parse_tcp_application_layer(tcp)
                except KeyError:
                    print("May encouter uncaptured TCP handshake.Skip")

    # 如果本包tcp负载为0，则进行握手标志位判断
    else:
        if src2dst in tcp_handshake_complete or src2dst_rvs in tcp_handshake_complete:
            try:
                tcp_handshake_complete[src2dst] += 1
            except KeyError:
                tcp_handshake_complete[src2dst_rvs] += 1
        else:
            tcp_handshake_complete[src2dst] = 1


def parse_tcp_application_layer(tcp: dpkt.tcp.TCP):
    if len(tcp.data) == 0:
        return
    # dpkt似乎没有方法可以在读到一个packet时得知其具有的应用层协议还是仅tcp协议，必须从下往上层层剥离。
    # 解析HTTP/HTTPS目前想到的两种方式可能只能是：
    # （1）判断tcp.data是否含有HTTP/HTTPS特有的内容；
    # （2）异常处理，先将tcp.data直接当成HTTP解析，抛出异常时当成HTTPS解析，还抛出异常则当无应用层的TCP协议解析。
    try:
        request = dpkt.http.Request(tcp.data)
        parse_http_request(request, tcp.dport)
    except dpkt.dpkt.UnpackError:  # 若尝试解析HTTP引发UnpackError，改为尝试解析TLS server_name
        try:
            global tlsSNI_parsed_port_pair
            tls = dpkt.ssl.TLS(tcp.data)
            parse_tls_server(tls, tcp.dport)
            tlsSNI_parsed_port_pair[(tcp.sport, tcp.dport)] = 1
        except:  # 若尝试解析TLS仍引发异常，则按普通TCP Payload解析
            tcp_payload = str(tcp.data[:other_tcp_payload_len])
            if (tcp.sport, tcp.dport) in port_pair_c2s:
                tcp_payload += f"    {str(tcp.sport)}:{str(tcp.dport)}"
            else:
                tcp_payload += f"    {str(tcp.dport)}:{str(tcp.sport)}[reply]"
            add_dict_kv(TCP_PAYLOAD, tcp_payload)


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


def parse_udp(udp: dpkt.udp.UDP, src: str, dst: str):
    if (udp.sport, udp.dport) not in udp_4tuple_dict and (udp.dport, udp.sport) not in udp_4tuple_dict:
        if udp.dport == 53:
            try:
                parse_dns(udp)
            except:
                parse_udp_payload(udp)
        else:
            parse_udp_payload(udp)
        udp_4tuple_dict[(udp.sport, udp.dport)] = True
        udp_4tuple_dict[(udp.dport, udp.sport)] = True


def parse_udp_payload(udp: dpkt.udp.UDP):
    udp_payload = str(udp.data[:udp_payload_len]) + f"    {str(udp.sport)}:{str(udp.dport)}"
    add_dict_kv(UDP_PAYLOAD, udp_payload)


def parse_dns(udp: dpkt.udp.UDP):
    dns = dpkt.dns.DNS(udp.data)
    query = dns.qd[0].name
    add_dict_kv(DNS_QUERY, query)


if __name__ == "__main__":
    input_pcap_file = r'E:\pcap_collection\网易游戏抓包\梦幻西游手游\hw2.pcap'
    import time
    start = time.time()
    parse_pcap(input_pcap_file)
    print(start)
    print(time.time())