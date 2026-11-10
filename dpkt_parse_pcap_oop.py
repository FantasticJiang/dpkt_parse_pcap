import socket
import dpkt
from dpkt import UnpackError, NeedData
from utils import *

class PcapParser:
    def __init__(self):
        # 协议特征字段
        self.HTTP_HEADER = {}
        self.HTTP_HOST = {}
        self.HTTP_UA = {}
        self.HTTP_URL = {}
        self.HTTP_REFERER = {}
        self.HTTP_XRW = {}
        self.HTTP_BUNDLEID = {}
        self.HTTP_USER_IDENTITY = {}
        self.HTTP_Q_UA2 = {}
        self.HTTP_X_UMENG_SDK = {}
        self.HTTP_SPECIAL_FIELDS = [self.HTTP_REFERER, self.HTTP_XRW, self.HTTP_BUNDLEID, self.HTTP_USER_IDENTITY, self.HTTP_Q_UA2, self.HTTP_X_UMENG_SDK]
        self.TLS_SERVER_NAME = {}
        self.TLS_CN = {}
        self.TCP_PAYLOAD_HEAD = {}
        self.TCP_PAYLOAD_TAIL = {}
        self.UDP_PAYLOAD_HEAD = {}
        self.UDP_PAYLOAD_TAIL = {}
        self.QUIC_SNI = {}
        self.DNS_QUERY = {}
        self.other_tcp_payload_len = 30
        self.udp_payload_len = 20

        self.tls_caches = {}
        self.http_caches = {}
        self.tcp_4tuple_dict = {}
        self.tcp_handshake_complete = {}
        self.tlsSNI_parsed_port_pair = {}
        self.port_pair_c2s = {}
        self.udp_4tuple_dict = {}
        self.SYN_ACK = {}

    def clear_temp_dict(self):
        self.tcp_4tuple_dict.clear()
        self.tcp_handshake_complete.clear()
        self.tlsSNI_parsed_port_pair.clear()
        self.port_pair_c2s.clear()
        self.udp_4tuple_dict.clear()
        self.tls_caches.clear()
        self.http_caches.clear()

    def write_parse_result(self, filename: str):
        write_dict_to_file(self.HTTP_HOST, filename, '_host.log')
        write_dict_to_file(self.HTTP_UA, filename, '_ua.log')
        write_dict_to_file(self.HTTP_URL, filename, '_url.log')
        if self.HTTP_REFERER or self.HTTP_XRW or self.HTTP_BUNDLEID or self.HTTP_USER_IDENTITY or self.HTTP_Q_UA2 or self.HTTP_X_UMENG_SDK:
            write_dict_to_file(self.HTTP_SPECIAL_FIELDS, filename, '_special_fields.log')
        write_dict_to_file(self.TLS_SERVER_NAME, filename, '_ser_name.log')
        write_dict_to_file(self.TLS_CN, filename, '_cn.log')
        if self.QUIC_SNI:
            write_dict_to_file(self.QUIC_SNI, filename, '_quic_sni.log')
        write_dict_to_file(self.DNS_QUERY, filename, '_dns_query.log')
        write_dict_bysort(self.TCP_PAYLOAD_HEAD, filename, '_tcp_flow_head.log')
        write_dict_bysort(self.TCP_PAYLOAD_TAIL, filename, '_tcp_flow_tail.log')
        write_dict_bysort(self.UDP_PAYLOAD_HEAD, filename, '_udp_flow_head.log')
        write_dict_bysort(self.UDP_PAYLOAD_TAIL, filename, '_udp_flow_tail.log')
        self.clear_temp_dict()

    def parse_pcap(self, input_path: str, qtuiobj=None):
        pcap_file = open(input_path, 'rb')
        magic_head = pcap_file.read(4)
        pcap_file.seek(0, 0)
        if magic_head == b'\n\r\r\n':
            input_pcap = dpkt.pcapng.Reader(pcap_file)
        elif magic_head == b'\xd4\xc3\xb2\xa1' or magic_head == b'\xa1\xb2\xc3\xd4':
            input_pcap = dpkt.pcap.Reader(pcap_file)
        else:
            print('It is not a pcapng or pcap file.')
            pcap_file.close()
            return
        packet_count = 0
        for _, buf in input_pcap:
            packet_count += 1
            try:
                eth = dpkt.ethernet.Ethernet(buf)
                self.parse_ethernet(eth, buf)
            except Exception as e:
                print(f"[Error] 解析以太网帧失败: {e}")
                continue
            if packet_count % 5000 == 0:
                if qtuiobj:
                    qtuiobj.refresh_number(packet_count)
                print(f'已解析分组数：{packet_count}')
        if qtuiobj:
            qtuiobj.refresh_number(packet_count)
        self.process_incomplete_caches()
        import os
        filename = os.path.splitext(input_path)[0]
        self.write_parse_result(filename)
        pcap_file.close()

    def parse_ethernet(self, eth, buf):
        if eth.type == dpkt.ethernet.ETH_TYPE_IP:  # IPv4
            ip = eth.data
            src = socket.inet_ntoa(ip.src)
            dst = socket.inet_ntoa(ip.dst)
            self.parse_ip_packet(ip, src, dst)
        elif eth.type == dpkt.ethernet.ETH_TYPE_IP6:  # IPv6
            ip6 = eth.data
            src = socket.inet_ntop(socket.AF_INET6, ip6.src)
            dst = socket.inet_ntop(socket.AF_INET6, ip6.dst)
            self.parse_ip_packet(ip6, src, dst)
        elif eth.type == 0x8100:  # VLAN
            vlan = eth.data
            if isinstance(vlan, dpkt.ip.IP):  # IPv4
                ip = vlan
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                self.parse_ip_packet(ip, src, dst)
            elif isinstance(vlan, dpkt.ip6.IP6):  # IPv6
                ip6 = vlan
                src = socket.inet_ntop(socket.AF_INET6, ip6.src)
                dst = socket.inet_ntop(socket.AF_INET6, ip6.dst)
                self.parse_ip_packet(ip6, src, dst)
            elif hasattr(vlan, 'type') and vlan.type == 0x8100:  # 嵌套VLAN
                try:
                    inner_eth = dpkt.ethernet.Ethernet(bytes(vlan))
                    self.parse_ethernet(inner_eth, bytes(vlan))
                except Exception as e:
                    print(f"[Error] 解析嵌套VLAN帧失败: {e}")
            else:
                print(f"[Warning] 未知VLAN类型，跳过。")
        else:
            # 处理没有二层报头的情况
            try:
                ip = dpkt.ip.IP(buf)
                src = socket.inet_ntoa(ip.src)
                dst = socket.inet_ntoa(ip.dst)
                self.parse_ip_packet(ip, src, dst)
            except dpkt.dpkt.UnpackError:
                pass

    def parse_ip_packet(self, ip, src, dst):
        if isinstance(ip.data, dpkt.tcp.TCP):
            self.parse_tcp(ip.data, src, dst)
        elif isinstance(ip.data, dpkt.udp.UDP):
            self.parse_udp(ip.data, src, dst)
        else:
            print("skip none tcp and udp packet.")

    def parse_tcp(self, tcp: dpkt.tcp.TCP, src: str, dst: str):
        sport = tcp.sport
        dport = tcp.dport
        if not (sport, dport) in self.port_pair_c2s and not (dport, sport) in self.port_pair_c2s:
            self.port_pair_c2s[(sport, dport)] = True
        src2dst = (src, sport, dst, dport)
        src2dst_rvs = (dst, dport, src, sport)
        if len(tcp.data) > 0:
            if src2dst in self.tcp_4tuple_dict or src2dst_rvs in self.tcp_4tuple_dict:
                try:
                    self.tcp_4tuple_dict[src2dst] += 1
                except KeyError:
                    self.tcp_4tuple_dict[src2dst_rvs] += 1
                if (dport, sport) in self.tlsSNI_parsed_port_pair and b'\x16\x03' == tcp.data[:2] and b'\x55\x04\x03' in tcp.data:
                    try:
                        self.parse_tls_cn(tcp.data, sport)
                    except Exception as e:
                        print(e)
                elif (sport, dst, dport) in self.tls_caches:
                    self.parse_tcp_application_layer(tcp, dst)
                elif (sport, dst, dport) in self.http_caches:
                    self.parse_tcp_application_layer(tcp, dst)
            else:
                self.tcp_4tuple_dict[src2dst] = 1
                try:
                    if self.tcp_handshake_complete[src2dst] >= 20 and self.SYN_ACK[src2dst]:
                        self.parse_tcp_application_layer(tcp, dst)
                except KeyError:
                    try:
                        if self.tcp_handshake_complete[src2dst_rvs] >= 20 and self.SYN_ACK[src2dst_rvs]:
                            self.parse_tcp_application_layer(tcp, src)
                    except KeyError:
                        print(f"May encouter uncaptured TCP handshake,info:{src}:{sport}->{dst}:{dport}.Skip.")
        else:
            if src2dst in self.tcp_handshake_complete or src2dst_rvs in self.tcp_handshake_complete:
                try:
                    self.tcp_handshake_complete[src2dst] += tcp.flags
                    if tcp.flags >= 18:
                        self.SYN_ACK[src2dst] = True
                except KeyError:
                    self.tcp_handshake_complete[src2dst_rvs] += tcp.flags
                    if tcp.flags >= 18:
                        self.SYN_ACK[src2dst_rvs] = True
            else:
                self.tcp_handshake_complete[src2dst] = tcp.flags

    def parse_tcp_application_layer(self, tcp: dpkt.tcp.TCP, server_ipaddr: str):
        sport = tcp.sport
        dport = tcp.dport
        if len(tcp.data) == 0:
            return
        if b'\x16\x03' == tcp.data[:2] or (sport, server_ipaddr, dport) in self.tls_caches:
            if (sport, server_ipaddr, dport) in self.tls_caches:
                maybe_tls = self.tls_caches.pop((sport, server_ipaddr, dport)) + tcp.data
            else:
                maybe_tls = tcp.data
            try:
                tls = dpkt.ssl.TLS(maybe_tls)
                self.parse_tls_server(tls, dport)
            except NeedData:
                self.tls_caches[(sport, server_ipaddr, dport)] = tcp.data
            except UnpackError:
                self.record_tcp_payload(maybe_tls, server_ipaddr, sport, dport)
        else:
            if (sport, server_ipaddr, dport) in self.http_caches:
                maybe_http = self.http_caches.pop((sport, server_ipaddr, dport)) + tcp.data
            else:
                maybe_http = tcp.data
            try:
                http_request = dpkt.http.Request(maybe_http)
                self.parse_http_request(http_request, dport)
            except NeedData:
                self.http_caches[(sport, server_ipaddr, dport)] = maybe_http
            except UnpackError:
                self.record_tcp_payload(maybe_http, server_ipaddr, sport, dport)

    def parse_http_request(self, http: dpkt.http.Request, dport: int):
        headers = http.headers
        headers['method'] = http.method
        headers['uri'] = http.uri
        add_dict_kv(self.HTTP_HOST, headers['host']+f" [{str(dport)}]")
        add_dict_kv(self.HTTP_URL, headers['method'] + " " + headers['uri'] + f" [{str(dport)}]")
        if 'user-agent' in headers:
            if isinstance(headers['user-agent'], str):
                add_dict_kv(self.HTTP_UA, headers['user-agent']+f" [{str(dport)}]")
            elif isinstance(headers['user-agent'], list):
                for ua in headers['user-agent']:
                    add_dict_kv(self.HTTP_UA, ua+f" [{str(dport)}]")
        if 'referer' in headers:
            add_dict_kv(self.HTTP_REFERER, headers['referer']+f" [{str(dport)}]")
        if 'bundleid' in headers:
            add_dict_kv(self.HTTP_BUNDLEID, headers['bundleid']+f" [{str(dport)}]")
        if 'user-identity' in headers:
            add_dict_kv(self.HTTP_USER_IDENTITY, headers['user-identity']+f" [{str(dport)}]")
        if 'x-requested-with' in headers:
            add_dict_kv(self.HTTP_XRW, headers['x-requested-with']+f" [{str(dport)}]")
        if 'q-ua2' in headers:
            add_dict_kv(self.HTTP_Q_UA2, headers['q-ua2']+f" [{str(dport)}]")

    def parse_tls_server(self, tls: dpkt.ssl.TLS, dport: int):
        handshake = dpkt.ssl.TLSHandshake(tls.records[0].data)
        client_hello = handshake.data
        for ext in client_hello.extensions:
            if ext[0] == 0:
                ser_name = ext[1][5:].decode()
                ser_name_ = ser_name + f' [{str(dport)}]'
                add_dict_kv(self.TLS_SERVER_NAME, ser_name_)

    def parse_tls_cn(self, tcpdata: bytes, dport: int):
        import re
        cn_pos_list = [i.start() for i in re.finditer(b'\x55\x04\x03', tcpdata)]
        for pos in cn_pos_list:
            cn_len = tcpdata[pos + 4]
            commonName = tcpdata[pos+5 : pos+5+cn_len].decode(encoding='utf-8', errors='ignore')
            if ' ' not in commonName:
                commonName = commonName + f' [{str(dport)}]'
                add_dict_kv(self.TLS_CN, commonName)

    def process_incomplete_caches(self):
        if self.tls_caches:
            for key,value in self.tls_caches.items():
                sport, dst, dport = key
                self.record_tcp_payload(value, dst, sport, dport)
        if self.http_caches:
            for key,value in self.http_caches.items():
                sport, dst, dport = key
                self.record_tcp_payload(value, dst, sport, dport)

    def record_tcp_payload(self, tcpdata: bytes, server_ipaddr: str, sport, dport):
        tcp_payload_head = str(tcpdata[:self.other_tcp_payload_len])
        tcp_payload_tail = str(tcpdata[-self.other_tcp_payload_len:])
        if (sport, dport) in self.port_pair_c2s:
            tcp_payload_head += f"    {str(sport)}->{server_ipaddr}:{str(dport)}"
            tcp_payload_tail += f"    {str(sport)}->{server_ipaddr}:{str(dport)}"
        else:
            tcp_payload_head += f"    {server_ipaddr}:{str(dport)}->{str(sport)}[reply]"
            tcp_payload_tail += f"    {server_ipaddr}:{str(dport)}->{str(sport)}[reply]"
        add_dict_kv(self.TCP_PAYLOAD_HEAD, tcp_payload_head)
        add_dict_kv(self.TCP_PAYLOAD_TAIL, tcp_payload_tail)

    def parse_udp(self, udp: dpkt.udp.UDP, src: str, dst: str):
        if udp.dport == 53:
            try:
                self.parse_dns(udp)
            except Exception:
                self.parse_udp_payload(udp, src, dst)
        elif udp.sport != 53 and (src, udp.sport, dst, udp.dport) not in self.udp_4tuple_dict and (dst, udp.dport, src, udp.sport) not in self.udp_4tuple_dict:
            self.parse_udp_payload(udp, src, dst)
            self.udp_4tuple_dict[(src, udp.sport, dst, udp.dport)] = True
            self.udp_4tuple_dict[(dst, udp.dport, src, udp.sport)] = True

    def parse_udp_payload(self, udp: dpkt.udp.UDP, srcaddr: str, dstaddr: str):
        udp_payload_head = str(udp.data[:self.udp_payload_len]) + f"    {str(udp.sport)}->{dstaddr}:{str(udp.dport)}"
        add_dict_kv(self.UDP_PAYLOAD_HEAD, udp_payload_head)
        udp_payload_tail = str(udp.data[-self.udp_payload_len:]) + f"    {str(udp.sport)}->{dstaddr}:{str(udp.dport)}"
        add_dict_kv(self.UDP_PAYLOAD_TAIL, udp_payload_tail)

    def parse_dns(self, udp: dpkt.udp.UDP):
        dns = dpkt.dns.DNS(udp.data)
        query = dns.qd[0].name
        add_dict_kv(self.DNS_QUERY, query)

if __name__ == "__main__":
    input_pcap_file = r'E:\pcap_collection\！样本包（技术、协议等等）\802.1QVLAN\sample1.pcapng'
    import time
    start = time.time()
    parser = PcapParser()
    parser.parse_pcap(input_pcap_file)
    print(start)
    print(time.time())