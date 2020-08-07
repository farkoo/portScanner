import argparse
import socket
import sys
from struct import *
import binascii
import portList
import time


sstarget = ""
target = 0
begin_port = 0
end_port = 0
delay = 0
mode = 0


class Packet:
    def __init__(self, src_ip, dest_ip, dest_port, _mode):

        # IP segment
        self.version = 0x4
        self.ihl = 0x5
        self.type_of_service = 0x0
        self.total_length = 0x28
        self.identification = 0xabcd
        self.flags = 0x0
        self.fragment_offset = 0x0
        self.ttl = 0x40
        self.protocol = 0x6
        self.header_checksum = 0x0
        self.src_ip = src_ip
        self.dest_ip = dest_ip
        self.src_addr = socket.inet_aton(src_ip)
        self.dest_addr = socket.inet_aton(dest_ip)
        self.v_ihl = (self.version << 4) + self.ihl
        self.f_fo = (self.flags << 13) + self.fragment_offset

        # TCP segment
        self.src_port = 0x3039
        self.dest_port = dest_port
        self.seq_no = 0x0
        self.ack_no = 0x0
        self.data_offset = 0x5
        self.reserved = 0x0
        self.ns, self.cwr, self.ece, self.urg, self.ack, self.psh, self.rst, self.syn, self.fin = 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0, 0x0
        self.window_size = 0x7110
        self.checksum = 0x0
        self.urg_pointer = 0x0
        self.data_offset_res_flags = (self.data_offset << 12) + (self.reserved << 9) + (self.ns << 8) + (
                self.cwr << 7) + (self.ece << 6) + (self.urg << 5) + (self.ack << 4) + (self.psh << 3) + (
                                             self.rst << 2) + (self.syn << 1) + self.fin
        if _mode == 1 or _mode == 2:
            self.syn = 0x1
        elif _mode == 3 or _mode == 5:
            self.ack = 0x1
        elif _mode == 4:
            self.fin = 0x1

        # packet
        self.tcp_header = b""
        self.ip_header = b""
        self.packet = b""

    def calc_checksum(self, msg):
        s = 0
        for i in range(0, len(msg), 2):
            w = (msg[i] << 8) + msg[i + 1]
            s = s + w
        # s = 0x119cc
        s = (s >> 16) + (s & 0xffff)
        # s = 0x19cd
        s = ~s & 0xffff
        # s = 0xe632
        return s

    def generate_tmp_ip_header(self):
        tmp_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                             self.identification, self.f_fo,
                             self.ttl, self.protocol, self.header_checksum,
                             self.src_addr,
                             self.dest_addr)
        return tmp_ip_header

    def generate_tmp_tcp_header(self):
        tmp_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                              self.seq_no,
                              self.ack_no,
                              self.data_offset_res_flags, self.window_size,
                              self.checksum, self.urg_pointer)
        return tmp_tcp_header

    def generate_packet(self):
        # IP header + checksum
        final_ip_header = pack("!BBHHHBBH4s4s", self.v_ihl, self.type_of_service, self.total_length,
                               self.identification, self.f_fo,
                               self.ttl, self.protocol, self.calc_checksum(self.generate_tmp_ip_header()),
                               self.src_addr,
                               self.dest_addr)
        # TCP header + checksum
        tmp_tcp_header = self.generate_tmp_tcp_header()
        pseudo_header = pack("!4s4sBBH", self.src_addr, self.dest_addr, self.checksum, self.protocol,
                             len(tmp_tcp_header))
        psh = pseudo_header + tmp_tcp_header
        final_tcp_header = pack("!HHLLHHHH", self.src_port, self.dest_port,
                                self.seq_no,
                                self.ack_no,
                                self.data_offset_res_flags, self.window_size,
                                self.calc_checksum(psh), self.urg_pointer)

        self.ip_header = final_ip_header
        self.tcp_header = final_tcp_header
        self.packet = final_ip_header + final_tcp_header

    def send_packet(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
        s.sendto(self.packet, (self.dest_ip, 0))
        data = s.recv(1024)
        s.close()
        return data


class PortScanning:
    def __init__(self, _port, _response):
        self.port = _port
        self.response = _response

    def connect_scan(self):
        cont = binascii.hexlify(self.response)
        # s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        # try:
        #     s.connect((target, _port))
        #     print(_port, "/tcp\t\t" + "open\t", strport)
        #     s.close()
        # except:
        #     print(_port, "/tcp\t\t", "closed\t", strport)

        if len(str(type(self.response))) == 0:
            flag = 2
        if cont[66:68] == b"12" or cont[66:68] == b"10" or cont[66:68] == b"18" or cont[66:68] == b"19":
            flag = 1
        elif cont[66:68] == b"14":
            flag = 2
        else:
            flag = 6
        self.printResult(flag)
        return

    def syn_scan(self):
        cont = binascii.hexlify(self.response)
        if len(str(type(self.response))) == 0:
            flag = 3
        elif cont[18:20] == b"01" and cont[40:42] == b"03" and (cont[42:44] == b"01" or cont[42:44] == b"02" or cont[42:44] == b"03" or cont[42:44] == b"09" or cont[42:44] == b"10" or cont[42:44] == b"13"):
            flag = 3
        if cont[66:68] == b"12" or cont[66:68] == b"10" or cont[66:68] == b"18" or cont[66:68] == b"19":
            flag = 1
        elif cont[66:68] == b"14":
            flag = 2
        else:
            flag = 6
        self.printResult(flag)
        return

    def ack_scan(self):
        cont = binascii.hexlify(self.response)
        if len(str(type(self.response))) == 0:
            flag = 3
        elif cont[18:20] == b"01" and cont[40:42] == b"03" and (cont[42:44] == b"01" or cont[42:44] == b"02" or cont[42:44] == b"03" or cont[42:44] == b"09" or cont[42:44] == b"10" or cont[42:44] == b"13"):
            flag = 3
        elif cont[66:68] == b"04" or cont[66:68] == b"14" or cont[66:68] == b"12" or cont[66:68] == b"18" or (cont[66:68] == b"10"):
            flag = 4
        else:
            flag = 6
        self.printResult(flag)
        return

    def fin_scan(self):
        cont = binascii.hexlify(self.response)
        if len(str(type(self.response))) == 0 or cont[66:68] == b"12" or cont[66:68] == b"18" or (cont[66:68] == b"10"):
            flag = 5
        elif cont[18:20] == b"01" and cont[40:42] == b"03" and (cont[42:44] == b"01" or cont[42:44] == b"02" or cont[42:44] == b"03" or cont[42:44] == b"09" or cont[42:44] == b"10" or cont[42:44] == b"13"):
            flag = 3
        elif cont[66:68] == b"14":
            flag = 2
        else:
            flag = 6
        self.printResult(flag)
        return

    def window_scan(self):
        cont = binascii.hexlify(self.response)
        if len(str(type(self.response))) == 0:
            flag = 3
        elif cont[18:20] == b"01" and cont[40:42] == b"03" and (cont[42:44] == b"01" or cont[42:44] == b"02" or cont[42:44] == b"03" or cont[42:44] == b"09" or cont[42:44] == b"10" or cont[42:44] == b"13"):
            flag = 3
        elif cont[66:68] == b"14" and cont[68:72] != b"0000":
            flag = 1
        elif (cont[66:68] == b"14" and cont[68:72] == b"0000") or (cont[66:68] == b"12") or (cont[66:68] == b"18") or (cont[66:68] == b"10"):
            flag = 2
        else:
            flag = 6
        self.printResult(flag)
        return

    def printResult(self, flag):
        if str(self.port) in portList.services:
            strport = (portList.services[str(self.port)])
        else:
            strport = "unknow"
        if flag == 1:   # port is open
            print(self.port, "/tcp\t\t", "open\t", strport)
        if flag == 2:   # port is closed
            print(self.port, "/tcp\t\t", "closed\t", strport)
        if flag == 3:   # port is filtered
            print(self.port, "/tcp\t\t", "filtered\t", strport)
        if flag == 4:   # port is unfiltered
            print(self.port, "/tcp\t\t", "unfiltered\t", strport)
        if flag == 5:   # port is open|filtered
            print(self.port, "/tcp\t\t", "open|filtered\t", strport)
        if flag == 6:   # check required
            print(self.port, "/tcp\t\t", "CHECK\t", strport)


def listToString(s):
    str1 = ""
    for ele in s:
        str1 += ele
    return str1


def FQDNtoIP(s):
    global sstarget
    if s.count('.') > 0:
        sstarget = socket.gethostbyname(s)
    else:
        sstarget = s
    return sstarget


def prepare_parameters():
    global target, mode, delay, begin_port, end_port
    parser = argparse.ArgumentParser(prog='port_scanner')
    parser.add_argument('--version', action='version', version='%(prog)s 1.0')
    parser.add_argument('-t', '--target', required=True, help='Target host')
    parser.add_argument('-p', '--ports', nargs=1, required=True, help='Port interval to scan')
    parser.add_argument('-m', '--mode', nargs=1, required=True,
                        help='scan mode: CS(Connect() Scan), SS(SYN Scan), AS(ACK Scan), FS(FIN Scan), WS(Window Scan) ')
    parser.add_argument('-d', '--delay', nargs=1, required=True, help='Adjust delay between probes')
    args = parser.parse_args()

    A = args.ports
    A = listToString(A)
    B = [int(x) for x in A.split('-') if x.strip()]

    try:
        beginPort = B[0]
        endPort = B[1]
        assert 0 < beginPort <= endPort and endPort > 0
    except AssertionError:
        print("[ERROR] Port range is invalid - startPort must be <= endPort, both of which > 0")
        sys.exit()

    target = args.target
    target = FQDNtoIP(target)
    begin_port = B[0]
    end_port = B[1]
    if args.mode[0] == "CS":
        mode = 1
    elif args.mode[0] == "SS":
        mode = 2
    elif args.mode[0] == "AS":
        mode = 3
    elif args.mode[0] == "FS":
        mode = 4
    elif args.mode[0] == "WS":
        mode = 5
    delay = args.delay[0]

    strdelay = ""
    for i in range(len(delay)):
        if delay[i] == 's':
            break
        else:
            strdelay += delay[i]
    delay = strdelay


def startScanning():
    prepare_parameters()
    print("Starting FARKOO-Nmap ...")
    print("Nmap scan report for: ", target)
    print("PORT\t\tSTATE\tSERVICE")
    for port in range(begin_port, end_port + 1):
        srcIp = "127.0.0.1"
        dstIp = str(target)
        p = Packet(srcIp, dstIp, port, mode)
        p.generate_packet()
        result = p.send_packet()
        ps = PortScanning(port, result)
        if mode == 1:
            ps.connect_scan()
        elif mode == 2:
            ps.syn_scan()
        elif mode == 3:
            ps.ack_scan()
        elif mode == 4:
            ps.fin_scan()
        elif mode == 5:
            ps.window_scan()
        time.sleep(int(delay))
    print("Nmap done ^ ^.")


startScanning()
