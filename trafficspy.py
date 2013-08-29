#!/usr/bin/env python
# -*- encoding:utf-8 -*-

import pcap
import sys
import string
import socket
import struct
import fcntl
import os
import pwd
import curses

# === classes ===

class Packet(object):
    def __init__(self, src_ip, dst_ip, src_port, dst_port, pktlen, timestamp):
        self.src_ip = src_ip
        self.dst_ip = dst_ip
        self.src_port = src_port
        self.dst_port = dst_port
        self.pktlen = pktlen
        self.timestamp = timestamp

    @property   
    def is_outgoing(self):
        global local_ip
        return self.src_ip == local_ip

    @property
    def hash_str(self):
        return ''.join((self.src_ip, ':', str(self.src_port), '-', self.dst_ip, ':', str(self.dst_port)))

    def __eq__(self, other):
        return (self.src_ip == other.src_ip) \
        and (self.dst_ip == other.dst_ip) \
        and (self.src_port == other.src_port) \
        and (self.dst_port == other.dst_port)

    def __str__(self):
        return self.src_ip + ':' + str(self.src_port)  + ' > ' + self.dst_ip + ':' + str(self.dst_port)


class Connection(object):
    def __init__(self, packet):
        self.total_sent = 0
        self.total_recv = 0
        self.sent_pktlist = []
        self.recv_pktlist = []
        
        if packet.is_outgoing:
            self.total_sent += packet.pktlen
            self.sent_pktlist.append(packet)
            self.last_pkt_timestamp = packet.timestamp
            self.refpkt = packet
        else:
            self.total_recv += packet.pktlen
            self.recv_pktlist.append(packet)
            self.last_pkt_timestamp = packet.timestamp
            self.refpkt = Packet(packet.dst_ip, packet.src_ip, 
                packet.dst_port, packet.src_port, 
                packet.pktlen, packet.timestamp)
            del packet

    def add_pkt_2_connection(self, packet):
        self.last_pkt_timestamp = packet.timestamp
        if packet.is_outgoing:
            self.total_sent += packet.pktlen
            self.sent_pktlist.append(packet)
        else:
            self.total_recv += packet.pktlen
            self.recv_pktlist.append(packet)

    def __str__(self):
        return str(self.refpkt)


class Process(object):
    def __init__(self, inode, name, pid=0, uid=0):
        self.inode = inode
        self.name = name
        self.pid = pid
        self.uid = uid
        self.connlist = []

    def add_connection_2_process(self, conn):
        if all(i.refpkt != conn.refpkt for i in self.connlist):
            self.connlist.append(conn)

    @property
    def user(self):
        return pwd.getpwuid(self.uid).pw_name

    @property
    def last_pkt(self):
        if len(self.connlist) != 0:
            return max(conn.last_pkt_timestamp for conn in self.connlist)
        else:
            return 0 

    def __str__(self):
        return self.name

'''
protocols = {socket.IPPROTO_TCP:'tcp',
    socket.IPPROTO_UDP:'udp',
    socket.IPPROTO_ICMP:'icmp'}
'''

def get_local_ipaddr(ifname):
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    return socket.inet_ntoa(fcntl.ioctl(s.fileno(), 
        0x8915, struct.pack('256s', ifname[:15]))[20:24])

def decode_ip_packet(s):
    '''
    Decoding ip packets. Accroding to the IP frame format,
    we can decode every field of the packet. 
    NOTE: We also decode the source port and destination port 
    here for convenience, since they are layer 4 elements
    '''
    d = {}
    d['version'] = (ord(s[0]) & 0xf0) >> 4
    d['header_len'] = ord(s[0]) & 0x0f
    d['tos'] = ord(s[1])
    d['total_len'] = socket.ntohs(struct.unpack('H', s[2:4])[0])
    d['id'] = socket.ntohs(struct.unpack('H', s[4:6])[0])
    d['flags'] = (ord(s[6]) & 0xe0)>>5
    d['fragment_offset'] = socket.ntohs(struct.unpack('H',s[6:8])[0] & 0x1f)
    d['ttl'] = ord(s[8])
    d['protocol'] = ord(s[9])
    d['checksum'] = socket.ntohs(struct.unpack('H',s[10:12])[0])
    d['source_address'] = pcap.ntoa(struct.unpack('L', s[12:16])[0])
    d['destination_address'] = pcap.ntoa(struct.unpack('L', s[16:20])[0])

    if d['header_len'] > 5:   # headr length
        d['options'] = s[20:4*(d['header_len'] - 5)]
    else:
        d['options']=None
    d['data'] = s[4*d['header_len']:]
    d['source_port'] = socket.ntohs(struct.unpack('H', d['data'][0:2])[0])
    d['destination_port'] = socket.ntohs(struct.unpack('H', d['data'][2:4])[0])
    return d

def dumphex(s):
    bytes = map(lambda x:'%.2x'%x, map(ord, s))
    for i in xrange(0, len(bytes)/16):
        print '   %s' % string.join(bytes[i*16:(i+1)*16], '')
    print '   %s' % string.join(bytes[(i+1)*16:], '')


def find_connection(packet):
    '''
    Find out which connection does this packet belongs to
    '''
    global connections
    for i in connections:
        if packet == i.refpkt:
            return i

    # Do it again, this time with the packet inverted
    pkt = Packet(packet.dst_ip, packet.src_ip, 
                packet.dst_port, packet.src_port, 
                packet.pktlen, packet.timestamp)
    for i in connections:
        if pkt == i.refpkt:
            del pkt
            return i

    del pkt
    return None


def update_inode_2_pid():
    '''
    build and update inode to pid mapping dict
    '''
    global inodepid
    pids = (x for x in os.listdir('/proc') if (lambda x:all(i in string.digits for i in x))(x))
    for pid in pids:
        path = os.path.join('/proc', pid, 'fd')
        for root, dirs, files in os.walk(path):
            for fd in files:
                fullpath = os.path.join(path, fd)
                try:
                    data = os.readlink(fullpath)
                    if data.startswith('socket'):
                        inode = data.split('[')[1][:-1]
                        if inodepid.get(inode) is not None:
                            del inodepid[inode]
                        inodepid[inode] = pid
                except OSError:  # Just ignore it
                    pass 


def get_process_name(pid):
    '''
    get process name by pid
    '''
    path = os.path.join('/proc', pid, 'exe')
    try:
        return os.readlink(path) 
    except:
        return "unknown"


def get_process_by_connection(conn):
    global conninode
    global inodepid
    global processes
    debug = True

    inode = conninode.get(conn.refpkt.hash_str)
    if inode is None:
        # build two dicts 
        update_inode_2_pid()
        parse_proc_net_tcp()
        # try again 
        inode = conninode.get(conn.refpkt.hash_str)
        
    if inode is None:
        pass
    else: # found inode, then try to find pid
        pid = inodepid.get(inode)
        if pid is None:
            update_inode_2_pid()
            pid = inodepid.get(inode)

        if pid is None:
            #print 'No pid info for inode'
            pass
        else:
            name = get_process_name(pid)
            try:
                uid = os.stat(os.path.join('/proc', pid)).st_uid
            except OSError:
                # Normaly this operation would success. If it's not
                # it's probably because user kill the process but the program
                # still process it's connections. It's nonsence to calculate
                # a dead process's traffic rate, so just return here. 
                return
            flag = True
            for i in processes:
                if i.name == name:
                    flag = False
                    i.add_connection_2_process(conn)
            if flag:
                proc = Process(inode, name, pid, uid)
                proc.add_connection_2_process(conn)
                processes.append(proc)


def parse_proc_net_tcp():
    '''
    parsing /proc/net/tcp. build and update hash string to inode mapping dict.
    hash string is like: '192.168.1.17:80-172.22.192.8:11234'
    We are only interested in 'local_address', 'rem_address' and 'inode'.

    NOTE: if inode == 0, that means the TCP is in TIME_WAIT state.  

     sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode                                                     
   0: 00000000:0050 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 9161 1 d2745400 300 0 0 2 -1                              
   1: 0100007F:0277 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 7420 1 d2744a00 300 0 0 2 -1                              
   2: 00000000:01BD 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 78437 1 d2744000 300 0 0 2 -1                             
   3: 0100007F:0CEA 00000000:0000 0A 00000000:00000000 00:00000000 00000000   116        0 7996 1 d2744f00 300 0 0 2 -1                              
   4: 00000000:008B 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 78439 1 d2744500 300 0 0 2 -1                             
   5: CF144A0A:01BD C7144A0A:1271 01 00000000:00000000 02:0009D8A2 00000000     0        0 427152 2 dd658f00 36 4 31 4 4                             
   6: CF144A0A:01BD D6144A0A:D54C 01 00000000:00000000 02:000A98A5 00000000     0        0 427541 2 dd658a00 40 4 1 2 3                              
   7: CF144A0A:01BD A1144A0A:C1BB 01 00000000:00000000 02:000AFF0D 00000000     0        0 427623 2 dd658000 22 4  
    '''
    global conninode
    with open('/proc/net/tcp') as f:
        data = f.readlines()
        # omit the first line
        # may be try regular exprssion ?
        for i in data[1:]:
            line = [x for x in i.strip().split(' ') if x != '']
            src = line[1].split(':')
            src_ip = socket.inet_ntoa(struct.pack('I', int(src[0], 16)))
            src_port = int(src[1], 16)
            dst = line[2].split(':')
            dst_ip = socket.inet_ntoa(struct.pack('I', int(dst[0], 16)))
            dst_port = int(dst[1], 16)
            # get the hash string, like '192.168.1.17:80-172.22.192.8:11234'
            # hash_str = src_ip + ':' + str(src_port) + '-' + dst_ip + ':' + str(dst_port)
            hash_str = ''.join((src_ip, ':', str(src_port), '-', dst_ip, ':', str(dst_port)))

            inode = line[9]
            if inode == 0:
                return None
            else:
                conninode[hash_str] = inode


def refresh_processes(proclist):
    '''
    Check processes, and remove any timed-out one.
    We also check the existence of /proc/pid, if user
    kill that process we can remove it right away   
    '''
    global current_time
    parse_proc_net_tcp()
    for proc in proclist:
        if not os.access(os.path.join('/proc', proc.pid), os.F_OK):
            proclist.remove(proc)
        if current_time - proc.last_pkt  >= PROCESS_AGEOUT:
            proclist.remove(proc)


def get_traffic_rate(proc):
    '''
    get target process's traffic rate
    '''
    global current_time
    sum_sent, sum_recv = 0, 0
    for conn in proc.connlist:
        if current_time - conn.last_pkt_timestamp >= CONNECTION_AGEOUT:
            proc.connlist.remove(conn)
        else:
            sent, recv = 0, 0
            for pkt in conn.sent_pktlist:
                if current_time - pkt.timestamp >= PERIOD:
                    conn.sent_pktlist.remove(pkt)
                else:
                    sent += pkt.pktlen
            sum_sent += sent

            for pkt in conn.recv_pktlist:
                if current_time - pkt.timestamp >= PERIOD:
                    conn.recv_pktlist.remove(pkt)
                else:
                    recv += pkt.pktlen
            sum_recv += recv

    return float(sum_sent) / PERIOD / 1024, float(sum_recv) / PERIOD / 1024


def got_packet(pktlen, data, timestamp):
    '''
    libpcap's callback function. It is called when a packet is captured.
    NOTE: at this moment, the packet we captured here is a layer 2 packet (ethernet/PPP/...)
    '''
    global current_time
    global screen
    if not data:
        return

    # Only deal with ethernet packet
    # check ethernet type (ipv4: 0x0800, ipv6:0x86dd)
    if data[12:14] == '\x08\x00':    
        d = decode_ip_packet(data[14:])
        current_time = timestamp
        '''
        print '\n%s.%f %s > %s' % (time.strftime('%H:%M', time.localtime(timestamp)),
                timestamp % 60, d['source_address'], d['destination_address'])

        for key in ['version', 'header_len', 'tos', 'total_len', 'id', 
                    'flags', 'fragment_offset', 'ttl']:
            print ' %s:%d' %(key, d[key])
        print ' protocol: %s' % protocols[d['protocol']]
        print ' header checksum: %d' % d['checksum']
        print ' source port: %d' % d['source_port']
        print ' destination port: %d' % d['destination_port']
        '''

        packet = Packet(d['source_address'], d['destination_address'],
            d['source_port'], d['destination_port'], pktlen, timestamp)

        connection = find_connection(packet)
        if connection != None:
            connection.add_pkt_2_connection(packet)
        else:  # It is a new connection 
            connection = Connection(packet)
            get_process_by_connection(connection)

    refresh_processes(processes)
    draw_ui(screen)


def init_ui():
    screen = curses.initscr()
    curses.start_color()
    curses.init_pair(1, curses.COLOR_GREEN, curses.COLOR_BLACK)
    curses.init_pair(2, curses.COLOR_BLUE, curses.COLOR_BLACK)
    curses.init_pair(3, curses.COLOR_RED, curses.COLOR_BLACK)
    curses.noecho()
    curses.cbreak()
    screen.nodelay(True)
    return screen


def exit_ui(screen):
    screen.clear()
    curses.endwin()


def draw_ui(screen):
    global processes

    height, width = screen.getmaxyx()
    # check terminal window width
    if width < 60:
        screen.clear()
        screen.addstr(0, 0, "Terminal window is too narrow! Please make it wider to display properly.\n")
        return

    if width > 512:
        width = 512

    proglen = width - 53
    screen.clear()
    screen.addstr(0, 0, "Traffic Monitor V0.1  Type 'q' to quit.", curses.color_pair(3)|curses.A_BOLD)
    screen.attron(curses.A_REVERSE)
    title_field = ["PID", 4*' ', "USER", 4*' ', "PROGRAM", (proglen-1)*' ',  "DEV", 4*' ', "  SENT",  4*' ', "  RECEIVED", 4*' '] 
    screen.addstr(2, 0, ''.join(title_field))
    screen.attroff(curses.A_REVERSE)
    for index, proc in enumerate(processes, 1):
        screen.addstr(3+index, 0, proc.pid)
        screen.addstr(3+index, 6, proc.user)
        screen.addstr(3+index, 6+9, proc.name)
        screen.addstr(3+index, 6+9+proglen+2+4, sys.argv[1])
        upstream, downstream = get_traffic_rate(proc)
        screen.addstr(3+index, 6+9+proglen+2+6+2, "%10.3f"%upstream, curses.color_pair(1)|curses.A_BOLD)
        screen.addstr(3+index, 6+9+proglen+2+6+9+3, "%10.3f"%downstream, curses.color_pair(1)|curses.A_BOLD)
        screen.addstr(3+index, 6+9+proglen+2+6+9+3+11, "KB/sec")

    screen.refresh()


if __name__ == '__main__':

    if len(sys.argv) < 2:
        print 'usage: sniff.py <interface> [expr]'
        sys.exit(0)

    conninode   = {}  # key: hash_str, value: inode
    inodepid    = {}  # key: inode , value: pid
    processes   = []  # all the processes
    connections = []  # all the connections
    current_time = 0  # current packet's timestamp
    PROCESS_AGEOUT = 90
    CONNECTION_AGEOUT = 50
    PERIOD = 5 

    local_ip = get_local_ipaddr(sys.argv[1])
    p_obj = pcap.pcapObject()
    dev = sys.argv[1]
    net, mask = pcap.lookupnet(dev)
    try:
        p_obj.open_live(dev, 1600, 0, 100)
    except:
        print 'You need root privilege to run this program!'
        sys.exit()

    # if we specify packet filter, set it now
    if len(sys.argv) == 3:
        p_obj.setfilter(string.join(sys.argv[2:], ''), 0, 0)

    screen = init_ui()
    while True:
        ch = screen.getch()
        if ch == ord('q') or ch == ord('Q'):
            exit_ui(screen)
            # print results in red. Using ANSI Escape Sequences trick :)
            print '\033[31m%d packets received, %d packets dropped, %d packets dropped by interface\033[0m\n' % p_obj.stats()
            sys.exit()    
        
        p_obj.dispatch(1, got_packet)
