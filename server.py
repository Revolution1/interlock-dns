#!/usr/bin/env python
import sys

import gevent
from docker import Client
from gevent import monkey
from gevent import socket
from gevent.server import DatagramServer
from gevent.server import StreamServer

from utils import diff_list
from utils import get_manager_ips
from utils import get_server_names
from utils import parse_interval

monkey.patch_all()

from dnslib import *

import logging

log = logging.getLogger('DCE-DNSServer')
log_handler = logging.StreamHandler(sys.stderr)
log.addHandler(log_handler)
log.setLevel('DEBUG')

ROOT_SERVERS_MAP = {'a.root-servers.net': ['198.41.0.4'],
                    'b.root-servers.net': ['192.228.79.201'],
                    'c.root-servers.net': ['192.33.4.12'],
                    'd.root-servers.net': ['128.8.10.90'],
                    'e.root-servers.net': ['192.203.230.10'],
                    'f.root-servers.net': ['192.5.5.241'],
                    'g.root-servers.net': ['192.112.36.4'],
                    'h.root-servers.net': ['128.63.2.53'],
                    'i.root-servers.net': ['192.36.148.17'],
                    'j.root-servers.net': ['192.58.128.30'],
                    'k.root-servers.net': ['193.0.14.129'],
                    'l.root-servers.net': ['198.32.64.12'],
                    'm.root-servers.net': ['202.12.27.33']}


class Resolver(object):
    def __init__(self, ip_map=None, poll_interval='3s', ttl='5s', root_servers_map=None):
        self.map = ip_map or {}
        self.client = Client()
        self.interval = parse_interval(poll_interval)
        self.ttl = int(parse_interval(ttl))
        self.poll_flag = True
        self.names = []
        self.manager_ips = []
        self.root_servers_map = root_servers_map or ROOT_SERVERS_MAP

    def poll_names(self):
        names = get_server_names(self.client)
        manager_ips = get_manager_ips(self.client)
        msg = []
        na, nd = diff_list(self.names, names)
        ia, id = diff_list(self.manager_ips, manager_ips)
        if any([na, nd, ia, id]):
            msg.append('Poll Success!')
        if na or nd:
            msg.append('Names:')
            if na:
                msg.append('    Added:   %s' % ', '.join(na))
            if nd:
                msg.append('    Deleted: %s' % ', '.join(nd))
        if ia or id:
            msg.append('Manager IPs:')
            if ia:
                msg.append('    Added:   %s' % ', '.join(ia))
            if id:
                msg.append('    Deleted: %s' % ', '.join(id))
        self.map = {n.lower(): manager_ips for n in names}
        if msg:
            log.info('\n'.join(msg))
        self.names = names
        self.manager_ips = manager_ips

    def stop_polling(self):
        self.poll_flag = False

    def start_polling(self):
        def poll(self):
            while self.poll_flag:
                try:
                    self.poll_names()
                except Exception as e:
                    log.error('Polling failed: %s' % e)
                gevent.sleep(self.interval)

        gevent.spawn(poll, self)

    def resolve(self, name):
        if name.endswith('.'):
            name = name[:-1]
        name = name.lower()
        return self.map.get(name) or self.root_servers_map.get(name)

    def resolve_ns(self, name):
        if name.endswith('.'):
            name = name[:-1]
        name = name.lower()
        return self.root_servers_map.get(name)

    def get_reply(self, query):
        IPs = []
        if not isinstance(query, DNSRecord):
            query = DNSRecord.parse(query)
        qname = str(query.q.qname)
        qtype = query.q.qtype
        reply = query.reply()
        hit = 'No'
        if qtype == QTYPE.A:
            IPs = self.resolve(qname)
        if qtype == QTYPE.NS:
            IPs = self.resolve_ns(qname)
        if IPs:
            hit = 'Yes'
            [reply.add_answer(RR(qname, qtype, rdata=A(ip), ttl=self.ttl)) for ip in IPs]
        else:
            # _time = int(datetime.now().strftime('%Y%m%d00'))
            # reply.add_auth(RR("", QTYPE.SOA, ttl=10800,
            #                   rdata=SOA('a.root-servers.net', 'nstld.verisign-grs.com',
            #                             (_time, 1800, 900, 604800, 86400))))
            # for i in self.root_servers_map:
            #     reply.add_auth(RR("", QTYPE.NS, ttl=57435, rdata=NS(i)))
            # reply.add_auth(RR("", QTYPE.NS, ttl=57435, rdata=NS('114.114.114.114')))
            # reply.header.rcode = RCODE.NXDOMAIN
            reply.header.rcode = RCODE.SERVFAIL
        log.info('handling request name: %s; type: %s; hit: %s' % (qname, QTYPE[qtype], hit))
        return reply


class UDPServer(DatagramServer):
    def __init__(self, resolver, *args, **kwargs):
        """
        :type resolver: Resolver
        """
        super(UDPServer, self).__init__(*args, **kwargs)
        self.resolver = resolver

    def handle(self, data, address):
        reply = self.resolver.get_reply(data)
        self.sendto(reply.pack(), address)


class TCPServer(StreamServer):
    def __init__(self, resolver, *args, **kwargs):
        """
        :type resolver: Resolver
        """
        super(TCPServer, self).__init__(*args, **kwargs)
        self.resolver = resolver

    def handle(self, sock, address):
        """
        :type sock: socket.socket
        """
        data = sock.recv(8192)
        length = struct.unpack("!H", bytes(data[:2]))[0]
        while len(data) - 2 < length:
            data += sock.recv(8192)
        data = data[2:]
        reply = self.resolver.get_reply(data)
        sock.sendall(reply.pack())


class ServerRack(object):
    def __init__(self, servers):
        self.servers = servers

    def serve_forever(self):
        started = []
        g = []
        try:
            for server in self.servers[:]:
                g.append(gevent.spawn(server.serve_forever))
                started.append(server)
                name = getattr(server, 'name', None) or server.__class__.__name__ or 'Server'
                log.info('%s started on %s', name, server.address)
            [i.join() for i in g]
        except KeyboardInterrupt:
            log.info('Keyboard interrupted Exiting...')
        except Exception:
            pass
        finally:
            self.stop(started)

    def stop(self, servers=None):
        if servers is None:
            servers = self.servers[:]
        for server in servers:
            try:
                server.stop()
                server.resolver.stop_polling()
            except Exception:
                if hasattr(server, 'loop'):  # gevent >= 1.0
                    server.loop.handle_error(server.stop, *sys.exc_info())


def main():
    import os
    addr = (os.getenv('BIND_IP', ''), int(os.getenv('BIND_PORT', '53')))
    log.info('Starting DCE-DNSServer...')
    resolver = Resolver(poll_interval=os.getenv('POLL_INTERVAL', '3s'),
                        ttl=os.getenv('DNS_TTL', '5s'))
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind(addr)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(addr)
    servers = [UDPServer(resolver=resolver, listener=udp_socket)]
    if str(os.getenv('TCP_SERVER_ENABLED', '')).lower() in ('true', '1', 'enabled'):
        servers.append(TCPServer(resolver=resolver, listener=tcp_socket))
    rack = ServerRack(servers)
    resolver.start_polling()
    rack.serve_forever()


if __name__ == '__main__':
    main()
