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


class Resolver(object):
    # map = {'example.com': ['123.123.123.123',
    #                        '12.12.12.12']}

    def __init__(self, ip_map=None, poll_interval='3s'):
        self.map = ip_map or {}
        self.client = Client()
        self.interval = parse_interval(poll_interval)
        self.poll_flag = True
        self.names = []
        self.manager_ips = []

    def poll_names(self):
        names = get_server_names(self.client)
        manager_ips = get_manager_ips(self.client)
        msg = ('Poll Success!'
               'Names:'
               '    Added:   {na}'
               '    Deleted: {nd}'
               'Manager IPs:'
               '    Added:   {ia}'
               '    Deleted: {id}')
        self.map = {n: manager_ips for n in names}
        log.info(msg.format(*diff_list(self.names, names) +
                             diff_list(self.manager_ips, manager_ips)))
        self.names = names
        self.manager_ips = manager_ips

    def stop_polling(self):
        self.poll_flag = False

    def start_polling(self):
        def poll(self):
            while self.poll_flag:
                gevent.sleep(self.interval)
                try:
                    self.poll_names()
                except Exception as e:
                    log.error('Polling failed: %s' % e)

        gevent.spawn(poll, self)

    def resolve(self, name):
        return self.map.get(name)

    def get_reply(self, query):
        IPs = []
        if not isinstance(query, DNSRecord):
            query = DNSRecord.parse(query)
        qname = str(query.q.qname)
        qtype = query.q.qtype
        if qname.endswith('.'):
            qname = qname[:-1]
        reply = query.reply()
        if qtype == QTYPE.A:
            IPs = self.resolve(qname)
        if IPs:
            [reply.add_answer(RR(qname, qtype, rdata=A(ip), ttl=10)) for ip in IPs]
        else:
            reply.header.rcode = getattr(RCODE, 'NXDOMAIN')
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
    resolver = Resolver(poll_interval=os.getenv('POLL_INTERVAL', '3s'))
    tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    tcp_socket.bind(addr)
    udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    udp_socket.bind(addr)
    rack = ServerRack([TCPServer(resolver=resolver, listener=tcp_socket),
                       UDPServer(resolver=resolver, listener=udp_socket)])
    resolver.start_polling()
    rack.serve_forever()


if __name__ == '__main__':
    main()
