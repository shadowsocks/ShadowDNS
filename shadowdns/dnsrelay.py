#!/usr/bin/python
# -*- coding: utf-8 -*-

# Copyright (c) 2014 clowwindy
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

import time
import socket
import struct
import logging
from shadowsocks import eventloop, asyncdns, lru_cache, encrypt
from shadowsocks import utils as shadowsocks_utils
from shadowsocks.common import parse_header


BUF_SIZE = 4096

CACHE_TIMEOUT = 10


class UDPDNSRelay():
    def __init__(self, config):
        self._loop = None
        self._config = config
        self._id_to_addr = lru_cache.LRUCache(CACHE_TIMEOUT)
        self._local_sock = None
        self._remote_sock = None
        self._last_time = time.time()

        dns_addr = config['dns']
        addrs = socket.getaddrinfo(dns_addr, 53, 0,
                                   socket.SOCK_DGRAM, socket.SOL_UDP)
        if not addrs:
            raise Exception("can't get addrinfo for DNS address")
        af, socktype, proto, canonname, sa = addrs[0]

        dns_port = struct.pack('>H', 53)
        if af == socket.AF_INET:
            self._address_to_send = '\x01' + socket.inet_aton(sa[0]) + dns_port
        else:
            self._address_to_send = '\x04' + socket.inet_pton(af, sa[0]) + \
                                    dns_port

        self._local_addr = (config['local_address'], 53)
        self._remote_addr = (config['server'], config['server_port'])

        sockets = []
        for addr in (self._local_addr, self._remote_addr):
            addrs = socket.getaddrinfo(addr[0], addr[1], 0,
                                       socket.SOCK_DGRAM, socket.SOL_UDP)
            if len(addrs) == 0:
                raise Exception("can't get addrinfo for %s:%d" % addr)
            af, socktype, proto, canonname, sa = addrs[0]
            sock = socket.socket(af, socktype, proto)
            sock.setblocking(False)
            sockets.append(sock)

        self._local_sock, self._remote_sock = sockets
        self._local_sock.bind(self._local_addr)

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop

        loop.add(self._local_sock, eventloop.POLL_IN)
        loop.add(self._remote_sock, eventloop.POLL_IN)
        loop.add_handler(self.handle_events)

    def _handle_local(self, sock):
        data, addr = sock.recvfrom(BUF_SIZE)
        header = asyncdns.parse_header(data)
        if header:
            try:
                req_id = header[0]
                req = asyncdns.parse_response(data)
                self._id_to_addr[req_id] = addr
                data = self._address_to_send + data
                data = encrypt.encrypt_all(self._config['password'],
                                           self._config['method'], 1, data)
                self._remote_sock.sendto(data, self._remote_addr)
                logging.info('request %s', req.hostname)
            except Exception as e:
                logging.error(e)

    def _handle_remote(self, sock):
        data, addr = sock.recvfrom(BUF_SIZE)
        if data:
            try:
                data = encrypt.encrypt_all(self._config['password'],
                                           self._config['method'], 0, data)
                header_result = parse_header(data)
                if header_result is None:
                    return
                addrtype, dest_addr, dest_port, header_length = header_result
                data = data[header_length:]
                header = asyncdns.parse_header(data)
                if header:
                    req_id = header[0]
                    res = asyncdns.parse_response(data)
                    addr = self._id_to_addr.get(req_id, None)
                    if addr:
                        self._local_sock.sendto(data, addr)
                        del self._id_to_addr[req_id]
                    logging.info('response %s', res)
            except Exception as e:
                logging.error(e)

    def handle_events(self, events):
        for sock, fd, event in events:
            if sock == self._local_sock:
                self._handle_local(sock)
            elif sock == self._remote_sock:
                self._handle_remote(sock)
        now = time.time()
        if now - self._last_time > CACHE_TIMEOUT / 2:
            self._id_to_addr.sweep()


def main():
    shadowsocks_utils.check_python()

    config = shadowsocks_utils.get_config(True)

    encrypt.init_table(config['password'], config['method'])

    logging.info("starting dns at %s:%d" % (config['local_address'], 53))

    config['dns'] = config.get('dns', '8.8.8.8')

    loop = eventloop.EventLoop()
    udprelay = UDPDNSRelay(config)
    udprelay.add_to_loop(loop)
    loop.run()

if __name__ == '__main__':
    main()
