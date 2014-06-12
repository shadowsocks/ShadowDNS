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
import errno
import logging
from shadowsocks import eventloop, asyncdns, lru_cache, encrypt
from shadowsocks import utils as shadowsocks_utils
from shadowsocks.common import parse_header


BUF_SIZE = 16384

CACHE_TIMEOUT = 10


class DNSRelay(object):

    def __init__(self, config):
        self._loop = None
        self._config = config
        self._last_time = time.time()

        self._local_addr = (config['local_address'], 53)
        self._remote_addr = (config['server'], config['server_port'])

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

    def add_to_loop(self, loop):
        if self._loop:
            raise Exception('already add to loop')
        self._loop = loop
        loop.add_handler(self.handle_events)

    def handle_events(self, events):
        pass


class UDPDNSRelay(DNSRelay):

    def __init__(self, config):
        DNSRelay.__init__(self, config)

        self._id_to_addr = lru_cache.LRUCache(CACHE_TIMEOUT)
        self._local_sock = None
        self._remote_sock = None

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
        DNSRelay.add_to_loop(self, loop)

        loop.add(self._local_sock, eventloop.POLL_IN)
        loop.add(self._remote_sock, eventloop.POLL_IN)

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
                import traceback
                traceback.print_exc()
                logging.error(e)

    def _handle_remote(self, sock):
        data, addr = sock.recvfrom(BUF_SIZE)
        if data:
            try:
                data = encrypt.encrypt_all(self._config['password'],
                                           self._config['method'], 0, data)
                header_result = parse_header(data)
                if header_result is None:
                    return None, None
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
                import traceback
                traceback.print_exc()
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


class TCPDNSRelay(DNSRelay):

    def __init__(self, config):
        DNSRelay.__init__(self, config)

        self._local_to_remote = {}
        self._remote_to_local = {}
        self._local_to_encryptor = {}

        addrs = socket.getaddrinfo(self._local_addr[0], self._local_addr[1], 0,
                                   socket.SOCK_STREAM, socket.SOL_TCP)
        if len(addrs) == 0:
            raise Exception("can't get addrinfo for %s:%d" % self._local_addr)
        af, socktype, proto, canonname, sa = addrs[0]
        self._listen_sock = socket.socket(af, socktype, proto)
        self._listen_sock.setblocking(False)
        self._listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self._listen_sock.bind(self._local_addr)
        self._listen_sock.listen(1024)

    def _handle_conn(self, sock):
        try:
            local, addr = sock.accept()
            addrs = socket.getaddrinfo(self._remote_addr[0],
                                       self._remote_addr[1], 0,
                                       socket.SOCK_STREAM, socket.SOL_TCP)
            if len(addrs) == 0:
                raise Exception("can't get addrinfo for %s:%d" %
                                self._remote_addr)
            af, socktype, proto, canonname, sa = addrs[0]
            remote = socket.socket(af, socktype, proto)
            local.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            remote.setsockopt(socket.SOL_TCP, socket.TCP_NODELAY, 1)
            self._local_to_remote[local] = remote
            self._remote_to_local[remote] = local

            self._loop.add(local, 0)
            self._loop.add(remote, eventloop.POLL_OUT)
            try:
                remote.connect(self._remote_addr)
            except (OSError, IOError) as e:
                if eventloop.errno_from_exception(e) in (errno.EINPROGRESS,
                                                         errno.EAGAIN):
                    pass
                else:
                    raise
        except (OSError, IOError) as e:
            logging.error(e)

    def _destroy(self, local, remote):
        if local in self._local_to_remote:
            self._loop.remove(local)
            self._loop.remove(remote)
            del self._local_to_remote[local]
            del self._remote_to_local[remote]
            if local in self._local_to_encryptor:
                del self._local_to_encryptor[local]
            local.close()
            remote.close()
        else:
            logging.error('already destroyed')

    def _handle_local(self, local, event):
        remote = self._local_to_remote[local]
        encryptor = self._local_to_encryptor.get(local, None)
        if event & eventloop.POLL_ERR:
            self._destroy(local, remote)
        elif event & eventloop.POLL_IN:
            try:
                data = local.recv(BUF_SIZE)
                if not data:
                    self._destroy(local, remote)
                else:
                    if not encryptor:
                        try:
                            req = asyncdns.parse_response(data[2:])
                            if req:
                                logging.info('request %s', req.hostname)
                        except Exception as e:
                            logging.error(e)
                        encryptor = \
                            encrypt.Encryptor(self._config['password'],
                                              self._config['method'])
                        self._local_to_encryptor[local] = encryptor
                        data = self._address_to_send + data
                    data = encryptor.encrypt(data)
                    remote.send(data)
            except (OSError, IOError) as e:
                self._destroy(local, self._local_to_remote[local])
                logging.error(e)

    def _handle_remote(self, remote, event):
        local = self._remote_to_local[remote]
        if event & eventloop.POLL_ERR:
            self._destroy(local, remote)
        elif event & eventloop.POLL_OUT:
            self._loop.modify(remote, eventloop.POLL_IN)
            self._loop.modify(local, eventloop.POLL_IN)
        elif event & eventloop.POLL_IN:
            try:
                data = remote.recv(BUF_SIZE)
                if not data:
                    self._destroy(local, remote)
                else:
                    encryptor = self._local_to_encryptor[local]
                    data = encryptor.decrypt(data)
                    try:
                        res = asyncdns.parse_response(data[2:])
                        if res:
                            logging.info('response %s', res)
                    except Exception as e:
                        logging.error(e)
                    local.send(data)
            except (OSError, IOError) as e:
                self._destroy(local, remote)
                logging.error(e)

    def add_to_loop(self, loop):
        DNSRelay.add_to_loop(self, loop)
        loop.add(self._listen_sock, eventloop.POLL_IN)

    def handle_events(self, events):
        for sock, fd, event in events:
            if sock == self._listen_sock:
                self._handle_conn(sock)
            elif sock in self._local_to_remote:
                self._handle_local(sock, event)
            elif sock in self._remote_to_local:
                self._handle_remote(sock, event)
        # TODO implement timeout


def main():
    shadowsocks_utils.check_python()

    config = shadowsocks_utils.get_config(True)

    encrypt.init_table(config['password'], config['method'])

    logging.info("starting dns at %s:%d" % (config['local_address'], 53))

    config['dns'] = config.get('dns', '8.8.8.8')

    loop = eventloop.EventLoop()

    udprelay = UDPDNSRelay(config)
    udprelay.add_to_loop(loop)
    tcprelay = TCPDNSRelay(config)
    tcprelay.add_to_loop(loop)

    loop.run()

if __name__ == '__main__':
    main()
