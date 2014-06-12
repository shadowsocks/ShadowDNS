#!/usr/bin/python
# -*- coding: utf-8 -*-

import sys
sys.path.insert(0, 'shadowsocks')
import os
import signal
import select
import time
from subprocess import Popen, PIPE

p1 = Popen(['sudo', sys.executable, 'shadowdns/dnsrelay.py', '-c', sys.argv[-1]],
           shell=False, bufsize=0, stdin=PIPE, stdout=PIPE, stderr=PIPE, close_fds=True)
p2 = Popen(['ssserver', '-c', sys.argv[-1]], shell=False, bufsize=0, stdin=PIPE,
           stdout=PIPE, stderr=PIPE, close_fds=True, env=os.environ)
p3 = None

try:
    local_ready = False
    server_ready = False
    fdset = [p1.stdout, p2.stdout, p1.stderr, p2.stderr]
    while True:
        r, w, e = select.select(fdset, [], fdset)
        if e:
            break
            
        for fd in r:
            line = fd.readline()
            sys.stdout.write(line)
            if line.find('starting dns') >= 0:
                local_ready = True
            if line.find('starting server') >= 0:
                server_ready = True

        if local_ready and server_ready and p3 is None:
            time.sleep(1)
            p3 = Popen(['dig', '@127.0.0.1', 'any', 'google.com'],
                       shell=False, bufsize=0, close_fds=True)
            break
            
    if p3 is not None:
        r = p3.wait()
        if r == 0:
            print 'test passed'
        sys.exit(r)

finally:
    for p in [p1, p2]:
        try:
            os.kill(p.pid, signal.SIGTERM)
        except OSError:
            pass
   
sys.exit(-1)
