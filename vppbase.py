from flask import Flask, request, jsonify
from flask_cors import CORS
from vpp_papi import VPPApiClient
import os
import subprocess
import fnmatch
import json
import socket
import time
vpp_json_dir = '/usr/share/vpp/api/'
jsonfiles = []
for root, dirnames, filenames in os.walk(vpp_json_dir):
  for filename in fnmatch.filter(filenames, '*.api.json'):
    jsonfiles.append(os.path.join(root, filename))

vpp = VPPApiClient(apifiles=jsonfiles, server_address='/run/vpp/api.sock')
vpp.connect("test-client")

v = vpp.api.show_version()
print('VPP version is %s' % v.version)
ip = 'none'
def blocklist():
  ips = socket.gethostbyname_ex('youtube.com')
  ipn = ip[2]
  ipno = ipn[0]
  if ipno != ip:
    ip = ipno
	ip_netmask = ip+"/32"
    acl_add = subprocess.check_output(["sudo", "vppctl", "set", "acl-plugin", "acl", deny, "src", "any", "dst", ip_netmask, ",", "permit", "src", "any", "dst", "any"]).decode("utf-8")
    acl_ind = acl_add.split(":")[1]
    #os.system(f"sudo vppctl set acl-plugin acl {data['action']} src {data['source']} dst {data['destination']}, proto {data['protocol']} sport {data['sport_range']}, dport {data['dport_range']}, permit src any dst any")
    acl_int = vpp.api.acl_interface_add_del(is_add=1, is_input=0, sw_if_index=, acl_index=int(acl_ind))
  time.sleep(60)
  blocklist()
  
blocklist()
