from vpp_papi import VPPApiClient
import os
import subprocess
import json
import fnmatch
import sys
vpp_json_dir = '/usr/share/vpp/api/'
jsonfiles = []
for root, dirnames, filenames in os.walk(vpp_json_dir):
  for filename in fnmatch.filter(filenames, '*.api.json'):
    jsonfiles.append(os.path.join(root, filename))

vpp = VPPApiClient(apifiles=jsonfiles, server_address='/run/vpp/api.sock')
vpp.connect("test-client")

v = vpp.api.show_version()
print('VPP version is %s' % v.version)
out = vpp_papi.sw_interface_set_l3_xconnect(enable=1, rx_sw_if_index=interface_name, tx_sw_if_index=interface_name)
print(out)
