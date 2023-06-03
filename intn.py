import psutil
import pymongo
from pymongo.server_api import ServerApi

from flask import Flask, request, jsonify
from flask_cors import CORS
from pyroute2 import NetNS
import socket
ns = NetNS('dataplane')

app = Flask(__name__)
CORS(app)

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["int_details"]
coll_route_info = db["ubuntu_route_info"]
coll_interface_info = db["ubuntu_interface_info"]


routes_protocol_map = {
    -1: '',
    0: 'unspec',
    1: 'redirect',
    2: 'kernel',
    3: 'boot',
    4: 'static',
    8: 'gated',
    9: 'ra',
    10: 'mrt',
    11: 'zebra',
    12: 'bird',
    13: 'dnrouted',
    14: 'xorp',
    15: 'ntk',
    16: 'dhcp',
    18: 'keepalived',
    42: 'babel',
    186: 'bgp',
    187: 'isis',
    188: 'ospf',
    189: 'rip',
    192: 'eigrp',
}

routes_protocol_id_map = { y:x for x, y in routes_protocol_map.items() }

def store_ubuntu_routing_table():
 coll_route_info.delete_many({})
 ipr = IPRoute()
 routes = ns.get_routes(family=socket.AF_INET)
 routing_table = []
 for route in routes:
  destination = "0.0.0.0/0"
  metric = 0
  gateway = "none"
  protocol = int(route['proto'])
  for attr in route['attrs']:
    if attr[0] == 'RTA_OIF':
	    intfc_name = ns.get_links(attr[1])[0].get_attr('IFLA_IFNAME')
	  if attr[0] == 'RTA_GATEWAY':
	    gateway = attr[1]
	  if attr[0] == 'RTA_PRIORITY':
	    metric = attr[1]
	  if attr[0] == 'RTA_DST':
	    destination = attr[1]
	
  coll_route_info.insert_one({
        "interface_name":str(intfc_name),
        "gateway":str(gateway),
        "destination":str(destination),
        "metric":int(metric),
        "protocol":routes_protocol_map[protocol],
        })
  routing_table.append({ 
                "gateway": str(gateway),
                "destination": str(destination),
                "metric": int(metric),
                "protocol": routes_protocol_map[protocol],
                "interface": str(intfc_name)
			})
            
 return routing_table

def store_interface_details():
  coll_interface_info_.delete_many({})
  interface = psutil.net_if_addrs()
  intfc_ubuntu = []
  for intfc_name in interface:
    addresses = interface[intfc_name]
    for address in addresses:
      
       if address.family == 2:
         colect = {
            "interface_name":intfc_name,
            "IPv4address":str(address.address),
            "netmask":str(address.netmask),
            "broadcast":str(address.broadcast)
         }
       if address.family == 17:
         colect.update({
            "mac_address":str(address.address)
         })
       for i in coll_route_info.find():
         if intfc_name == i["interface_name"]:
           colect.update({
                "gateway":i["gateway"]
             })
         
    intfc_ubuntu.append(colect)
    coll_interface_info.insert_one(colect)
  pci_out = subprocess.check_output(["lspci"]).decode().split("\n")
  for line in pci_out:
    if "Ethernet controller" in line:
      pci_info = "0000:"+line.split()[0]
      lsh_out = subprocess.check_output(["lshw", "-c", "network", "-businfo"])
      lsh_out = lsh_out.decode().split("\n")
      lsh_out = lsh_out[2:]
      for line in lsh_out:
        li = line.split()
        lii = li[0].split("@")
        pci_addr = lii[1]
        if pci_info == pci_addr:
           for i in coll_interface_info.find():
             if i["interface_name"] == li[1]:
               query = {"interface_name": li[1]}
               update_data = {$set: {"pci_address":pci_info}}
               coll_interface_info.update_many(query, update_data)
  
@app.route('/routing_table')
def get_ubuntu_routing_table():
  routing_table = []
  for route in coll_route_info.find():
    routing_table.append(route)
    
  return routing_table
@app.route('/interface_details')    
def get_interface_details():
  interface_details = []
  for interface in coll_interface_info.find():
    interface_details.append(interface)
    
  return interface_details

    
  

print(store_ubuntu_routing_table())
store_interface_details()
      
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
