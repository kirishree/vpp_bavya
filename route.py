from flask import Flask, request, jsonify
from flask_cors import CORS
from pyroute2 import NetNS
import socket
ns = NetNS('dataplane')

app = Flask(__name__)
CORS(app)
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

@app.route('/routing_table')
def get_frr_routing_table():
 routes = ns.get_routes(family=socket.AF_INET)
 routing_table = []
 for route in routes:
  destiantion = "0.0.0.0/0"
  metric = 0
  protocol = int(route['proto'])
  for attr in route['attrs']:
    if attr[0] == 'RTA_OIF':
	  intfc_name = ns.get_links(attr[1])[0].get_attr('IFLA_NAME')
	if attr[0] == 'RTA_GATEWAY':
	  gateway = attr[1]
	if attr[0] == 'RTA_PRIORITY':
	  metric = attr[1]
	if attr[0] == 'RTA_DST':
	  destination = attr[1]
	  
  routing_table.append({ 
                "gateway": str(gateway),
                "destination": str(destination),
                "metric": int(metric),
                "protocol": routes_protocol_map[protocol] ,
                "interface": str(interface)
			})
 return routing_table
 
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
				
		
