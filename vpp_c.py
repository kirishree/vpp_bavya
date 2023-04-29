from flask import Flask, request, jsonify
from flask_cors import CORS
from vpp_papi import VPPApiClient
import os
import subprocess
import json
import fnmatch
import sys
import pymongo
from pymongo.server_api import ServerApi
import secrets
import random
import binascii
import ipaddress
import requests
from ipaddress import IPv4Interface
import netaddr
from netaddr import IPAddress
#--------------------------------------------------------------------------------------------------------------
#Local Database to store interface details of Ubuntu
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["wan_details"]
coll = db["wan_info"]
coll.delete_many({})
#-----------------------------------------------------------------------------------------------------------------
#Local Database to maintain iteration variable user for instance creation in VPP
db = client["iteration_variable"]
col = db["instance_list"]
client1 = pymongo.MongoClient("mongodb+srv://bavya:bavya23@cluster0.xxummtw.mongodb.net/?retryWrites=true&w=majority", server_api=ServerApi('1')) 

#-----------------------------------------------------------------------------------------------------------------
#Cloud Database to store Ipsec sa 
db_ipsec = client1["ipsec_key"]
col_ipsec_sa = db_ipsec["sa_table"]
#-----------------------------------------------------------------------------------------------------------------
#Cloud Database for MAC address of Loopback Interface
db_mac = client1["mac_address"]
col_mac = db_mac["mac_list"]
#-----------------------------------------------------------------------------------------------------------------
#Cloud Database for Ipsec Keys 
col_cryptokeys = db_ipsec["crypto_keys"]
col_integkeys = db_ipsec["integ_keys"]
#----------------------------------------------------------------------------------------------------------------
#Cloud Database to maintain Loopback IP Addresses
db_loopback = client1["loopback_address"]
col_vxlan_loopaddr = db_loopback["vxlan_loop_addr"]
col_gre_loopaddr = db_loopback["gre_loop_addr"]
#----------------------------------------------------------------------------------------------------------
#VPP Api Block
vpp_json_dir = '/usr/share/vpp/api/'
jsonfiles = []
for root, dirnames, filenames in os.walk(vpp_json_dir):
  for filename in fnmatch.filter(filenames, '*.api.json'):
    jsonfiles.append(os.path.join(root, filename))

vpp = VPPApiClient(apifiles=jsonfiles, server_address='/run/vpp/api.sock')
vpp.connect("test-client")

v = vpp.api.show_version()
print('VPP version is %s' % v.version)
#---------------------------------------------------------------------------------------------------------
app = Flask(__name__)
CORS(app)
#--------------------------------------------------------------------------------------------------------------
# Machine INFO
@app.route('/')  
def get_machine_info():
    with open('/etc/machine-id', 'r') as f:
        machine_id = f.read().strip()
    with open("/etc/hostname", "r") as f:
        host_name = f.read().strip()
    data = []
    output = subprocess.check_output(["ip", "route", "show"]).decode("utf-8")
    no = 1
    for line in output.splitlines():
      if no == 1:  
        if "default via" in line:
            gateway = line.split()[2]
            interface_name = line.split()[4]
            no = 0
         		
    cmd = "ifconfig -a"
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    #print(output)
    interfaces = {}

    current_interface = None
    iface = 1
    for line in output.splitlines():
        if line.startswith(' '):
            # We are in the middle of a block of information about the current interface
            if current_interface:
              parts = line.strip().split()
              if iface == 1:
                if parts[0] == "inet":
                    if current_interface == interface_name:
                       netmask =parts[3]
                       prefixlength = IPAddress(netmask).netmask_bits()
                       print(prefixlength)
                       ipaddress = parts[1]
                       slash = "/"
                       ipaddr_prefix = ipaddress+slash+str(prefixlength)
                       coll.insert_one({"interface_name": current_interface, "ip_address":parts[1], "ipaddress_netmask":ipaddr_prefix, "gateway":gateway})
                       collect = {"machine_id":machine_id, "host_name":host_name, "wan_ip":parts[1]}
                       data.append(collect)
                       iface = 0
                       return data
        else:
            # This is a new interface block
            parts = line.strip().split()
            if parts:
                current_interface = parts[0].strip(':')
                interfaces[current_interface] = {}

     
   		

#--------------------------------------------------------------------------------------------------------
#Ubuntu Interface - INFO
@app.route('/interfaces')  
def get_interface_info():
    data = []
    cmd = "ifconfig -a"
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
    #print(output)
    interfaces = {}
    
    current_interface = None
 
    response = requests.get("http://checkip.dyndns.org").text
    # Extract the public IP address from the response
    public_ip = response.split("<body>")[1].split("</body>")[0].strip()
    
    for line in output.splitlines():
        if line.startswith(' '):
            # We are in the middle of a block of information about the current interface
            if current_interface != "lo":
                parts = line.strip().split()
               
                if parts[0] == "inet":
                   output1 = subprocess.check_output(["ip", "route", "show"]).decode("utf-8")
                   num = 1
                   for line1 in output1.splitlines():
                     if "default via" in line1:
                       coll.insert_one({"gateway":line1.split()[2], "interface_name":line1.split()[4], "static/dhcp":line1.split()[6]})
                      
                       if current_interface == line1.split()[4]:
                         netmask =parts[3]
                         prefixlength = IPAddress(netmask).netmask_bits()
                         print(prefixlength)
                         ipaddress = parts[1]
                         slash = "/"
                         ipaddr_prefix = ipaddress+slash+str(prefixlength)
                         int_type = "wan"
                         gateway = line1.split()[2]
                         publicip = public_ip
                         stat_dhcp = line1.split()[6]
                         num = 0
                         collect = {"interface_name":current_interface, "int_type":int_type, "static/dhcp":stat_dhcp, "ipv4_address":ipaddress, "gateway":gateway, "mtu":mtu, "public_ip":publicip }
                         coll.insert_one({"interface_name":current_interface, "int_type":int_type, "static/dhcp":stat_dhcp, "ipv4_address":ipaddress, "gateway":gateway, "mtu":mtu, "public_ip":publicip, "ipaddr_prefix":ipaddr_prefix })
                   print(num)
                   if num == 1:
                       netmask =parts[3]
                       prefixlength = IPAddress(netmask).netmask_bits()
                       print(prefixlength)
                       ipaddress = parts[1]
                       slash = "/"
                       ipaddr_prefix = ipaddress+slash+str(prefixlength)
                       int_type = "lan"
                       gateway = " "
                       publicip = " "
                       stat_dhcp = "static"
                       collect = {"interface_name":current_interface, "int_type":int_type, "static/dhcp":stat_dhcp, "ipv4_address":ipaddress, "gateway":gateway, "mtu":mtu, "public_ip":publicip }
                       coll.insert_one({"interface_name":current_interface, "int_type":int_type, "static/dhcp":stat_dhcp, "ipv4_address":ipaddress, "gateway":gateway, "mtu":mtu, "public_ip":publicip, "ipaddr_prefix":ipaddr_prefix })
                if parts[0] == "ether":
                   mac_addr = parts[1]
                   print(mac_addr)
                   collect.update({"mac_addr":mac_addr})
                   data.append(collect)
                
        else:
            # This is a new interface block
            parts = line.strip().split()
            if parts:
                current_interface = parts[0].strip(':')
                interfaces[current_interface] = {}
                mtu = parts[3]
                
    return data
#------------------------------------------------------------------------------------------------------  
#Function to move Interface from Ubuntu to VPP
@app.route('/interface_name', methods = ['POST'])  
def interface_move():
  os.system(f"sudo vpp stop")
  data = request.json
  response = {"message":"successfull"}
  for i in data:
    os.system(f'sudo ifconfig {i["interface_name"]} down')
    os.system(f'sudo set int state {i["interface_name"]} up')
  os.system(f"sudo vpp start")  
  for i in data:
   for j in coll.find():
      if i["interface_name"]  == j["interface_name"]:
        if i["interface_name"] == "enp0s3":
          int_name = "GigabitEthernet0/3/0"
          local_gateway = j["gateway"]
          local_ip = j["ipaddr_prefix"]
          iface_list = vpp.api.sw_interface_dump()
          for iface in iface_list:
           if(iface.interface_name==int_name):
             index_int=iface.sw_if_index
          if(index_int>0):
             vpp.api.sw_interface_set_flags(sw_if_index=index_int, flags=3)
             vpp.api.sw_interface_add_del_address(sw_if_index=index_int, is_add=1, prefix=local_ip)
             os.system(f"sudo vppctl ip route add 0.0.0.0/0 via {local_gateway}")
          else:
              print("Interface Not found")
        
        elif i["interface_name"] == "enp0s8":
          int_name = "GigabitEthernet0/8/0"
          local_gateway = j["gateway"]
          local_ip = j["ipaddr_prefix"]
          iface_list = vpp.api.sw_interface_dump()
          for iface in iface_list:
           if(iface.interface_name==int_name):
             index_int=iface.sw_if_index
          if(index_int>0):
             vpp.api.sw_interface_set_flags(sw_if_index=index_int, flags=3)
             vpp.api.sw_interface_add_del_address(sw_if_index=index_int, is_add=1, prefix=local_ip)
             os.system(f"sudo vppctl ip route add 0.0.0.0/0 via {local_gateway}")
          else:
              print("Interface Not found")
        
        elif i["interface_name"] == "enp0s9":
          int_name = "GigabitEthernet0/9/0"
          local_gateway = j["gateway"]
          local_ip = j["ipaddr_prefix"]
          iface_list = vpp.api.sw_interface_dump()
          for iface in iface_list:
           if(iface.interface_name==int_name):
             index_int=iface.sw_if_index
          if(index_int>0):
             vpp.api.sw_interface_set_flags(sw_if_index=index_int, flags=3)
             vpp.api.sw_interface_add_del_address(sw_if_index=index_int, is_add=1, prefix=local_ip)
             os.system(f"sudo vppctl ip route add 0.0.0.0/0 via {local_gateway}")
          else:
              print("Interface Not found")
  return jsonify(response), 200    

#-----------------------------------------------------------------------------------------------------------
#Loopback IP Address Generation for Vxlan Tunnel 
def vxlan_loopback_ip_addr(vx_loop_id):
  add = 0
  
  for i in col_vxlan_loopaddr.find():
    if i["loop_id"] == vx_loop_id:
        add = 1
        return i["ip2"]
  if add == 0:
    return(vxlan_loopback_ip_addr_generation(vx_loop_id))
    
def vxlan_loopback_ip_addr_generation(vx_loop_id):
    octect1 = 10
    octect2 = random.randint(0, 255)
    octect3 = random.randint(0, 255)
    octect4 = random.randrange(0, 255, 2)
    ipaddr = []
    loopbackip1 = f"{octect1}.{octect2}.{octect3}.{octect4}/31"
    octect4 += 1
    loopbackip2 = f"{octect1}.{octect2}.{octect3}.{octect4}/31"
    for i in col_vxlan_loopaddr.find():
       if i["ip1"] == loopbackip1:
         vxlan_loopback_ip_addr_generation()
    col_vxlan_loopaddr.insert_one({ "loop_id":vx_loop_id, "ip1":loopbackip1, "ip2":loopbackip2})
    return loopbackip1

#-------------------------------------------------------------------------------------------------------
# Loopback IP Address Generation for GRE Tunnel
def gre_loopback_ip_addr(gre_loop_id):
  add = 0
  for i in col_gre_loopaddr.find():
    if i["loop_id"] == gre_loop_id:
        add = 1
        return i["ip2"]
  if add == 0:
    return(gre_loopback_ip_addr_generation(gre_loop_id))

  
def gre_loopback_ip_addr_generation(gre_loop_id):  
    octect1 = 172
    octect2 = random.randint(16, 31)
    octect3 = random.randint(0, 255)
    octect4 = random.randrange(0, 255, 2)
    ipaddr = []
    loopbackip1 = f"{octect1}.{octect2}.{octect3}.{octect4}/31"
    octect4 += 1
    loopbackip2 = f"{octect1}.{octect2}.{octect3}.{octect4}/31"
    for i in col_gre_loopaddr.find():
       if i["ip1"] == loopbackip1:
         gre_loopback_ip_addr_generation()
    col_gre_loopaddr.insert_one({ "loop_id":gre_loop_id, "ip1":loopbackip1, "ip2":loopbackip2})
    return loopbackip1

def vxlan_loopback_remote_addr(local):
  for i in col_vxlan_loopaddr.find():
    if i["ip1"] == local:
        return i["ip2"]
    if i["ip2"] == local:
        return i["ip1"]

#-----------------------------------------------------------------------------------------------------------
#MAC Address Generation  for Loopback Interface
    
def mac_address_generation():
    mac = [random.randint(0x00,0xff), random.randint(0x00,0xff), random.randint(0x00,0xff), random.randint(0x00,0xff), random.randint(0x00,0xff), random.randint(0x00,0xff)]
    mac_string = ':'.join(map(lambda x:"%02x"%x,mac))
    for i in col_mac.find({},{'_id':0}):
       if mac_string == i["mac"]:
          mac_address_generation()
    col_mac.insert_one({ "mac":mac_string})   
    return(mac_string)
    
#------------------------------------------------------------------------------------------------------------
#Encryption Key Generation For AES in Ipec   
def crypto_key_generation():
    key = secrets.token_hex(32)
    for i in col_cryptokeys.find({},{'_id':0}):
        if key == i["keys"]:
           crypto_key_generation()
    col_cryptokeys.insert_one({"keys": key})
    return key
#--------------------------------------------------------------------------------------------------------------
#Integrity Key Generation for SHA in Ipsec
def integ_key_generation():
    key = secrets.token_hex(40)
    for i in col_integkeys.find({},{'_id':0}):
        if key == i["keys"]:
           crypto_key_generation()
    col_integkeys.insert_one({"keys": key})
    return key    

#-----------------------------------------------------------------------------------------------------------------
#VXLAN Tunnel Setup
   
@app.route('/interface_name', methods = ['POST'])  
def vxlan_setup():
    data = request.json
    response = {"message":"successfull"}
    x = col.find_one()
    loopback_instance = x["loopback_instance"]
    bridge_instance = x["bridge_instance"]
    vxlan_instance = x["vxlan_instance"]
    gre_instance = x["gre_instance"]
    
       
    sain_check = 0
    saout_check = 0
    for i in col_ipsec_sa.find({}, {'-id':0}):
       if i["sa_id"] == data["sa_in"]:
         ck1 = bytes.fromhex(i["crypto_key"])
         ik1=bytes.fromhex(i["integrity_key"])
         sain_check = 1
       elif i["sa_id"] == data["sa_out"]:
         ck2=bytes.fromhex(i["crypto_key"])
         ik2=bytes.fromhex(i["integrity_key"])
         saout_check = 1
    
    if sain_check == 0:
        key_crypto_in_spi = crypto_key_generation()
        key_integ_in_spi = integ_key_generation()
        ck1 = bytes.fromhex(key_crypto_in_spi)
        ik1=bytes.fromhex(key_integ_in_spi)
        col_ipsec_sa.insert_one({ "sa_id":data["sa_in"], "spi_in":data["spi_in"], "crypto_key":key_crypto_in_spi, "integrity_key":key_integ_in_spi })
    if saout_check == 0:
        key_crypto_out_spi = crypto_key_generation()
        key_integ_out_spi = integ_key_generation()
        ck2=bytes.fromhex(key_crypto_out_spi)
        ik2=bytes.fromhex(key_integ_out_spi)
        col_ipsec_sa.insert_one({ "sa_id":data["sa_out"], "spi_in":data["spi_out"], "crypto_key":key_crypto_out_spi, "integrity_key":key_integ_out_spi })
  
      

    vpp.api.ipsec_sad_entry_add_del_v2(entry = {"sad_id":data["sa_in"], "spi":data["spi_in"], "protocol":50, "crypto_algorithm":1, "crypto_key":{ "length":16, "data":ck1}, "integrity_algorithm":2, "integrity_key":{ "length":20, "data":ik1 }}, is_add=1)
    vpp.api.ipsec_sad_entry_add_del_v2(entry = {"sad_id":data["sa_out"], "spi":data["spi_out"], "protocol":50, "crypto-algorithm":1, "crypto_key":{"length":16, "data":ck2}, "integrity_algorithm":2, "integrity_key":{"length":20, "data":ik2}}, is_add=1)

    vx_loop_addr = vxlan_loopback_ip_addr(data["vx_loop_id"])
    
    loip = IPv4Interface(vx_loop_addr)
    vx_lc_loop_addr = loip.ip
    
    reip = IPv4Interface(vxlan_loopback_remote_addr(vx_loop_addr))
    vx_re_addr = reip.ip
    gr_loop_addr = gre_loopback_ip_addr(data["vx_loop_id"])
    greip = IPv4Interface(gr_loop_addr)
    gre_addr = greip.ip
  
    vx_mac_addr= mac_address_generation()
    gr_mac_addr = mac_address_generation()
    sa_ini = data["sa_in"]
    sa_inl = [sa_ini]
      
#creating loopback interface for vxlan
    loopback_instance +=1
    loopvxlan = vpp.api.create_loopback_instance(mac_address=vx_mac_addr, is_specified=1, user_instance=loopback_instance)
    vpp.api.sw_interface_set_flags(sw_if_index=loopvxlan.sw_if_index, flags=3)
    vpp.api.sw_interface_add_del_address(sw_if_index=loopvxlan.sw_if_index, is_add=1, prefix=vx_loop_addr)
    

#vxlan tunnel creation
    vxlan_instance +=1
    vxtunnel = vpp.api.vxlan_add_del_tunnel_v2(src_address=data["vxlan_src_ip"], dst_address=data["vxlan_dst_ip"], vni=24, is_add=1, decap_next_index=1, instance=vxlan_instance)

#bridge domain creation
    bridge_instance +=1
    vpp.api.bridge_domain_add_del(bd_id=bridge_instance, flood=1, learn=1, uu_flood=1, forward=1, arp_term=0)

#set loopback to bridge as bvi
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=loopvxlan.sw_if_index, bd_id=bridge_instance, shg=0, enable=1, port_type=1)

#set vxlan tunnel to bridge as 1
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=vxtunnel.sw_if_index, bd_id=bridge_instance, shg=1, enable=1)
  
#creating loopback interface for gre
    loopback_instance +=1
    loopgre = vpp.api.create_loopback_instance(mac_address=gr_mac_addr, is_specified=1, user_instance=loopback_instance)
    vpp.api.lcp_itf_pair_add_del(is_add=1, sw_if_index=loopgre.sw_if_index, host_if_type=0, host_if_name="loopgre", netns="dataplane")
    vpp.api.sw_interface_set_flags(sw_if_index=loopgre.sw_if_index, flags=3)
    vpp.api.sw_interface_add_del_address(sw_if_index=loopgre.sw_if_index, is_add=1, prefix=gr_loop_addr)
    vpp.api.lcp_itf_pair_add_del(is_add=1, sw_if_index=loopgre.sw_if_index, host_if_type=0, host_if_name="loopgre", netns="dataplane")
    
#bridge domain creation
    bridge_instance +=1
    vpp.api.bridge_domain_add_del(bd_id=bridge_instance, flood=1, learn=1, uu_flood=1, forward=1, arp_term=1)

#create gre tunnel
    gre_instance +=1
    gretunnel = vpp.api.gre_tunnel_add_del(tunnel = {"src":vx_lc_loop_addr, "dst":vx_re_addr, "type":1, "mode":0, "instance":gre_instance}, is_add=1)
    vpp.api.sw_interface_set_flags(sw_if_index=gretunnel.sw_if_index, flags=3)

#protect gre tunnel by ipsec
   
    vpp.api.ipsec_tunnel_protect_update(tunnel = {"sw_if_index":gretunnel.sw_if_index, "sa_in":sa_inl, "sa_out":data["sa_out"], "n_sa_in":1})

#set gre1 to bridge 2 as shg 1
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=gretunnel.sw_if_index, bd_id=bridge_instance, shg=1, enable=1)
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=loopgre.sw_if_index, bd_id=bridge_instance, shg=0, enable=1, port_type=1) 
    
# delete the old database and add new one
    col.delete_many({})
    col.insert_one({ "loopback_instance":loopback_instance, "bridge_instance":bridge_instance, "vxlan_instance":vxlan_instance, "gre_instance":gre_instance })

# frr configuration
    broad_addr = data["broadcast_lan_address"]
    with open("/etc/frr/frr.conf", "a") as f:
      f.write(f"\n!\nrouter ospf\n network {gre_addr} area 0\n network {broad_addr} area 0\nexit\n!")
    os.system(f"sudo service frr restart")
    return jsonify(response), 200

#------------------------------------------------------------------------------------------------------------------
#Machine-ID - INFO

@app.route('/machine_id')
def get_machine_id():
    with open('/etc/machine-id', 'r') as f:
        return {'machine_id': f.read().strip()}

#------------------------------------------------------------------------------------------------------------------
#VPP Interface - INFO
@app.route('/vpp_interface_details')  
def get_interface_details():
    iface_list = vpp.api.sw_interface_dump()
    data = []
    int_ip = []
    for iface in iface_list:
        iface_ip = vpp.api.ip_address_dump(sw_if_index=iface.sw_if_index, is_ipv6=0)
        for intip in iface_ip:
          int_ip = intip.prefix 
        
        colect = { "int_index":iface.sw_if_index, "int_mac_address":str(iface.l2_address), "int_speed":iface.link_speed, "int_link_mtu":iface.link_mtu, "int_ipv4_address":str(int_ip), "int_name":iface.interface_name, "int_mtu":iface.mtu[0], "int_status":iface.flags }
        data.append(colect)
    
    return data
#--------------------------------------------------------------------------------------------------------------------
#GRE Tunnel - INFO

@app.route('/gre_details')   
def get_gre_details():
	iface_list = vpp.api.gre_tunnel_dump()
	data = []
	for li in iface_list:
		for det in li:
			if(isinstance(det, tuple)):
				print("src-address=%s dst-address=%s instance=%d type=%s" %(det[7], det[8], det[4], det[0]))
				colect = {"src-address":str(det[7]), "dst-address":str(det[8]), "instance":det[4], "type":det[0]}
				data.append(colect)
	return data
#-----------------------------------------------------------------------------------------------------------------
#Vxlan Tunnel - INFO

@app.route('/vxlan_details')   
def get_vxlan_details():
    iface_list = vpp.api.vxlan_tunnel_v2_dump()
    data = []
    for iface in iface_list:
        colect = {"src-address":str(iface.src_address), "dst-address":str(iface.dst_address), "mcast_index":iface.mcast_sw_if_index, "encap-vrf-id":iface.encap_vrf_id, "vni":iface.vni, "decap-index":iface.decap_next_index}
        data.append(colect)
        print("idx=%d src-address=%s dst-address=%s mcast_index=%d encap-vrf-id=%d vni=%d decap-index=%d" % (iface.sw_if_index,
                iface.src_address, iface.dst_address, iface.mcast_sw_if_index, iface.encap_vrf_id, iface.vni, iface.decap_next_index))
    return data
#------------------------------------------------------------------------------------------------------------------
#Ipsec Tunnel - INFO
@app.route('/ipsec_details')   
def get_ipsec_details():
    tun_protect = vpp.api.ipsec_tunnel_protect_dump()
    data = []
    for iface in tun_protect:
        
        for ip in iface:
            if(isinstance(ip, tuple)):
                
                li = ip[4]
                print(li)
                colect = {"tunnel-id":ip[0], "sa-in":li[0], "sa-out":ip[2]}
                data.append(colect)
                print("tunnel-id=%s sa-out=%d, sa-in=%d" % (ip[0], ip[2], li[0]))
    return data   
#------------------------------------------------------------------------------------------------------------------------------------------
#FRR Routing Table - INFO    
@app.route('/routing_table')
def get_frr_routing_table():
    # Run the frr CLI command to get the routing table information
    output = subprocess.check_output(["vtysh", "-c", "show ip route"]).decode("utf-8")
    # Split the output into lines
    lineso = output.split("\n")
   # print(lineso)
    lines = lineso[7:]
    print(lines)
    linesn = lines[:-1]
    print(linesn)
    # Initialize a list to store the routing table entries  
    routing_table = []
    # Loop through the lines
    for line in linesn:
        # Split the line into columns
        columns = line.split()
        print(columns)
        # If the line contains information about a routing table entry
        dummy = columns[0]
        print(dummy)
        if 'K>*' in dummy :
        
            # Extract the desired information from the columns
            gateway = columns[4]
            #print(gateway)
            destination = columns[1]
            metric = columns[2]
            protocol = "Kernel Route"
            interface = columns[5]
            # Append the routing table entry to the list of entries
            
        elif 'K' in dummy :
                    # Extract the desired information from the columns
            gateway = columns[5]
            #print(gateway)
            destination = columns[2]
            metric = columns[3]
            protocol = "Kernel Route"
            interface = columns[6]
            # Append the routing table entry to the list of entries
            
           
        elif 'C>*' in dummy :
                    # Extract the desired information from the columns
            gateway = columns[3]
            #print(gateway)
            destination = columns[1]
            metric = columns[3]
            protocol = "Directly Connected"
            interface = columns[5]
           
        elif 'C' in dummy :
                    # Extract the desired information from the columns
            gateway = columns[4]
            #print(gateway)
            destination = columns[2]
            metric = columns[4]
            protocol = "Directly Connected"
            interface = columns[6]
            # Append the routing table entry to the list of entries
        
        elif 'O>*' in dummy :
                    # Extract the desired information from the columns
            gateway = columns[4]
            #print(gateway)
            destination = columns[1]
            metric = columns[2]
            protocol = "OSPF"
            interface = columns[5]
            # Append the routing table entry to the list of entries
            
        elif 'O' in dummy :
                    # Extract the desired information from the columns
            gateway = columns[4]
            #print(gateway)
            destination = columns[1]
            metric = columns[2]
            protocol = "OSPF"
            interface = columns[6]
            # Append the routing table entry to the list of entries   
            
        routing_table.append({
                "gateway": str(gateway),
                "destination": str(destination),
                "metric": metric,
                "protocol": str(protocol),
                "interface": str(interface)
            })
    # Return the list of routing table entries
     # Connect to the MongoDB database
    #client = pymongo.MongoClient("mongodb://localhost:27017")
    #db = client["reach_manage"]
    #collection = db["frrrouting"]
    # Insert the routing table entries into the MongoDB database
    #collection.delete_many({})
    #for entry in routing_table:
     #   collection.insert_one(entry)
    
    return routing_table

   

machine_id_json = json.dumps(get_machine_id())
interface_details_json = json.dumps(get_interface_details())
gre_details_json = json.dumps(get_gre_details())
vxlan_details_json = json.dumps(get_vxlan_details())
ipsec_details_json = json.dumps(get_ipsec_details())
routing_details_json = json.dumps(get_frr_routing_table())	

#--------------------------------------------------------------------------------------------------------------------------------------------
#Delete vxlan tunnel
@app.route('/vxlan_delete', methods = ['POST'])  
def vxlan_delete():
    data = request.json
    response = {"message":"successfull"}
    vxtunnel = vpp.api.vxlan_add_del_tunnel_v2(src_address=data["vxlan_src_ip"], dst_address=data["vxlan_dst_ip"], vni=24, is_add=0)
    return jsonify(response), 200
    
    
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


