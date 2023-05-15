from flask import Flask, request, jsonify
import pyufw as ufw
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
import time
from ipaddress import IPv4Interface
import netaddr
from netaddr import IPAddress
import pyufw as ufw
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
client1 = pymongo.MongoClient("mongodb://10.8.0.1:27017/")
#client1 = pymongo.MongoClient("mongodb+srv://bavya:bavya23@cluster0.xxummtw.mongodb.net/?retryWrites=true&w=majority", server_api=ServerApi('1')) 

#-----------------------------------------------------------------------------------------------------------------
#local database for vxlan details
db_vxlan = client["vxlan"]
col_vxlan_details = db_vxlan ["vxlan_details"]

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
        if "default" in line:
            gateway = line.split()[4]
            interface_name = line.split()[6]
            no = 0
         		
    cmd = "ifconfig -a"
    output = subprocess.check_output(cmd, shell=True, universal_newlines=True)
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
                       ipaddress = parts[1]
                       slash = "/"
                       ipaddr_prefix = ipaddress+slash+str(prefixlength)
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
                     if "default" in line1:
                       
                      
                       if current_interface == line1.split()[6]:
                         netmask =parts[3]
                         prefixlength = IPAddress(netmask).netmask_bits()
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
                   
                   if num == 1:
                       netmask =parts[3]
                       prefixlength = IPAddress(netmask).netmask_bits()
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
                   collect.update({"mac_addr":parts[1]})
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
    octect3 = random.randint(1, 255)
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
        
def gre_loopback_remote_addr(local):
  for i in col_gre_loopaddr.find():
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
   
@app.route('/tunnel_data', methods = ['POST'])  
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
    for i in col_ipsec_sa.find({}, {'_id':0}):
       if i["sa_id"] == data["sa_in"]:
         ck1 = bytes.fromhex(i["crypto_key"])
         ik1=bytes.fromhex(i["integrity_key"])
         sain_check = 1
    for i in col_ipsec_sa.find({}, {'_id':0}):
       if i["sa_id"] == data["sa_out"]:
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

    sa_inn = data["sa_in"]
    sa_outn = data["sa_out"]
    if saout_check == 1:
       sa_inn, sa_outn = sa_outn, sa_inn

    vx_loop_addr = vxlan_loopback_ip_addr(data["vx_loop_id"])
    
    loip = IPv4Interface(vx_loop_addr)
    vx_lc_loop_addr = loip.ip
    
    reip = IPv4Interface(vxlan_loopback_remote_addr(vx_loop_addr))
    vx_re_addr = reip.ip
    gr_loop_addr = gre_loopback_ip_addr(data["vx_loop_id"])
    greip = IPv4Interface(gr_loop_addr)
    gre_addr = str(greip.ip)+"/32"
    gre_remote_ip = gre_loopback_remote_addr(gr_loop_addr)
  
    vx_mac_addr= mac_address_generation()
    gr_mac_addr = mac_address_generation()
    
    sa_inl = [sa_inn]
      
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
    vpp.api.bridge_domain_add_del_v2(bd_id=bridge_instance, flood=1, learn=1, uu_flood=1, forward=1, arp_term=0)

#set loopback to bridge as bvi
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=loopvxlan.sw_if_index, bd_id=bridge_instance, shg=0, enable=1, port_type=1)

#set vxlan tunnel to bridge as 1
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=vxtunnel.sw_if_index, bd_id=bridge_instance, shg=1, enable=1)
  
#creating loopback interface for gre
    loopback_instance +=1
    loopgre = vpp.api.create_loopback_instance(mac_address=gr_mac_addr, is_specified=1, user_instance=loopback_instance)
    vpp.api.lcp_itf_pair_add_del(is_add=1, sw_if_index=loopgre.sw_if_index, host_if_type=0, host_if_name="gre", netns="dataplane")
    vpp.api.sw_interface_set_flags(sw_if_index=loopgre.sw_if_index, flags=3)
    vpp.api.sw_interface_add_del_address(sw_if_index=loopgre.sw_if_index, is_add=1, prefix=gr_loop_addr)
    #vpp.api.lcp_itf_pair_add_del(is_add=1, sw_if_index=loopgre.sw_if_index, host_if_type=0, host_if_name="loopgre", netns="dataplane")
    
#bridge domain creation
    bridge_instance +=1
    vpp.api.bridge_domain_add_del_v2(bd_id=bridge_instance, flood=1, learn=1, uu_flood=1, forward=1, arp_term=1)

#create gre tunnel
    gre_instance +=1
    gretunnel = vpp.api.gre_tunnel_add_del(tunnel = {"src":vx_lc_loop_addr, "dst":vx_re_addr, "type":1, "mode":0, "instance":gre_instance}, is_add=1)
    vpp.api.sw_interface_set_flags(sw_if_index=gretunnel.sw_if_index, flags=3)

#protect gre tunnel by ipsec
   
    vpp.api.ipsec_tunnel_protect_update(tunnel = {"sw_if_index":gretunnel.sw_if_index, "sa_in":sa_inl, "sa_out":sa_outn, "n_sa_in":1})

#set gre1 to bridge 2 as shg 1
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=gretunnel.sw_if_index, bd_id=bridge_instance, shg=1, enable=1)
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=loopgre.sw_if_index, bd_id=bridge_instance, shg=0, enable=1, port_type=1) 
#add the tunnel details in database    
    col_vxlan_details.insert_one({"src_address":data["vxlan_src_ip"], "dst_address":data["vxlan_dst_ip"], "src_loopback_addr":gr_loop_addr, "dst_loopback_addr":gre_remote_ip,"gre_bridge_id":bridge_instance, "status":"connected", "encrypt":"PSK" })
    
# delete the old database and add new one
    col.delete_many({})
    col.insert_one({ "loopback_instance":loopback_instance, "bridge_instance":bridge_instance, "vxlan_instance":vxlan_instance, "gre_instance":gre_instance })

# frr configuration
    lan_addr = data["lan_address"]
    with open("/etc/frr/frr.conf", "a") as f:
      f.write(f"\n!\nrouter ospf\n network {gre_addr} area 0\n network {lan_addr} area 0\nexit\n!")
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
        
    return data
#------------------------------------------------------------------------------------------------------------------
@app.route('/vxlan_tunnel_details')   
def vxlan_details():
    data= []
    tunnel_details = col_vxlan_details.find({},{'_id':0})
    iface_list = vpp.api.vxlan_tunnel_v2_dump()
    for i in tunnel_details:
      for iface in iface_list:
        if str(iface.dst_address) == i["dst_address"]:
          if str(iface.src_address) == i["src_address"]:
             output = subprocess.check_output(["vtysh", "-c", "show ip ospf ne"]).decode("utf-8")
             out = output.split("\n")
             out1 = out[2:-2]
             
             for j in out1:
               li = j.split()
               ne = i["dst_loopback_addr"]
               ne = ne.split("/")
               if li[5] == ne[0]:
                  data.append(i)
    return (data)

#------------------------------------------------------------------------------
#Ipsec Tunnel - INFO
@app.route('/ipsec_details')   
def get_ipsec_details():
    tun_protect = vpp.api.ipsec_tunnel_protect_dump()
    data = []
    for iface in tun_protect:
        
        for ip in iface:
            if(isinstance(ip, tuple)):
                li = ip[4]
                colect = {"tunnel-id":ip[0], "sa-in":li[0], "sa-out":ip[2]}
                data.append(colect)
                
    return data   
#------------------------------------------------------------------------------------------------------------------------------------------
#FRR Routing Table - INFO    
@app.route('/routing_table')
def get_frr_routing_table():
    # Run the frr CLI command to get the routing table information
    output = subprocess.check_output(["vtysh", "-c", "show ip route"]).decode("utf-8")
    # Split the output into lines
    lineso = output.split("\n")
   
    linesn = lineso[7:-1]
    
    #Initialize a list to store the routing table entries  
    routing_table = []
    # Loop through the lines
    for line in linesn:
        # Split the line into columns
        columns = line.split()
        
        # If the line contains information about a routing table entry
        routing_type = columns[0]
        
  # Extract the desired information from the columns
        if 'K>*' in routing_type :
        

            gateway = columns[4]
            destination = columns[1]
            metric = columns[2]
            protocol = "Kernel Route"
            interface = columns[5]
            
            
        elif 'S' in routing_type :
            
            gateway = columns[5]
            destination = columns[2]
            metric = columns[3]
            protocol = "static Route"
            interface = columns[6]
            
            
           
        elif 'C>*' in routing_type:
            
            gateway = columns[3]
            destination = columns[1]
            metric = columns[3]
            protocol = "Directly Connected"
            interface = columns[5]
           
        elif 'C' in routing_type :
            
            gateway = columns[4]
            destination = columns[2]
            metric = columns[4]
            protocol = "Directly Connected"
            interface = columns[6]
            
        
        elif 'O>*' in routing_type :
            
            gateway = columns[4]
            destination = columns[1]
            metric = columns[2]
            protocol = "OSPF"
            interface = columns[5]
            
            
        elif 'O' in routing_type :
                    
            gateway = columns[4]
            destination = columns[1]
            metric = columns[2]
            protocol = "OSPF"
            interface = columns[6]
            
            
        routing_table.append({
                "gateway": str(gateway),
                "destination": str(destination),
                "metric": metric,
                "protocol": str(protocol),
                "interface": str(interface)
            })
        
    return routing_table

   


#--------------------------------------------------------------------------------------------------------------------------------------------
#Delete vxlan tunnel
@app.route('/vxlan_delete', methods = ['DELETE'])  
def vxlan_delete():
    vxlan_src_ip = request.args.get('vxlan_src_ip')
    vxlan_dst_ip = request.args.get('vxlan_dst_ip')
    response = {"message":"successfull"}
    vpp.api.vxlan_add_del_tunnel_v2(src_address=vxlan_src_ip, dst_address=vxlan_dst_ip, vni=24, is_add=0)
    return jsonify(response), 200
    
#----------------------------------------------------------------------------------------------------------------------------------
# function to insert outbound rule in ACL
@app.route('/outbound_aclrule', methods = ['POST'])  
def outbound_rule():
        data = request.json
        response = {"message":"successfull"}
        acl_add = subprocess.check_output(["sudo", "vppctl", "set", "acl-plugin", "acl", data["action"], "src", data["source"], "dst", data["destination"], "sport", data["src_port"], "dport", data["dst_port"], "proto", data["protocol"], ",", "permit", "src", "any", "dst", "any"]).decode("utf-8")
        acl_ind = acl_add.split(":")[1]
        #os.system(f"sudo vppctl set acl-plugin acl {data['action']} src {data['source']} dst {data['destination']}, proto {data['protocol']} sport {data['sport_range']}, dport {data['dport_range']}, permit src any dst any")
        acl_int = vpp.api.acl_interface_add_del(is_add=1, is_input=0, sw_if_index=data["int_index"], acl_index=int(acl_ind))
        return jsonify(response), 200
        
# function to insert outbound rule in ACL
@app.route('/inbound_aclrule', methods = ['POST'])  
def inbound_rule():
        data = request.json
        response = {"message":"successfull"}
        acl_add = subprocess.check_output(["sudo", "vppctl", "set", "acl-plugin", "acl", data["action"], "src", data["source"], "dst", data["destination"], "sport", data["src_port"], "dport", data["dst_port"], "proto", data["protocol"], ",", "permit", "src", "any", "dst", "any"]).decode("utf-8")
        acl_ind = acl_add.split(":")[1]
        #os.system(f"sudo vppctl set acl-plugin acl {data['action']} src {data['source']} dst {data['destination']}, proto {data['protocol']} sport {data['sport_range']}, dport {data['dport_range']}, permit src any dst any")
        acl_int = vpp.api.acl_interface_add_del(is_add=1, is_input=1, sw_if_index=data["int_index"], acl_index=int(acl_ind))
        return jsonify(response), 200


#----------------------------------------------------------------------------------------------------------------------------------
@app.route('/acl_status')  
def acl_status():
  i = 0
  data = []
  for i in range(100):
    stat = vpp.api.acl_dump(acl_index=i)
    if stat != []:
     rule = stat[0].r
     protocol = (rule[0].proto).value
     if protocol == 0:
       proto = "HOPOPT"
     elif protocol == 1:
       proto = "ICMP"
     elif protocol == 2:
       proto = "IGMP"
     elif protocol == 6:
      proto = "TCP"
     elif protocol == 17:
      proto = "UDP"
     elif protocol == 47:
      proto = "GRE"
     elif protocol == 50:
      proto = "ESP"
     elif protocol == 51:
      proto = "AH"
     elif protocol == 58:
      proto = "ICMP6"
     elif protocol == 88:
      proto = "EIGRP"
     elif protocol == 89:
       proto = "OSPF"
     elif protocol == 132:
       proto = "SCTP"
     elif protocol == 255:
       proto = "Reserved"

     act = (rule[0].is_permit).value
     if act == 0:
       action = "deny"
     elif act == 1:
       action = "permit"
     elif act ==2:
       action = "permit+reflect"
     if rule[0].srcport_or_icmptype_first == rule[0].srcport_or_icmptype_last:
       src_port = rule[0].srcport_or_icmptype_first
     else:
       src_port = str(rule[0].srcport_or_icmptype_first)+"-"+ str(rule[0].srcport_or_icmptype_last)
     if rule[0].dstport_or_icmpcode_first == rule[0].dstport_or_icmpcode_last:
       dst_port = rule[0].dstport_or_icmpcode_first
     else:
        dst_port = str(rule[0].dstport_or_icmpcode_first) + "-" + str(rule[0].dstport_or_icmpcode_last)
        colect = {"acl_index":i, "action":action, "src_port":src_port, "dst_port":dst_port, "source":rule[0].src_prefix, "destination":rule[0].dst_prefix, "protocol": proto}
  
    
     data.append(colect)
     i += 1 
    else:
      return data
#----------------------------------------------------------------------------------------------------------------------------------



#----------------------------------------------------------------------------------------------------------------------------------
# function to implement qos via policy based classification
@app.route('/qos_policy_add', methods = ['POST'])  
def qos_policy_add():
  data = request.json
  response = {'message':'successfull'}
  vpp.api.policer_add_del(is_add=1, name=data["policy_name"], conform_action={"type":2, "dscp":data["dscp"]})
  vpp.api.policer_input(name=data["policy_name"], sw_if_index=1, apply=1)
  vpp.api.policer_output(name=data["policy_name"], sw_if_index=1, apply=1)
  vpp.api.sw_interface_set_tx_placement(sw_if_index=data["int_index"], queue_id=data["queue_id"])
  vpp.api.sw_interface_set_rx_placement(sw_if_index=data["int_index"], queue_id=data["queue_id"])
  vpp.api.classify_add_del_sessions(is_add=1, table_index=0, hit_next_index=1, match_len=len(data["match"]), match = str.encode(data["match"]), opaque_index=1)
  vpp.api.qos_record_enable_disable(enable=1, record={"sw_if_index":data["int_index"], "input_source":3})
  vpp.api.qos_mark_enable_disable(enable=1, mark={"sw_if_index":data["int_index"], "output_source":3})
  return jsonify(response), 200
  
  
if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)


