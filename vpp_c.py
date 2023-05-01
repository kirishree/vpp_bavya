from vpp_papi import VPPApiClient
import os
import fnmatch
import sys
import pymongo
from pymongo.server_api import ServerApi
import secrets
import random
import binascii
import ipaddress
from ipaddress import IPv4Interface

client1 = pymongo.MongoClient("mongodb+srv://bavya:bavya23@cluster0.xxummtw.mongodb.net/?retryWrites=true&w=majority", server_api=ServerApi('1')) 
client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["database"]
col = db["instance_list"]

db_ipsec = client1["ipsec_key"]
col_ipsec_sa = db_ipsec["sa_table"]

db_mac = client1["mac_address"]
col_mac = db_mac["mac_list"]

col_cryptokeys = db_ipsec["crypto_keys"]
col_integkeys = db_ipsec["integ_keys"]

db_loopback = client1["loopback_address"]
col_vxlan_loopaddr = db_loopback["vxlan_loop_addr"]
col_gre_loopaddr = db_loopback["gre_loop_addr"]
vpp_json_dir = '/usr/share/vpp/api/'

# construct a list of all the json api files
jsonfiles = []
for root, dirnames, filenames in os.walk(vpp_json_dir):
  for filename in fnmatch.filter(filenames, '*.api.json'):
    jsonfiles.append(os.path.join(root, filename))

vpp = VPPApiClient(apifiles=jsonfiles, server_address='/run/vpp/api.sock')
vpp.connect("test-client")

v = vpp.api.show_version()
print('VPP version is %s' % v.version)
def vxlan_loopback_ip_addr():
  add = 0
  print("enter the vxlan loopback address id")
  vx_loop_id = input()
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
    
def gre_loopback_ip_addr():
  add = 0
  print("enter the gre loopback address id")
  gre_loop_id = input()
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

def wan_intf_setup():
   print("enter local wan int name")
   int_name = input()
   print("enter local gateway")
   local_gateway = input()
   print("enter local private ip witn netmask ex: 192.168.1.150/24")
   local_ip = input()
   iface_list = vpp.api.sw_interface_dump()
   for iface in iface_list:
    if(iface.interface_name==int_name):
       index_int=iface.sw_if_index
   if(index_int>0):
    vpp.api.sw_interface_set_flags(sw_if_index=index_int, flags=3)
    vpp.api.sw_interface_add_del_address(sw_if_index=index_int, is_add=1, prefix=local_ip)
    os.system(f"sudo vppctl ip route add 0.0.0.0/0 via {local_gateway}")
   else:
    print("Not found") 
    
    
def mac_address_generation():
    mac = [random.randint(0x00,0xff), random.randint(0x00,0xff), random.randint(0x00,0xff), random.randint(0x00,0xff), random.randint(0x00,0xff), random.randint(0x00,0xff)]
    mac_string = ':'.join(map(lambda x:"%02x"%x,mac))
    for i in col_mac.find({},{'_id':0}):
       if mac_string == i["mac"]:
          mac_address_generation()
    col_mac.insert_one({ "mac":mac_string})   
    return(mac_string)

def vxlan_setup():
    x = col.find_one({},{'_id':0, 'loopback_instance':1})
    for i in x:
      loopback_instance = x[i]
    x = col.find_one({},{'_id':0, 'bridge_instance':1})
    for i in x:
      bridge_instance = x[i]
    x = col.find_one({},{'_id':0, 'vxlan_instance':1})
    for i in x:
      vxlan_instance = x[i]
    x = col.find_one({},{'_id':0, 'gre_instance':1})
    for i in x:
      gre_instance = x[i]
    
       
    #print("Enter the loopback address for vxlan tunnel with subnet mask Ex: 10.1.0.6/24")
    vx_loop_addr = vxlan_loopback_ip_addr()
    #print("enter the loopback address for local vxlan tunnel without subnetmask Ex: 10.1.0.6")
    loip = IPv4Interface(vx_loop_addr)
    vx_lc_loop_addr = loip.ip
    #print("Enter the remote loopback address for vxlan tunnel with out subnet mask Ex: 10.1.0.7")
    reip = IPv4Interface(vxlan_loopback_remote_addr(vx_loop_addr))
    vx_re_addr = reip.ip
    #print("Enter the loopback address for Gre tunnel")
    gr_loop_addr = gre_loopback_ip_addr()
    
  
    vx_mac_addr= mac_address_generation()
    gr_mac_addr = mac_address_generation()
    print("enter the local ip for vxan tunnel")
    local_ipl = input()
    print("enter the remote ip for vxlan tunnel")
    remote_ip = input()
    print("enter the sa-in value in ipsec")
    sa_ini = int(input())
    sa_inl = [sa_ini]
    print("enter the sa-out value in ipsec")
    sa_out =int(input())
    
#creating loopback interface for vxlan
    loopback_instance +=1
    loopvxlan = vpp.api.create_loopback_instance(mac_address=vx_mac_addr, is_specified=1, user_instance=loopback_instance)
    vpp.api.sw_interface_set_flags(sw_if_index=loopvxlan.sw_if_index, flags=3)
    vpp.api.sw_interface_add_del_address(sw_if_index=loopvxlan.sw_if_index, is_add=1, prefix=vx_loop_addr)
    

#vxlan tunnel creation
    vxlan_instance +=1
    vxtunnel = vpp.api.vxlan_add_del_tunnel_v2(src_address=local_ipl, dst_address=remote_ip, vni=24, is_add=1, decap_next_index=1, instance=vxlan_instance)

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
    #vpp.api.lcp_itf_pair_add_del(is_add=1, sw_if_index=loopgre.sw_if_index, host_if_type=0, host_if_name="loopgre", netns="dataplane")
    
#bridge domain creation
    bridge_instance +=1
    vpp.api.bridge_domain_add_del(bd_id=bridge_instance, flood=1, learn=1, uu_flood=1, forward=1, arp_term=1)

#create gre tunnel
    gre_instance +=1
    gretunnel = vpp.api.gre_tunnel_add_del(tunnel = {"src":vx_lc_loop_addr, "dst":vx_re_addr, "type":1, "mode":0, "instance":gre_instance}, is_add=1)
    vpp.api.sw_interface_set_flags(sw_if_index=gretunnel.sw_if_index, flags=3)

#protect gre tunnel by ipsec
   
    vpp.api.ipsec_tunnel_protect_update(tunnel = {"sw_if_index":gretunnel.sw_if_index, "sa_in":sa_inl, "sa_out":sa_out, "n_sa_in":1})

#set gre1 to bridge 2 as shg 1
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=gretunnel.sw_if_index, bd_id=bridge_instance, shg=1, enable=1)
    vpp.api.sw_interface_set_l2_bridge(rx_sw_if_index=loopgre.sw_if_index, bd_id=bridge_instance, shg=0, enable=1, port_type=1) 
    
# delete the old database and add new one
    col.delete_many({})
    col.insert_one({ "loopback_instance":loopback_instance, "bridge_instance":bridge_instance, "vxlan_instance":vxlan_instance, "gre_instance":gre_instance })

def crypto_key_generation():
    key = secrets.token_hex(32)
    for i in col_cryptokeys.find({},{'_id':0}):
        if key == i["keys"]:
           crypto_key_generation()
    col_cryptokeys.insert_one({"keys": key})
    return key
    
def integ_key_generation():
    key = secrets.token_hex(40)
    for i in col_integkeys.find({},{'_id':0}):
        if key == i["keys"]:
           crypto_key_generation()
    col_integkeys.insert_one({"keys": key})
    return key
   
def ipsecsa_setup():
    #key_collections = col_ipsec.find_many({},{'_id':0})
    print("enter the sa-in id value want to create")
    sa_in = int(input())
    print("enter tha sa-out id value want to create")
    sa_out = int(input())
    print("enter the spi-in id value want to create")
    spi_in = input()
    print("enter tha spi-out id value want to create")
    spi_out = input()
    sain_check = 0
    saout_check = 0
    for i in col_ipsec_sa.find({}, {'_id':0}):
       if i["sa_id"] == sa_in:
         ck1 = bytes.fromhex(i["crypto_key"])
         ik1=bytes.fromhex(i["integrity_key"])
         sain_check = 1
       elif i["sa_id"] == sa_out:
         ck2=bytes.fromhex(i["crypto_key"])
         ik2=bytes.fromhex(i["integrity_key"])
         saout_check = 1
    
    if sain_check == 0:
        key_crypto_in_spi = crypto_key_generation()
        key_integ_in_spi = integ_key_generation()
        ck1 = bytes.fromhex(key_crypto_in_spi)
        ik1=bytes.fromhex(key_integ_in_spi)
        col_ipsec_sa.insert_one({ "sa_id":sa_in, "spi_in":int(spi_in), "crypto_key":key_crypto_in_spi, "integrity_key":key_integ_in_spi })
    if saout_check == 0:
        key_crypto_out_spi = crypto_key_generation()
        key_integ_out_spi = integ_key_generation()
        ck2=bytes.fromhex(key_crypto_out_spi)
        ik2=bytes.fromhex(key_integ_out_spi)
        col_ipsec_sa.insert_one({ "sa_id":sa_out, "spi_in":int(spi_out), "crypto_key":key_crypto_out_spi, "integrity_key":key_integ_out_spi })
  
      

    vpp.api.ipsec_sad_entry_add_del_v2(entry = {"sad_id":sa_in, "spi":int(spi_in), "protocol":50, "crypto_algorithm":1, "crypto_key":{ "length":16, "data":ck1}, "integrity_algorithm":2, "integrity_key":{ "length":20, "data":ik1 }}, is_add=1)
    vpp.api.ipsec_sad_entry_add_del_v2(entry = {"sad_id":sa_out, "spi":int(spi_out), "protocol":50, "crypto-algorithm":1, "crypto_key":{"length":16, "data":ck2}, "integrity_algorithm":2, "integrity_key":{"length":20, "data":ik2}}, is_add=1)

def db_create_setup():
    col.delete_many({})
    col.insert_one({ "loopback_instance":3, "bridge_instance":3, "vxlan_instance":3, "gre_instance":3 })


print(" option: 1 --- WAN interface setup")
print(" option: 2 --- Create database for instance maintaining")
print(" option: 3 --- ipsec sa setup")
print(" option: 4--- vxlan tunnel setup")
print(" option: 5 --- Exit")
print(" enter an option")
option = input()
option_ch =int(option)


if(option_ch == 1):
    wan_intf_setup()
elif(option_ch == 2):
    db_create_setup()
elif(option_ch == 3):
    ipsecsa_setup()
elif(option_ch == 4):
    vxlan_setup()
elif(option_ch == 5):
    exit()


