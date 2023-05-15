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
                   a = 1
                   for line1 in output1.splitlines():
                     if "default" in line1:
                       
                        # we have to test for more than one wan interface.
                       if current_interface == line1.split()[6]:
                         netmask =parts[3]
                         prefixlength = IPAddress(netmask).netmask_bits()
                         ipaddress = parts[1]
                         slash = "/"
                         ipaddr_prefix = ipaddress+slash+str(prefixlength)
                         int_type = "wan"
                         gateway = line1.split()[4]
                         publicip = public_ip
                         stat_dhcp = line1.split()[8]
                         a = 0
                         collect = {"interface_name":current_interface, "int_type":int_type, "static/dhcp":stat_dhcp, "ipv4_address":ipaddress, "gateway":gateway, "mtu":mtu, "public_ip":publicip }
                         #yet to change to cloud db
                         coll.insert_one({"interface_name":current_interface, "int_type":int_type, "static/dhcp":stat_dhcp, "ipv4_address":ipaddress, "gateway":gateway, "mtu":mtu, "public_ip":publicip, "ipaddr_prefix":ipaddr_prefix })
                   
                   if a == 1:
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
