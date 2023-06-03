import os
import pymongo
import subprocess

client = pymongo.MongoClient("mongodb://localhost:27017/")
db = client["int_details"]
coll_interface_info = db["ubuntu_interface_info"]
coll_vpp_pci_info = db["vpp_pci_info"]

interface_details = subprocess.check_output(["sudo", "vppctl", "show", "hardware-interfaces"]).decode()
with open("int_details.txt", "w") as f:
  f.write(interface_details)
pci_out1 = subprocess.check_output(["awk", "/Gigabit/ {print $1} /pci/ {print $7}", "int_details.txt"]).decode()
pci_out2 = pci_out1.split("\n")
j=0
list_len = int(len(out)/2)
for i in range(list_len):
  colect = {"interface_name":pci_out2[j], "pci_address":pci_out2[j+1]}
  j = j+2
  coll_vpp_pci_info.inser_one(colect)

for  i in coll_vpp_pci_info.find():
  for j in coll_interface_info.find():
    if "pci_address" in j:
	  if i["pci_address"] == j["pci_address"]:
	     query = {"pci_address":j["pci_address"]}
         update_data = {"$set": {"IPv4address": j["IPv4address"]}}
         coll_vpp_pci_info.update_many(query, update_data)
		 with open("/etc/vpp/bootstarp1.vpp", "")as f:
		   f.write(f"\nset int state {j['interface_name']} up\nset int ip address {j['interface_name']} {j['IPv4address']}\n")
		 if "gateway" in j:
		   with open("/etc/vpp/bootstarp1.vpp", "a")as f:
		     f.write(f"\nip route add 0.0.0.0/0 via {j['gateway']}\n")
		   query = {"pci_address":j["pci_address"]}
           update_data = {"$set": {"gateway": j["gateway"]}}
           coll_vpp_pci_info.update_many(query, update_data)
inter = []
for intfc in coll_vpp_pci_info.find({},{'_id':0}):
    inter.append(intfc)
print(inter)	    
	     

