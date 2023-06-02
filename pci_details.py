import os
import subprocess
def pci_details():
  pci_out = subprocess.check_output(["lspci"]).decode().split("\n")
  data = []
  for line in pci_out:
    if "Ethernet controller" in line:
      pci_info = "0000:"+line.split()[0]
      lsh_out = subprocess.check_output(["lshw", "-c", "network", "-businfo"])
      lsh_out = lsh_out.decode().split("\n")
      lsh_out = lsh_out[2:-1]
      for line in lsh_out:
        li = line.split()
        pci_addr = li[0].split("@")[1]
        if pci_info == pci_addr:
           colect = {
             "pci_address":pci_info", 
             "interface_name":li[1]
           }
           data.append(colect)
  return data
print(pci_details())
