import nmap
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces as ni
import pprint
import iptools

class Network:
	my_addr = ""
	my_netmask = ""

	def setup(self):
		interfaces_list = ni.interfaces()
		for intr in interfaces_list:
			if intr != 'lo':
				print("Mac addresse of the interface %s is : %s " % (intr, str(ni.ifaddresses(intr)[AF_LINK][0]['addr'])))
				try :
					ni.ifaddresses(intr)[AF_INET]
					self.my_addr = ni.ifaddresses(intr)[AF_INET][0]['addr']
					self.my_netmask = ni.ifaddresses(intr)[AF_INET][0]['netmask']
					print ("interface %s is connected and has this addresse %s/%s " % (intr, self.my_addr, self.my_netmask))
				except KeyError:
					print ("interface %s is not connected !!" % intr)

	def scan_network(self):
		nm = nmap.PortScanner()
		print(self.my_addr+'/'+self.my_netmask)
		pp = pprint.PrettyPrinter(indent=2)
		pp.pprint(nm.scan(hosts=self.my_addr+'/'+str(iptools.ipv4.netmask2prefix(self.my_netmask)), arguments='-n -sP -PE -PA21,23,80,3389'))