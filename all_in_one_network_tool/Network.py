import nmap
from netifaces import AF_INET, AF_INET6, AF_LINK, AF_PACKET, AF_BRIDGE
import netifaces as ni
import pprint
import iptools

'''
Detect the live host on the network (host discovery)
Detect the open ports on the host (port discovery or enumeration)
Detect the software and the version to the respective port (service discovery)
Detect the operating system, hardware address, and the software version
Detect the vulnerability and security holes (Nmap scripts)
'''



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

	def get_hosts(self):
		""" Ping Scan """
		nm = nmap.PortScanner()
		print 
		print("Scannig the network for live hosts using ping")
		pp = pprint.PrettyPrinter(indent=2)
		pp.pprint(nm.scan(hosts=self.my_addr+'/'+str(iptools.ipv4.netmask2prefix(self.my_netmask)), arguments='-sP'))

	def tcp_syn_scan(self):
		"""TCP SYN Scan"""
		nm = nmap.PortScanner()
		print 
		print("Scannig the network for live hosts using SYN packets ")
		pp = pprint.PrettyPrinter(indent=2)
		pp.pprint(nm.scan(hosts=self.my_addr+'/'+str(iptools.ipv4.netmask2prefix(self.my_netmask)), arguments='-sS'))

	def tcp_connect_scan(self):
		"""TCP CONNECT Scan"""
		nm = nmap.PortScanner()
		print 
		print("Scannig the network for live hosts using Full TCP connection to detect open TCP ports")
		pp = pprint.PrettyPrinter(indent=2)
		pp.pprint(nm.scan(hosts=self.my_addr+'/'+str(iptools.ipv4.netmask2prefix(self.my_netmask)), arguments='-sS'))

	def scan_network(self):
		nm = nmap.PortScanner()
		print(self.my_addr+'/'+self.my_netmask)
		pp = pprint.PrettyPrinter(indent=2)
		pp.pprint(nm.scan(hosts=self.my_addr+'/'+str(iptools.ipv4.netmask2prefix(self.my_netmask)), arguments='-n -sP -PE -PA21,23,80,3389'))