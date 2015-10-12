from all_in_one_network_tool.Network import Network

if __name__ == "__main__":
	net = Network()
	net.setup()
	print("this computer is connected and has this addresse %s/%s" % (net.my_addr, net.my_netmask))
	# net.get_hosts()
	# this next one needs root privileges 
	# net.tcp_syn_scan()
	# net.tcp_connect_scan()
	# net.udp_scan()
	# net.fin_scan()
	# net.version_detection()
	# net.idle_scan()
	net.firewall_detector()
	net.fast_scan("192.168.0.0/24")
	# net.interfaces()