from all_in_one_network_tool.Network import Network

if __name__ == "__main__":
	net = Network()
	net.setup()
	print("this computer is connected and has this addresse %s/%s" % (net.my_addr, net.my_netmask))
	net.get_hosts()
	# this next one needs root privileges 
	net.tcp_syn_scan()
	net.tcp_connect_scan()