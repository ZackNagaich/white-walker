#!/usr/bin/python
import socket

def _get_domains():
	domains = {}
	try:
		with open('domains.csv') as fo:
			for line in fo:
				pair = line.rstrip().split(',')
				domains[pair[1]] = pair[0]
		return domains
	except:
		print("\nFailed to open domains.csv...\n")

def _get_host_by_addr(ip):
	try:
		host = socket.gethostbyaddr(ip)[0]
		return host

	except socket.herror,msg:
		print("\nFailed to perform reverse DNS lookup...%s\n" % (msg)) 


def _get_ip_by_host(hostname):
	try:
		ip = socket.gethostbyname(hostname)
		return(ip)

	except socket.herror,msg:
		print("\nFailed to perform DNS lookup...%s\n" % (msg))


def check_whitelist_by_ip(ip):
	
	domains = _get_domains()
	host = _get_host_by_addr(ip)
	if host in domains:
		print("\nWhitelist Membership Confirmed!\n%s is ranked %s" % (host,domains[host]))
	else:
		print("\nCould not find %s in whitelist...\n" % (host))

def main():
	print(get_host_by_addr('192.30.252.131'))
	print(get_ip_by_host('github.com'))

if __name__ == '__main__':
	main() 
