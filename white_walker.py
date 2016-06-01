#!/usr/bin/python
import socket
import re
import requests

class WhiteWalker():


	def __init__(self):
		self.domains = {}

	def _get_whitelist(self):
		try:	
			fp = open("domains.csv","r")
			lines = fp.readlines()
			for line in lines:
				pair = line.rstrip().split(',')
				self.domains[pair[1]] = pair[0]
		except:
			print("\nFailed to open domains.csv...fetching from github...\n")
			r = requests.get("https://raw.githubusercontent.com/ZackNagaich/white-walker/master/domains.csv")
			data = r.text
			fp = open("domains.csv","w")
			fp.write(data)
			fp.close()
			
			lines = data.split('\n')[:-1]
			for line in lines:
				pair = line.rstrip().split(',')
				self.domains[pair[1]] = pair[0]
			
			

	def _get_tld(self,domain):
		dot_indexes = [x for x,y in enumerate(domain) if y == '.']
		if len(dot_indexes) > 2:
			domain = domain[dot_indexes[1]+1:]
		elif len(dot_indexes) == 2:
			domain = domain[dot_indexes[0]+1:]
		
		return domain
	
	def _get_host_by_addr(self,ip):
		try:
			host = socket.gethostbyaddr(ip)[0]
			return host
	
		except socket.herror,msg:
			print("\nFailed to perform reverse DNS lookup...%s\n" % (msg)) 
		except:
			print("\nSomething went wrong...\n")
	
	def _get_ip_by_host(self,hostname):
		try:
			ip = socket.gethostbyname(hostname)
			return(ip)
	
		except socket.herror,msg:
			print("\nFailed to perform DNS lookup...%s\n" % (msg))
		except:
			print("\nSomething went wrong...\n")

	def check_whitelist_by_domain(self,domain):

		domain = self._get_tld(domain)	
		
		if len(self.domains) == 0:
			self._get_whitelist()

		if domain  in self.domains:
			print("\nWhitelist Membership Confirmed!\n%s is ranked %s" % (domain,self.domains[domain]))
			return True
		else:
			print("\nCould not find %s in whitelist...\n" % (domain))
			return False

	def check_whitelist_by_ip(self,ip):	
		if len(self.domains) ==  0:
			self._get_whitelist()

		host = self._get_host_by_addr(ip)

		if host is not None:
			host = self._get_tld(host)

			if host in self.domains:
				print("\nWhitelist Membership Confirmed!\n%s is ranked %s" % (host,self.domains[host]))
				return True
			else:
				print("\nCould not find %s in whitelist...\n" % (host))	
				return False
		else:
			return False
