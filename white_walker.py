#!/usr/bin/python
import socket
import re
import requests
from pythreatgrid.threatgrid import get_analysis, search_samples
import json
from pprint import pprint

class WhiteWalker():


	def __init__(self,api_key):
		self.domains = {}
		self.api_key = api_key


	def _search_samples(self,options):
		'''Override search_samples in pythreatgrid (direct GET request seems a bit faster, as opposed to generator yields)
		Args:
			options (dict): Options for the API request.
		Returns:
			 json_resp (dict): JSON object for API return 
		'''

		_HOST = 'https://panacea.threatgrid.com'
		'''str: Represents the host that the API will connect to.
		'''
		_APIROOT = '/api/v2'
		'''str: The root URI for the API.
		'''
		_URL = _HOST + _APIROOT
		'''str: Controls where requests will be sent.
		'''
		r = requests.get('%s/samples/search' % (_URL),
		data=options)
		json_resp = json.loads(r.text)

		return json_resp 

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
			

	def _get_tg_artifacts(self,checksum):
		sample_list = set()
		resp = self._search_samples({'api_key':self.api_key,'checksum':checksum})
		if 'data' in resp:
			for item in resp[u'data'][u'items']:
				sample_list.add(item['sample'])

		
		if len(sample_list) > 0:
			urls = set()
			for sample in sample_list:
				resp = ''
				for block in get_analysis({'api_key':self.api_key},sample):
					resp += block

				json_resp = json.loads(resp)	
				for network in json_resp[u'annotations'][u'network']:
					if 'reverse_dns' in json_resp[u'annotations'][u'network'][network]:
						url = self._get_tld(json_resp[u'annotations'][u'network'][network][u'reverse_dns'][0].lower())
						urls.add(url)
			return urls

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

	def check_whitelist_by_hash(self,checksum):
	
		if len(self.domains) == 0:
			self._get_whitelist()

		tg_domains = self._get_tg_artifacts(checksum)
		size = len(tg_domains)
		count = 0
		for domain in tg_domains:
			if domain in self.domains:
				count += 1
				
		if count > 0:
			print("\nWhitelist Membership Confirmed for %s out of %s total identified domains\n" % (count,size))
			return True
		else:
			print("\nCould not find any domains related to the submitted hash\n")
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
