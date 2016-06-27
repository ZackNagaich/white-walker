#!/usr/bin/python
import socket
import re
import zipfile, StringIO
import requests
from pythreatgrid.threatgrid import get_analysis, search_samples
import json

class WhiteWalker():


	def __init__(self,api_key):
		self.domains = {}
		self.api_key = api_key
 

	def _get_whitelist(self):
		''' Reads whitelist from domains.csv. If this fails, it fetches this list on Alexa.
		Args:
			None.
		Updates:
			Instance variable domains is set to a dictionary of ranking and domains from whitelist.
		'''
		try:	
			fp = open("top-1m.csv","r")
			lines = fp.readlines()
			for line in lines:
				pair = line.rstrip().split(',')
				self.domains[pair[1]] = pair[0]
		except:
			print("\nFailed to open domains.csv...fetching from github...\n")
			r = requests.get("http://s3.amazonaws.com/alexa-static/top-1m.csv.zip",stream=True)
			z = zipfile.ZipFile(StringIO.StringIO(r.content))
			z.extractall()
			
			fp = open("top-1m.csv","r")
			lines = fp.readlines()
			lines = data.split('\n')[:-1]
			for line in lines:
				pair = line.rstrip().split(',')
				self.domains[pair[1]] = pair[0]
			

	def _get_tg_artifacts(self,checksum):
		''' Searches ThreatGrid for sample ID's and strips out related URLs found in the analysis.
		Args:
			checksum - hash value to search threatgrid for.
		Returns:
			urls - A set of URLs obtained from ThreatGrid Sample Analysis	.
		'''

		sample_list = set()

		for resp in search_samples({'api_key':self.api_key,'checksum':checksum}):
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
		''' Trims down a domain to it's top level 
		Args:
			Domain to trim.
		Returns:
			domain - A TLD representation of the passed domain.
		'''
		dot_indexes = [x for x,y in enumerate(domain) if y == '.']
		if len(dot_indexes) > 2:
			domain = domain[dot_indexes[1]+1:]
		elif len(dot_indexes) == 2:
			domain = domain[dot_indexes[0]+1:]
		
		return domain
	

	def _get_host_by_addr(self,ip):
		''' Performs reverse DNS lookup for supplied IP.
		Args:
			ip - String representation of IPv4 address.
		Returns:
			host - host returned from reverse DNS lookup.
		'''
		try:
			host = socket.gethostbyaddr(ip)[0]
			return host
	
		except socket.herror,msg:
			print("\nFailed to perform reverse DNS lookup...%s\n" % (msg)) 
		except:
			print("\nSomething went wrong...\n")
	
	def _get_ip_by_host(self,hostname):
		''' Performs DNS lookup for supplied host name.
		Args:
			hostname - hostname to look up.
		Returns:
			ip - IPv4 address returned from DNS lookup .
		'''
		try:
			ip = socket.gethostbyname(hostname)
			return(ip)
	
		except socket.herror,msg:
			print("\nFailed to perform DNS lookup...%s\n" % (msg))
		except:
			print("\nSomething went wrong...\n")

	def check_whitelist_by_domain(self,domain):
		''' Checks whitelist for supplied domain.
		Args:
			domain - domain to check whitelist for. Should be TLD.
		Returns:
			Boolean - True if domain is in whitelist, False otherwise.
		'''	
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
		''' Gets related domains from supplied checksum using ThreatGrid. Then checks membership for the returned domains against whitelist.
		Args:
			checksum - hash to search threatgrid for to obtain related domains. .
		Returns:
			Boolean - True if at least 1 domain was matched to whitelist
			hit_domains - List of domains that matched against whitelist
			percentage - Percentage of hit domains against total number of identified domains. 
		'''	
		if len(self.domains) == 0:
			self._get_whitelist()

		tg_domains = self._get_tg_artifacts(checksum)
		size = len(tg_domains)
		hit_domains = list()
		count = 0
		for domain in tg_domains:
			if domain in self.domains:
				hit_domains.append(domain)
				count += 1

		percentage = size/count
				
		if count > 0:
			print("\nWhitelist Membership Confirmed for %s out of %s total identified domains (%s%%)\n" % (count,size,percentage))
			for domain in hit_domains:
				print(domain)
			return (True,hit_domains,percentage)
		else:
			print("\nCould not find any domains related to the submitted hash\n")
			return (False,hit_domains,percentage)
		

	def check_whitelist_by_ip(self,ip):	
		''' Checks whitelist for supplied ip.
		Args:
			ip - String representation of IPv4 address to perform DNS lookup with.
		Returns:
			Boolean - True if domain is in whitelist, False otherwise.
		'''
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
