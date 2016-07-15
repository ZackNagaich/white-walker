# white-walker

Python module to check against a whitelist of domains. Currently supports queries for a domain or IP address. 
The whitelist is obtained from Alexa's top 1 million sites. Checks against local domains.csv whitelist in working directory,
if not found it will obtain the whitelist from amazon. 
  

###Usage:

```
from white_walker import WhiteWalker

w = WhiteWalker('threatgrid_api_key_goes_here')

w.check_whitelist_by_domain('github.com')
w.check_whitelist_by_hash('hash_goes_here')
w.check_whitelist_by_ip('ip_goes_here')
```
