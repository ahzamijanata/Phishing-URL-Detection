import ipaddress
import re
from bs4 import BeautifulSoup
import socket
import requests
from googlesearch import search
import whois
from datetime import date, datetime
from dateutil.parser import parse as date_parse
from urllib.parse import urlparse
import socket
import dns.resolver
from ipwhois import IPWhois
import posixpath
from urllib import parse
from dns import resolver, reversename
import geoip2.database


PATH = 'lib/files/'

def start_url(url):
    """Split URL into: protocol, host, path, params, query and fragment."""
    if not urlparse(url.strip()).scheme:
        url = 'http://' + url
    parsed_url = urlparse(url.strip())
    return {
        'url': parsed_url.netloc + parsed_url.path + parsed_url.params + parsed_url.query + parsed_url.fragment,
        'protocol': parsed_url.scheme,
        'host': parsed_url.netloc,
        'path': parsed_url.path,
        'params': parsed_url.params,
        'query': parsed_url.query,
        'fragment': parsed_url.fragment
    }

class feature_extract:
    features = []
    
    def __init__(self, url):
        self.features = []
        self.url = url
        self.whois_response = ""
        self.response = ""
        self.soup = ""
        
        # Split URL into components
        url_components = start_url(url)
        self.protocol = url_components['protocol']
        self.host = url_components['host']
        self.path = url_components['path']
        self.params = url_components['params']
        self.query = url_components['query']
        self.fragment = url_components['fragment']
        self.filename = posixpath.basename(self.path)  # Tentukan nama file sekali di awal
        
        try:
            self.response = requests.get(url)
            self.soup = BeautifulSoup(self.response.text, 'html.parser')
        except:
            pass

        try:
            self.domain = self.host
        except:
            pass

        try:
            self.whois_response = whois.whois(self.domain)
        except:
            pass

        # URL-based features
        self.features.append(self.qty_dot_url()) #1
        self.features.append(self.qty_hyphen_url()) #2
        self.features.append(self.qty_underline_url()) #3
        self.features.append(self.qty_slash_url()) #4
        self.features.append(self.qty_questionmark_url()) #5
        self.features.append(self.qty_equal_url()) #6
        self.features.append(self.qty_at_url()) #7
        self.features.append(self.qty_and_url()) #8
        self.features.append(self.qty_exclamation_url()) #9
        self.features.append(self.qty_space_url()) #10
        self.features.append(self.qty_tilde_url()) #11
        self.features.append(self.qty_comma_url()) #12
        self.features.append(self.qty_plus_url()) #13
        self.features.append(self.qty_asterisk_url()) #14
        self.features.append(self.qty_hashtag_url()) #15
        self.features.append(self.qty_dollar_url()) #16
        self.features.append(self.qty_percent_url()) #17
        self.features.append(self.qty_tld_url()) #18
        self.features.append(self.length_url()) #19

        # Domain-based features
        self.features.append(self.qty_dot_domain()) #20
        self.features.append(self.qty_hyphen_domain()) #21
        self.features.append(self.qty_underline_domain()) #22
        '''
        self.features.append(self.qty_slash_domain()) #23
        self.features.append(self.qty_questionmark_domain()) #24
        self.features.append(self.qty_equal_domain()) #25
        '''
        self.features.append(self.qty_at_domain()) #26
        '''
        self.features.append(self.qty_and_domain()) #27
        self.features.append(self.qty_exclamation_domain()) #28
        self.features.append(self.qty_space_domain()) #29
        self.features.append(self.qty_tilde_domain()) #30
        self.features.append(self.qty_comma_domain()) #31
        self.features.append(self.qty_plus_domain()) #32
        self.features.append(self.qty_asterisk_domain()) #33
        self.features.append(self.qty_hashtag_domain()) #34
        self.features.append(self.qty_dollar_domain()) #35
        self.features.append(self.qty_percent_domain()) #36
        '''
        self.features.append(self.qty_vowels_domain()) #37
        self.features.append(self.domain_length()) #38
        self.features.append(self.domain_in_ip()) #39 <bool>
        self.features.append(self.server_client_domain()) #40 <bool>
        
        # Directory-based features
        self.features.append(self.qty_dot_directory()) #41
        self.features.append(self.qty_hyphen_directory()) #42
        self.features.append(self.qty_underline_directory()) #43
        self.features.append(self.qty_slash_directory()) #44
        self.features.append(self.qty_questionmark_directory()) #45
        self.features.append(self.qty_equal_directory()) #46
        self.features.append(self.qty_at_directory()) #47
        self.features.append(self.qty_and_directory()) #48
        self.features.append(self.qty_exclamation_directory()) #49
        self.features.append(self.qty_space_directory()) #50
        self.features.append(self.qty_tilde_directory()) #51
        self.features.append(self.qty_comma_directory()) #52
        self.features.append(self.qty_plus_directory()) #53
        self.features.append(self.qty_asterisk_directory()) #54
        self.features.append(self.qty_hashtag_directory()) #55
        self.features.append(self.qty_dollar_directory()) #56
        self.features.append(self.qty_percent_directory()) #57
        self.features.append(self.directory_length()) #58
        
        # File-based features
        self.features.append(self.qty_dot_file()) #59
        self.features.append(self.qty_hyphen_file()) #60
        self.features.append(self.qty_underline_file()) #61
        self.features.append(self.qty_slash_file()) #62
        self.features.append(self.qty_questionmark_file()) #63
        self.features.append(self.qty_equal_file()) #64
        self.features.append(self.qty_at_file()) #65
        self.features.append(self.qty_and_file()) #66
        self.features.append(self.qty_exclamation_file()) #67
        self.features.append(self.qty_space_file()) #68
        self.features.append(self.qty_tilde_file()) #69
        self.features.append(self.qty_comma_file()) #70
        self.features.append(self.qty_plus_file()) #71
        self.features.append(self.qty_asterisk_file()) #72
        self.features.append(self.qty_hashtag_file()) #73
        self.features.append(self.qty_dollar_file()) #74
        self.features.append(self.qty_percent_file()) #75
        self.features.append(self.file_length()) #75
        
        # Parameter-based features
        self.features.append(self.qty_dot_params()) #77
        self.features.append(self.qty_hyphen_params()) #78
        self.features.append(self.qty_underline_params()) #79
        self.features.append(self.qty_slash_params()) #80
        self.features.append(self.qty_questionmark_params()) #81
        self.features.append(self.qty_equal_params()) #82
        self.features.append(self.qty_at_params()) #83
        self.features.append(self.qty_and_params()) #84
        self.features.append(self.qty_exclamation_params()) #85
        self.features.append(self.qty_space_params()) #86
        self.features.append(self.qty_tilde_params()) #87
        self.features.append(self.qty_comma_params()) #88
        self.features.append(self.qty_plus_params()) #89
        self.features.append(self.qty_asterisk_params()) #90
        self.features.append(self.qty_hashtag_params()) #91
        self.features.append(self.qty_dollar_params()) #92
        self.features.append(self.qty_percent_params()) #93
        self.features.append(self.params_length()) #94
        self.features.append(self.tld_present_params()) #95 <bool>
        self.features.append(self.qty_params()) #96
        
        # External service-based features
        self.features.append(self.email_in_url()) #97 <bool>
        self.features.append(self.time_response()) #98
        self.features.append(self.domain_spf()) #99 <bool>
        self.features.append(self.asn_ip()) #100
        self.features.append(self.time_domain_activation()) #101
        self.features.append(self.time_domain_expiration()) #102
        self.features.append(self.qty_ip_resolved()) #103
        self.features.append(self.qty_nameservers()) #104
        self.features.append(self.qty_mx_servers()) #105
        self.features.append(self.ttl_hostname()) #106
        self.features.append(self.tls_ssl_certificate()) #107 <bool>
        self.features.append(self.qty_redirects()) #108
        self.features.append(self.url_google_index()) #109 <bool>
        self.features.append(self.domain_google_index()) #110 <bool>
        self.features.append(self.url_shortened()) #111 <bool>
        
# URL-based feature methods

    def qty_dot_url(self):
        try:
            return len(re.findall(r"\.", self.url))
        except:
            return -1
        
    def qty_hyphen_url(self):
        try:
            return self.url.count('-')
        except:
            return -1

    def qty_underline_url(self):
        try:
            return self.url.count('_')
        except:
            return -1

    def qty_slash_url(self):
        try:
            return self.url.count('/')
        except:
            return -1

    def qty_questionmark_url(self):
        try:
            return self.url.count('?')
        except:
            return -1

    def qty_equal_url(self):
        try:
            return self.url.count('=')
        except:
            return -1

    def qty_at_url(self):
        try:
            return self.url.count('@')
        except:
            return -1

    def qty_and_url(self):
        try:
            return self.url.count('&')
        except:
            return -1

    def qty_exclamation_url(self):
        try:
            return self.url.count('!')
        except:
            return -1

    def qty_space_url(self):
        try:
            return self.url.count(' ')
        except:
            return -1

    def qty_tilde_url(self):
        try:
            return self.url.count('~')
        except:
            return -1

    def qty_comma_url(self):
        try:
            return self.url.count(',')
        except:
            return -1

    def qty_plus_url(self):
        try:
            return self.url.count('+')
        except:
            return -1

    def qty_asterisk_url(self):
        try:
            return self.url.count('*')
        except:
            return -1

    def qty_hashtag_url(self):
        try:
            return self.url.count('#')
        except:
            return -1

    def qty_dollar_url(self):
        try:
            return self.url.count('$')
        except:
            return -1

    def qty_percent_url(self):
        try:
            return self.url.count('%')
        except:
            return -1

    def qty_tld_url(self): 
        """Return amount of Top-Level Domains (TLD) present in the URL."""
        file = open(PATH + 'tlds.txt', 'r')
        count = 0
        pattern = re.compile("[a-zA-Z0-9.]")
        for line in file:
            i = (self.url.lower().strip()).find(line.strip())
            while i > -1:
                if ((i + len(line) - 1) >= len(self.url)) or not pattern.match(self.url[i + len(line) - 1]):
                    count += 1
                i = self.url.find(line.strip(), i + 1)
        file.close()
        return count

    def length_url(self):
        return len(self.url)
    
# Domain-based feature methods
    
    def qty_dot_domain(self):
        try:
            return self.host.count('.')
        except:
            return -1

    def qty_hyphen_domain(self):
        try:
            return self.host.count('-')
        except:
            return -1

    def qty_underline_domain(self):
        try:
            return self.host.count('_')
        except:
            return -1

    def qty_slash_domain(self):
        try:
            return self.host.count('/')
        except:
            return -1

    def qty_questionmark_domain(self):
        try:
            return self.host.count('?')
        except:
            return -1

    def qty_equal_domain(self):
        try:
            return self.host.count('=')
        except:
            return -1

    def qty_at_domain(self):
        try:
            return self.host.count('@')
        except:
            return -1

    def qty_and_domain(self):
        try:
            return self.host.count('&')
        except:
            return -1

    def qty_exclamation_domain(self):
        try:
            return self.host.count('!')
        except:
            return -1

    def qty_space_domain(self):
        try:
            return self.host.count(' ')
        except:
            return -1

    def qty_tilde_domain(self):
        try:
            return self.host.count('~')
        except:
            return -1

    def qty_comma_domain(self):
        try:
            return self.host.count(',')
        except:
            return -1

    def qty_plus_domain(self):
        try:
            return self.host.count('+')
        except:
            return -1

    def qty_asterisk_domain(self):
        try:
            return self.host.count('*')
        except:
            return -1

    def qty_hashtag_domain(self):
        try:
            return self.host.count('#')
        except:
            return -1

    def qty_dollar_domain(self):
        try:
            return self.host.count('$')
        except:
            return -1

    def qty_percent_domain(self):
        try:
            return self.host.count('%')
        except:
            return -1

    def qty_vowels_domain(self):
        try:
            return len(re.findall(r'[aeiou]', self.host, re.IGNORECASE))
        except:
            return -1

    def domain_length(self):
        return len(self.domain) if self.host else -1

    def domain_in_ip(self):
        try:
            ipaddress.ip_address(self.host)
            return 1
        except:
            return 0
    
    def server_client_domain(self):
        """Return whether the "server" or "client" keywords exist in the domain."""
        if "server" in self.host.lower() or "client" in self.host.lower():
            return 1
        return 0

# Directory-based feature methods
    
    def qty_dot_directory(self):
        try:
            return self.path.count('.')if self.path else -1
        except:
            return -1

    def qty_hyphen_directory(self):
        try:
            return self.path.count('-')if self.path else -1
        except:
            return -1

    def qty_underline_directory(self):
        try:
            return self.path.count('_')if self.path else -1
        except:
            return -1

    def qty_slash_directory(self):
        try:
            return self.path.count('/')if self.path else -1
        except:
            return -1

    def qty_questionmark_directory(self):
        try:
            return self.path.count('?')if self.path else -1
        except:
            return -1

    def qty_equal_directory(self):
        try:
            return self.path.count('=')if self.path else -1
        except:
            return -1

    def qty_at_directory(self):
        try:
            return self.path.count('@')if self.path else -1
        except:
            return -1

    def qty_and_directory(self):
        try:
            return self.path.count('&')if self.path else -1
        except:
            return -1

    def qty_exclamation_directory(self):
        try:
            return self.path.count('!')if self.path else -1
        except:
            return -1

    def qty_space_directory(self):
        try:
            return self.path.count(' ')if self.path else -1
        except:
            return -1

    def qty_tilde_directory(self):
        try:
            return self.path.count('~')if self.path else -1
        except:
            return -1

    def qty_comma_directory(self):
        try:
            return self.path.count(',')if self.path else -1
        except:
            return -1

    def qty_plus_directory(self):
        try:
            return self.path.count('+')if self.path else -1
        except:
            return -1

    def qty_asterisk_directory(self):
        try:
            return self.path.count('*')if self.path else -1
        except:
            return -1

    def qty_hashtag_directory(self):
        try:
            return self.path.count('#')if self.path else -1
        except:
            return -1

    def qty_dollar_directory(self):
        try:
            return self.path.count('$')if self.path else -1
        except:
            return -1

    def qty_percent_directory(self):
        try:
            return self.path.count('%')if self.path else -1
        except:
            return -1

    def directory_length(self):
        try:
            return len(self.path)if self.path else -1
        except:
            return -1
    
# File-based feature methods
    
    def qty_dot_file(self):
        try:
            return self.filename.count('.')if self.filename else -1
        except:
            return -1

    def qty_hyphen_file(self):
        try:
            return self.filename.count('-')if self.filename else -1
        except:
            return -1

    def qty_underline_file(self):
        try:
            return self.filename.count('_')if self.filename else -1
        except:
            return -1

    def qty_slash_file(self):
        try:
            return self.filename.count('/')if self.filename else -1
        except:
            return -1

    def qty_questionmark_file(self):
        try:
            return self.filename.count('?')if self.filename else -1
        except:
            return -1

    def qty_equal_file(self):
        try:
            return self.filename.count('=')if self.filename else -1
        except:
            return -1

    def qty_at_file(self):
        try:
            return self.filename.count('@')if self.filename else -1
        except:
            return -1

    def qty_and_file(self):
        try:
            return self.filename.count('&')if self.filename else -1
        except:
            return -1

    def qty_exclamation_file(self):
        try:
            return self.filename.count('!')if self.filename else -1
        except:
            return -1

    def qty_space_file(self):
        try:
            return self.filename.count(' ')if self.filename else -1
        except:
            return -1

    def qty_tilde_file(self):
        try:
            return self.filename.count('~')if self.filename else -1
        except:
            return -1

    def qty_comma_file(self):
        try:
            return self.filename.count(',')if self.filename else -1
        except:
            return -1

    def qty_plus_file(self):
        try:
            return self.filename.count('+')if self.filename else -1
        except:
            return -1

    def qty_asterisk_file(self):
        try:
            return self.filename.count('*')if self.filename else -1
        except:
            return -1

    def qty_hashtag_file(self):
        try:
            return self.filename.count('#')if self.filename else -1
        except:
            return -1

    def qty_dollar_file(self):
        try:
            return self.filename.count('$')if self.filename else -1
        except:
            return -1

    def qty_percent_file(self):
        try:
            return self.filename.count('%')if self.filename else -1
        except:
            return -1
        
    def file_length(self):
        try:
            return len(self.filename)if self.filename else -1
        except:
            return -1

# Parameter-based feature methods

    def qty_dot_params(self):
        try:
            return self.query.count('.')if self.query else -1
        except:
            return -1

    def qty_hyphen_params(self):
        try:
            return self.query.count('-')if self.query else -1
        except:
            return -1

    def qty_underline_params(self):
        try:
            return self.query.count('_')if self.query else -1
        except:
            return -1

    def qty_slash_params(self):
        try:
            return self.query.count('/')if self.query else -1
        except:
            return -1

    def qty_questionmark_params(self):
        try:
            return self.query.count('?')if self.query else -1
        except:
            return -1

    def qty_equal_params(self):
        try:
            return self.query.count('=')if self.query else -1
        except:
            return -1

    def qty_at_params(self):
        try:
            return self.query.count('@')if self.query else -1
        except:
            return -1

    def qty_and_params(self):
        try:
            return self.query.count('&')if self.query else -1
        except:
            return -1

    def qty_exclamation_params(self):
        try:
            return self.query.count('!')if self.query else -1
        except:
            return -1

    def qty_space_params(self):
        try:
            return self.query.count(' ')if self.query else -1
        except:
            return -1

    def qty_tilde_params(self):
        try:
            return self.query.count('~')if self.query else -1
        except:
            return -1

    def qty_comma_params(self):
        try:
            return self.query.count(',')if self.query else -1
        except:
            return -1

    def qty_plus_params(self):
        try:
            return self.query.count('+')if self.query else -1
        except:
            return -1

    def qty_asterisk_params(self):
        try:
            return self.query.count('*')if self.query else -1
        except:
            return -1

    def qty_hashtag_params(self):
        try:
            return self.query.count('#')if self.query else -1
        except:
            return -1

    def qty_dollar_params(self):
        try:
            return self.query.count('$')if self.query else -1
        except:
            return -1

    def qty_percent_params(self):
        try:
            return self.query.count('%')if self.query else -1
        except:
            return -1

    def params_length(self):
        try:
            return len(self.query)if self.query else -1
        except:
            return -1

    def tld_present_params(self):
        """Return amount of Top-Level Domains (TLD) present in the URL."""
        file = open(PATH + 'tlds.txt', 'r')
        count = 0
        pattern = re.compile("[a-zA-Z0-9.]")
        for line in file:
            i = (self.query.lower().strip()).find(line.strip())
            while i > -1:
                if ((i + len(line) - 1) >= len(self.query)) or not pattern.match(self.query[i + len(line) - 1]):
                    count += 1
                i = self.query.find(line.strip(), i + 1)
        file.close()
        return count
        
    def qty_params(self):
        try:
            return len(parse.parse_qs(self.query))if self.query else -1
        except:
            return -1
            
# External service-based feature methods

    def email_in_url(self):
        """Return if there is an email in the text."""
        if re.findall(r'[\w\.-]+@[\w\.-]+', self.url):
            return 1
        else:
            return 0

    def time_response(self):
        """Return the response time in seconds."""
        try:
            latency = requests.get(self.url, headers={'Cache-Control': 'no-cache'}).elapsed.total_seconds()
            return latency
        except Exception:
            return -1
        
    def domain_spf(self):
        try:
            parsed_url = urlparse(self.url)
            domain = parsed_url.netloc if parsed_url.netloc else parsed_url.path
            answers = dns.resolver.resolve(domain, 'TXT')
            for rdata in answers:
                for txt_string in rdata.strings:
                    if txt_string.startswith(b'v=spf1'):
                        return 1  # SPF record found
            return 0  # No SPF record found
        except Exception as e:
            return -1  # Error
            
    def asn_ip(self):
        try:
            with geoip2.database.Reader(PATH + 'GeoLite2-ASN.mmdb') as reader:
                if domain_in_ip(self.host):
                    ip = self['host']
                else:
                    ip = resolver.query(self['host'], 'A')
                    ip = ip[0].to_text()

                if ip:
                    response = reader.asn(ip)
                    return response.autonomous_system_number
                else:
                    return -1
        except Exception:
            return -1

    def time_domain_activation(self):
        """Return time (in days) of domain activation."""
        host = urlparse(self.url).hostname
        if host.startswith("www."):
            host = host[4:]

        try:
            result_whois = whois.whois(host)
            if not result_whois or not result_whois.creation_date:
                return -1
            creation_date = result_whois.creation_date
            # Handle case where creation_date might be a list
            if isinstance(creation_date, list):
                creation_date = creation_date[0]
            d1 = creation_date
            if isinstance(d1, str):
                d1 = datetime.strptime(d1, "%Y-%m-%d")
            d2 = datetime.now()
            return abs((d2 - d1).days)
        except Exception as e:
            print(f"Error in time_domain_activation: {e}")
            return -1

    def time_domain_expiration(self):
        """Return time (in days) for register expiration."""
        host = urlparse(self.url).hostname
        if host.startswith("www."):
            host = host[4:]

        try:
            result_whois = whois.whois(host)
            if not result_whois or not result_whois.expiration_date:
                return -1
            expiration_date = result_whois.expiration_date
            # Handle case where expiration_date might be a list
            if isinstance(expiration_date, list):
                expiration_date = expiration_date[0]
            d1 = expiration_date
            if isinstance(d1, str):
                d1 = datetime.strptime(d1, "%Y-%m-%d")
            d2 = datetime.now()
            return abs((d1 - d2).days)
        except Exception as e:
            print(f"Error in time_domain_expiration: {e}")
            return -1

    def qty_ip_resolved(self):
        try:
            return len(socket.gethostbyname_ex(self.domain)[2])
        except:
            return -1

    def qty_nameservers(self):
        try:
            return len(self.whois_response.name_servers)
        except:
            return -1

    def qty_mx_servers(self):
        try:
            answers = dns.resolver.resolve(self.domain, 'MX')
            return len(answers)
        except dns.resolver.NoAnswer:
            return 0
        except dns.resolver.NXDOMAIN:
            return -1
        except Exception as e:
            print(f"An error occurred: {e}")
            return -1
        
    def ttl_hostname(self):
        try:
            ttl = resolver.query(self.host).rrset.ttl
            return ttl
        except Exception:
            return -1

    def tls_ssl_certificate(self):
        """Check if the ssl certificate is valid."""
        try:
            requests.get(self.url, verify=True, timeout=3)
            return 1
        except Exception:
            return 0

    def qty_redirects(self):
        try:
            return len(self.response.history)
        except:
            return -1

    def url_google_index(self):
        try:
            site = search(self.url)
            if site:
                return 1
            else:
                return 0
        except:
            return -1

    def domain_google_index(self):
        try:
            site = search(self.domain, 5)
            if site:
                return 1
            else:
                return 0
        except:
            return -1

    def url_shortened(self):
        """Check if the domain is a shortener."""
        file = open(PATH + 'shorteners.txt', 'r')
        for line in file:
            with_www = "www." + line.strip()
            if line.strip() == self.host.lower() or with_www == self.host.lower():
                file.close()
                return 1
        file.close()
        return 0
    
    def getFeaturesList(self):
        return self.features
