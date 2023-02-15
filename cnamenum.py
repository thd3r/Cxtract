#!/usr/bin/env python3

from __future__ import print_function

import re
import sys
import time
import argparse

import dns.resolver

class Enumerators:

    pattern = re.compile(
        r'^(?:[a-zA-Z0-9]'  # First character of the domain
        r'(?:[a-zA-Z0-9-_]{0,61}[A-Za-z0-9])?\.)'  # Sub domain + hostname
        r'+[A-Za-z0-9][A-Za-z0-9-_]{0,61}'  # First 61 characters of the gTLD
        r'[A-Za-z]$'  # Last character of the gTLD
    )

    start_time = time.strftime("%H:%M:%S")

    def __init__(self, verbose=True):
        self.verbose = verbose
        self.Resolver = dns.resolver.Resolver()

    def to_unicode(self, obj, charset='utf-8', errors='strict'):
        if obj is None:
            return None
        if not isinstance(obj, bytes):
            return str(obj)
        return obj.decode(charset, errors)

    def domain_validation(self, value):
        """
        Return whether or not given value is a valid domain.
        If the value is valid domain name this function returns ``True``
        """
        try:
            return self.pattern.match(self.to_unicode(value).encode('idna').decode('ascii'))
        except (UnicodeError, AttributeError):
            return False

    def find_cname(self, domain):
        """
        Returns whether the given domain has a CNAME or not.
        """
        domain_is_valid = self.domain_validation(domain)
        try:
            if domain_is_valid:
                result = self.Resolver.resolve(domain, "CNAME")
                for valdomain in result:
                    print("DOMAIN...:", domain)
                    print("CNAME....:", valdomain)
            else:
                print("INFO.....: Invalid domain for %s target" % (domain))
        except dns.resolver.LifetimeTimeout:
            self.find_cname(domain)
        except dns.resolver.NXDOMAIN:
            print("DOMAIN...: {}\nCNAME....: {}".format(domain, None) if not self.verbose else "INFO.....: The DNS query name does not exist: %s." % (domain))
        except dns.resolver.NoAnswer:
            print("DOMAIN...: {}\nCNAME....: {}".format(domain, None) if not self.verbose else "INFO.....: The DNS response does not contain an answer to the question: %s. IN CNAME" % (domain))

if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog="Enumeration", usage=f"{sys.argv[0]} [flags]")
    parser._optionals.title = "Options"
    parser.add_argument("-d", "--domain", action="store", help="domains to enumeration")
    parser.add_argument("-dL", "--domain-list", action="store", help="file containing list of domains for enumeration discovery")
    parser.add_argument("-v", "--verbose", action="store_true", default=False, help="Enable Verbosity and display results in realtime")
   
    args = parser.parse_args()
    domain = args.domain
    domain_list = args.domain_list
    verbose = args.verbose

    enum = Enumerators(verbose)
    
    if not (domain or domain_list):
        print(parser.format_help().lower())

    if domain_list:
        for domains in open(domain_list, encoding='utf-8').read().splitlines():
            enum.find_cname(domains)

    if domain:
        enum.find_cname(domain)
