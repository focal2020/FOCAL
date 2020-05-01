import re
import sys
import urlparse
from subprocess import Popen, PIPE
from threading import Thread
import dns.resolver

with open("canondeduped.txt") as f:
# with open("historyhits-Louis.txt") as f:
    SITES = f.readlines()
# you may also want to remove whitespace characters like `\n` at the end of each line
SITES = [x.strip() for x in SITES]
SITES[0] = 'ydabt.cf'
cnt = 0
with open('okstatus2.txt', 'w') as f:
    for site in SITES:
        try:
            hostname = urlparse.urlparse("http://"+site).hostname
            if hostname:
                try:
                    answers = dns.resolver.query(hostname, 'NS')
                    if answers:
                        cnt = cnt + 1
                        f.write("%s\n" % site)
                except:
                    continue
        except:
            continue