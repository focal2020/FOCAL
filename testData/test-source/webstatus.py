#!/usr/bin/env python
import os, time
import requests
from requests.exceptions import ConnectionError

with open("canondeduped.txt") as f:
# with open("historyhits-Louis.txt") as f:
    SITES = f.readlines()
# you may also want to remove whitespace characters like `\n` at the end of each line
SITES = [x.strip() for x in SITES]

cnt = 0
start_time = time.time()

with open('okstatus3.txt', 'w') as f:
    for site in SITES[::-1]:
        try:
            request = requests.get("http://"+site, timeout=1)
        except:
            continue
        else:
            cnt = cnt + 1
            f.write("%s\n" % site)
# with open('okstatus.txt', 'w') as f:
#     for site in SITES:
#         try:
#             request = requests.head(site)
#             if request is not None:
#                 cnt = cnt + 1
#                 f.write("%s\n" % site)
#                 # if cnt % 1000 == 0:
#                 #     print cnt
#         except:
#             continue
print cnt
print("--- %s seconds ---" % (time.time() - start_time))


        

        