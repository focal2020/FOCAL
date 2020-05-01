
# Introduction

FOCAL (Sa**f**er Br**o**wsing with Priva**c**y Enh**a**nced B**l**acklisting) is an integrated open-sourced Privacy-enhanced Safe Browsing platform. It enables a Safe Browsing proxy server by leveraging Intel SGX and users can proactively select blacklists. 

For demonstration purpose, we have provided the following instructions to set up docker-enabled server-side service.

# Starting FOCAL server via Docker

1. Run server
2. Install Docker
   1. `sudo apt-get update`
   2. `sudo apt-get install apt-transport-https ca-certificates curl software-properties-common`
   3. `curl -fsSL https://download.docker.com/linux/ubuntu/gpg | sudo apt-key add -`
   4. `sudo apt-key fingerprint 0EBFCD88`
   5. `sudo add-apt-repository "deb [arch=amd64] https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable"`
   6. `sudo apt-get update`
   7. `sudo apt-get install docker-ce`
   8. `docker --version`
3. Run Docker
   1. `sudo docker run -tid -p 80:80 focal/server:v1`
4. Access the IP address/URL of this server via a web browsing
   1. Register
   2. Upload a blacklist in JSON format
   3. Encrypt and publish it
5. Stop Docker
   1. `sudo docker container ls`
   2. `sudo docker stop [container id]`

# Enabling HTTPS

1. Apply for CA files including .PEM and .KEY
2. Put these CA files into the PATH:"/data/ca"
3. Rename them to "web.pem" and "web.key"
4. Restart FOCAL service
