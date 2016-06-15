# Puszek  

rootkit for linux, works by modifying syscall table  
  
## warning: not done yet, list of features is below and what's more rootkit prints debug information to dmesgs  
  
### features:  
  
1. hiding files with names with defined suffix (".rootkit" by default)  
2. hiding processes which cmdline contains defined word (".//./" by default)  
examples:  
.//./malicious_process  
wget http://cdimage.debian.org/debian-cd/8.5.0/amd64/iso-cd/debian-8.5.0-amd64-CD-1.iso .//./  
3. intercepting http (not https!) requests.  
all GET and POST http requests will be writen to cat /etc/http_requests.rootkit  
when password is sended in rewuest - it's written additionally to at /etc/passwords.rootkit  
