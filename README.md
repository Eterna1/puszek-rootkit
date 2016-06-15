# Puszek  

rootkit for linux, works by modifying syscall table, it's a kernel module  
  
## warning: not done yet, list of features is below and what's more rootkit prints debug information to dmesgs  
  
### features:  
  
1. hiding files with names containing defined suffix (".rootkit" by default)  
2. hiding processes which cmdline contains defined word (".//./" by default)  
examples:  
.//./malicious_process  
wget http://cdimage.debian.org/debian-cd/8.5.0/amd64/iso-cd/debian-8.5.0-amd64-CD-1.iso .//./  
3. intercepting http (not https!) requests.  
all intercepted GET and POST http requests will be writen to /etc/http_requests.rootkit  
when password is sent in request - it's written additionally to /etc/passwords.rootkit  
4.when hiden application uses internet netstat see port but doesn't see PID and applicatio name  
withot rootkit  
```
b@x:~ > sudo netstat -np46
[...]
tcp        0      0 192.168.0.10:54173      130.239.18.176:80       ESTABLISHED 9198/wget
[...]
```
with rootkit  
```
b@x:~ > sudo netstat -np46
[...]
tcp        0      0 192.168.0.10:54173      130.239.18.176:80       ESTABLISHED -  
[...]
```

tested on:  
```
Linux x 3.16.0-38-generic #52~14.04.1-Ubuntu SMP Fri May 8 09:43:57 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux  
```