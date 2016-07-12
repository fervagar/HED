#ifndef __KERNEL__
#  define __KERNEL__
#endif
#ifndef MODULE
#  define MODULE
#endif

/*
 * Copyright (C) 2016 Fernando Vañó García
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301 USA.
 *
 *	Fernando Vanyo Garcia <fervagar@tuta.io>
 */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/syscalls.h>
#include <linux/slab.h>
#include <linux/proc_fs.h>
#include <linux/inet.h>
#include <net/sock.h>
#include <net/inet_common.h>

#define AUTHOR "Fernando Vanyo <fervagar@tuta.io>"
#define DESC   "HED (HoneyPot Engage Detector). \
Module for detecting the creation of piped shells through a socket"

MODULE_LICENSE("Dual BSD/GPL");
MODULE_AUTHOR(AUTHOR);
MODULE_DESCRIPTION(DESC);

// Macros to Enable/Disable the bit 0 of the CR register (Protected Mode)
#define ENABLE_PROT_MODE write_cr0(read_cr0() | 0x10000)
#define DISABLE_PROT_MODE write_cr0(read_cr0() & (~ 0x10000))

// Timeout for the kernel threads //
#define TIMEOUT_DELAY 		(3 * HZ)

// Chain Length Limit Constants //
#define MIN_CLL			(1024 * 1024)	// 1M
#define INIT_CLL		(4 * MIN_CLL)	// 4M
#define MAX_CLL			(40 * MIN_CLL)	// 40M
#define PROC_CLL_FILENAME	("hedcll")	// Change the name in the field

// Port Knocking Constants //
#define NAT_ADDR		"192.168.56.1"
#define NAT_PORT		7692
#define MAX_MSG_SIZE		30
#define MAX_CONNECT_TRIES	3
#define MAX_RECV_TRIES		1
#define CAP_TIMEOUT		10	// Must be synchronized with the NAT Handler (TIMEOUT_SNIFFER)

// Streams //
#define STREAM_IN		0	// Child process <- Server //
#define STREAM_OUT		1	// Server <- Child process //

// Errors //
#define SUCCESS			0
#define EFD_NOT_FOUND		1
#define ECLL_EXCEEDED		2
#define EMSG_CREATE_ERR		3
#define ETIMEOUT_ACCOMPLISHED	4
#define ETIMEOUT_START_FAILURE	5
#define ETYPE_INCORRECT		6
#define ESEQ_NOT_FOUND		7
#define ELENGTH_MISMATCH	8
#define EALREADY_DETECTED	9

/**
 * SEARCH_FD - Macro for find a (hed_fd)node inside a given list
 * note: we should call this macro inside a critical section
 * @ptr: the pointer ( type: hed_fd )
 * @argfd: the file descriptor to search for
 * @list: the list itself
 * @member: the name of the list_head within the struct.
 */
#define SEARCH_FD(ptr, argfd, list, member) 			\
	do{							\
		bool found = false;				\
		list_for_each_entry(ptr, &list.member, member){	\
			if(ptr->fd == argfd){			\
				found = true;			\
				break;				\
			}					\
		}						\
		if(!found) ptr = NULL;				\
	}while(0);

/**
 * HED_FOR_EACH - Macro for traverse a list
 * @hed_node_ptr: pointer to the node
 * @list_ptr: pointer indicating the list
 */

#define HED_FOR_EACH(hed_node_ptr, list_ptr)			\
	list_for_each_entry(hed_node_ptr, &list_ptr.list, list)

// -- Port Knocking -- //
struct port_knocking_package {
	struct delayed_work dwork;
	unsigned long ipaddr;		// IP address
	unsigned int port;		// Port
	struct socket *sock;		// struct socket for closing it
} port_knocking_package;

// ------------------------------------------ //

static unsigned long **sys_call_table;
// ---- Dynamic change of CLL functionality disabled ----
//static struct proc_dir_entry *proc_entry;

// Global var to regulate the Chain Length Limit
atomic_t hed_cll = ATOMIC_INIT(INIT_CLL);

// ------------------------------------------ //

// -- Functions related with the procfs -- //

/* ---- Functionality disabled ----
void hed_set_cll(unsigned int limit);
static ssize_t procfs_read(struct file *f, char __user *buf, size_t len, loff_t *off);
static ssize_t procfs_write(struct file *f, const char __user *buf, size_t len, loff_t *off);
*/
static inline int hed_get_current_cll(void);

// -- Auxiliar functions -- //
static unsigned long **find_sys_call_table(void);
static struct hed_fd *get_hed_fd(unsigned int fd);
static void clear_fd_node(struct hed_fd *fd_node);
static struct hed_msg *get_hed_msg(char *buf, size_t len);
static void timeout_func(struct work_struct *work);
static int start_timeout(struct hed_fd *fd_node, struct mutex *m);
static inline bool check_open_sockets(struct task_struct *p);
static inline bool check_whitelist_process(void);
static unsigned long cleanup_lists(void);
static void create_fd(long fd, unsigned int streamIdx, int type);
static struct hed_fd *search_sequence(char *buf, long len, unsigned int streamIdx);
static bool do_compare(char *buf, long len, struct hed_fd *node);
static int add_msg_to_chain(long fd, char *buf, long len, unsigned int streamIdx);
static int compare_msg_in_chains(long fd, char *buf, long len, unsigned int streamIdx);

// -- Syscalls Hooks -- //
asmlinkage long (*o_sys_close)(unsigned int fd);
asmlinkage long _sys_close(unsigned int fd);

asmlinkage long (*o_sys_socket)(int domain, int type, int protocol);
asmlinkage long _sys_socket(int domain, int type, int protocol);

asmlinkage long (*o_sys_pipe)(int __user *fildes);
asmlinkage long _sys_pipe(int __user *fildes);

asmlinkage long (*o_sys_recvfrom)(int sockfd, char *buf, size_t len,
		unsigned int flags, struct sockaddr *src_addr, unsigned int *addrlen);
asmlinkage long _sys_recvfrom(int sockfd, char *buf, size_t len,
		unsigned int flags, struct sockaddr *src_addr, unsigned int *addrlen);

asmlinkage long (*o_sys_recv)(int sockfd, char *buf, size_t len, unsigned int flags);
asmlinkage long _sys_recv(int sockfd, char *buf, size_t len, unsigned int flags);

asmlinkage long (*o_sys_write)(unsigned int fd, const char __user *buf, size_t count);
asmlinkage long _sys_write(unsigned int fd, const char __user *buf, size_t count);

asmlinkage long (*o_sys_read)(unsigned int fd, char __user *buf, size_t count);
asmlinkage long _sys_read(unsigned int fd, char __user *buf, size_t count);

asmlinkage long (*o_sys_sendto)(int sockfd, void __user *buf, size_t len, unsigned int flags, \
		struct sockaddr __user *dest_addr, int addrlen);
asmlinkage long _sys_sendto(int sockfd, void __user *buf, size_t len, unsigned int flags, \
		struct sockaddr __user *dest_addr, int addrlen);

asmlinkage long (*o_sys_send)(int sockfd, void __user *buf, size_t len, unsigned flags);
asmlinkage long _sys_send(int sockfd, void __user *buf, size_t len, unsigned flags);

// -- Port Knocking -- //
static unsigned int get_digits_num(unsigned long n);
static int build_msg(char *msg, unsigned int len, unsigned long ipaddr, unsigned int port);
static int my_sendmsg(struct socket *sock, struct sockaddr_in *addr_in, void *buf, size_t len);
static int my_recvmsg(struct socket *sock, void *buf, size_t len);
static unsigned int extract_tcp_port(char *buffer);
static int send_engage_info(unsigned long ipaddr, unsigned int port, unsigned int tcp_remote_port);
static int get_tcp_rport(void);
static void start_port_knocking(struct work_struct *work);
static void setup_port_knocking(unsigned long ipaddr, unsigned int port, struct socket *sock);


// -- Hook functions -- //
static unsigned long insert_hooks(void);
static unsigned long restore_syscalls(void);

// ------------------------------------------ //

/* ---- Functionality disabled ----
static ssize_t procfs_read(struct file *f, char __user *buf, size_t len, loff_t *off){
	return 0;
}
static ssize_t procfs_write(struct file *f, const char __user *buf, size_t len, loff_t *off){	
	const unsigned int digits = 10;
	unsigned int result;
	int wbytes;
	char *recv;

	if(len > 0){
		//TODO for future versions: add Security (Password?)
		wbytes = (len > digits)? digits : len;
		recv = kmalloc((sizeof(char) * wbytes + 1), GFP_KERNEL);
		memset(recv, 0, (sizeof(char) * wbytes + 1));
		if(!copy_from_user(recv, buf, wbytes)){
			// Adjusting for kstrtouint()
			recv[wbytes] = 0xA;
			recv[wbytes - 1] = 0x0;

			if(!kstrtouint(recv, 0, &result) && (result < MAX_CLL && result > MIN_CLL))
				hed_set_cll(result);
		}
		kfree(recv);
	}

	return len;
}

static const struct file_operations pfops = {
	write: (*procfs_write),
	read: (*procfs_read),
};

// Function to change the Chain Length Limit //
void hed_set_cll(unsigned int limit) {
	if(limit < MAX_CLL && limit > MIN_CLL){
		atomic_set(&hed_cll, limit);
		#ifdef DEBUG
		printk(KERN_ALERT "[DEBUG] Chain Length Limit set to %d\n", limit);
		#endif
	}
}
*/

// Function to get the current Chain Length Limit //
static inline int hed_get_current_cll(){
	return atomic_read(&hed_cll);
}

// Auxiliar function to find the sys_call_table //
static unsigned long **find_sys_call_table() {
    
	unsigned long *ptr;
    unsigned long lower_addr;
    unsigned long upper_addr;

#if defined(_M_X64) || defined(__amd64__)
    lower_addr = 0xffffffff81000000;
#else
    lower_addr = 0x80000000;
#endif

    upper_addr = ~(lower_addr^lower_addr);

	for (ptr = (unsigned long* ) lower_addr; (unsigned long)ptr < upper_addr; ptr++){
		if (ptr[__NR_close] == (unsigned long) sys_close){
			#ifdef DEBUG
			printk(KERN_ALERT "[DEBUG] SYSCALL TABLE => 0x%p\n", ptr);
			#endif
			return (unsigned long **)ptr;
		}
	}

    return NULL;
}

static int init_fd(struct hed_fd *fd_node){
	if(fd_node != NULL){
		fd_node->len_sum = 0;
		fd_node->hed_flags = (fd_node->hed_flags & (HED_TYPE_SOCKET | HED_TYPE_PIPE));
		return SUCCESS;
	}
	else{
		return -EFD_NOT_FOUND;
	}
}

// Auxiliar function to allocate a hed_fd node (node of a file descriptor) //
static struct hed_fd *get_hed_fd(unsigned int fd){
	struct hed_fd *fd_node;
	
	fd_node = kmalloc(sizeof(*fd_node), GFP_KERNEL);
	fd_node->fd = fd;
	fd_node->hed_flags = HED_FNULL;
	fd_node->tbox = NULL;
	if(init_fd(fd_node)){
		return NULL;
	}
	else{
		INIT_LIST_HEAD(&fd_node->chain.list);
		return fd_node;
	}
}

// Auxiliar function to clear a hed_fd node //
static void clear_fd_node(struct hed_fd *fd_node){
	if(fd_node != NULL){
		if(fd_node->tbox != NULL){
			kfree(fd_node->tbox);
			fd_node->tbox = NULL;
		}
		HED_FREE_CHAIN(fd_node);
		// Check if the flag of stream_in has been set
		if(!(fd_node->hed_flags & (HED_FSTREAM_IN | HED_FSTREAM_COMP))){
			// Clear the node only if the flag is false
			init_fd(fd_node);
		}
	}
}

// Auxiliar function to allocate a hed_msg node (node of a message) //
static struct hed_msg *get_hed_msg(char *buf, size_t len){
	struct hed_msg *msg_node;
	void *err;

	msg_node = kmalloc(sizeof(*msg_node), GFP_KERNEL);
	msg_node->buf = kmalloc(len * sizeof(char), GFP_KERNEL);
	msg_node->len = len;

	err = memcpy(msg_node->buf, buf, len);

	if(err != msg_node->buf){
		return NULL;
	}
	else{
		return msg_node;
	}
}

// timeout X, activated by recvfrom() //
// timeout Y, activated by read() //
static void timeout_func(struct work_struct *work){
	struct timeout_package *tbox;
	struct delayed_work *dwork;
	struct mutex *saved_mutex;
	struct hed_fd *fd_node;

	dwork = container_of(work, struct delayed_work, work);
	tbox = container_of(dwork, struct timeout_package, dwork);
	
	mutex_lock(tbox->mutex);	
	
	fd_node = tbox->node;
	saved_mutex = tbox->mutex; // save the reference for unlock

	#ifdef DEBUG
	printk(KERN_ALERT "[DEBUG] **** TIMEOUT ****() fd: %d\n", fd_node->fd);
	#endif

	// Check if the fd node must be freed
	if(fd_node->hed_flags & HED_FFREE_PENDING){
		// Free the entire node
		kfree(fd_node->tbox);
		HED_FREE_FD(fd_node);
	}
	else{
		// Clear the contents of the node
		clear_fd_node(fd_node);
	}

	mutex_unlock(saved_mutex);

	return;
}

// Auxiliar function to start a timeout (related with a file descriptor) //
static int start_timeout(struct hed_fd *fd_node, struct mutex *m){
	struct timeout_package *tbox;
	
	// Fill the box of the delayed work
	tbox = kmalloc(sizeof(*tbox), GFP_KERNEL);
	if(tbox != NULL){
		INIT_DELAYED_WORK(&tbox->dwork, timeout_func);
		tbox->node = fd_node;
		tbox->mutex = m;
		fd_node->tbox = tbox;

		// Start the timeout
		schedule_delayed_work(&tbox->dwork, TIMEOUT_DELAY);

		return 0;
	}
	else{		
		return -1;
	}
}

// Auxiliar function to check if the process 'p' have any open socket //
//(at least 1 element in STREAM_IN) //
static inline bool check_open_sockets(struct task_struct *p){
	return (list_first_entry_or_null(&p->streams[STREAM_IN].list, struct hed_fd, list) != NULL);
}

// Auxiliar function to bypass the whitelist processes //
static inline bool check_whitelist_process(){
	return (!strncmp(current->comm, "sshd", 4));
}

// Auxiliar function to free all the resources of a process //
static unsigned long cleanup_lists(){
	struct task_struct *p;

	for_each_process(p){
		mutex_lock(&p->mutex_s[STREAM_IN]);
		mutex_lock(&p->mutex_s[STREAM_OUT]);

		HED_FREE_LISTS(p);

		mutex_unlock(&p->mutex_s[STREAM_IN]);
		mutex_unlock(&p->mutex_s[STREAM_OUT]);
	}
	
	return 0;
}


// Auxiliar function to create a fd node and add it to a given stream //
static void create_fd(long fd, unsigned int streamIdx, int type){
	struct hed_fd *fd_node;
	
	SEARCH_FD(fd_node, fd, current->streams[streamIdx], list);
	if(fd_node == NULL){ // It must be NULL	
		fd_node = get_hed_fd(fd);
		// Important: set the type
		fd_node->hed_flags = type;
		if(fd_node != NULL){
			// Add node
			list_add_tail(&(fd_node->list), &(current->streams[streamIdx].list));
		}
	}

}

// Auxiliar function to do the comparision //
static bool do_compare(char *buf, long len, struct hed_fd *node){
	struct hed_msg *msg_node;
	int b_idx;	// Index of the buffer
	int c_idx;	// Index of the chain (local to each node)
	int t_idx;	// Index of the chain (total)

	b_idx = 0; t_idx = 0;
	HED_FOR_EACH(msg_node, node->chain){
		for(c_idx = 0; c_idx < msg_node->len; c_idx++, t_idx++){
			if(buf[b_idx] == msg_node->buf[c_idx]){
				b_idx++;
			}
			else if(b_idx){
				b_idx = 0;
			}

			if(b_idx == len) return true;
		}
	}
	return (b_idx == len);
}

// Auxiliar function to find a given secuence in any stored fd //
// Return NULL if sequence not found //
static struct hed_fd *search_sequence(char *buf, long len, unsigned int streamIdx){
	struct hed_fd *fd_node;

	HED_FOR_EACH(fd_node, current->streams[streamIdx]){
		if(fd_node->len_sum < len){
			continue;
		}
		if(do_compare(buf, len, fd_node)) return fd_node;
	}
	return NULL;
}

// Auxiliar function to create a msg node and add it to a chain of a file descriptor //
static int add_msg_to_chain(long fd, char *buf, long len, unsigned int streamIdx){
	struct hed_msg *msg_node;
	struct hed_fd *fd_node;

	// Check if fd is stored
	SEARCH_FD(fd_node, fd, current->streams[streamIdx], list);
	if(fd_node == NULL){
		return -EFD_NOT_FOUND; // fd not found 
	}

	// (STREAM_IN): Check if flag of 'Stream IN' is set
	// (STREAM_OUT): Check if the flag of Detection Complete is set
	if( ((streamIdx == STREAM_IN) && (fd_node->hed_flags & HED_FSTREAM_IN))
	|| ((streamIdx == STREAM_OUT) && (fd_node->hed_flags & HED_FSTREAM_COMP))){
		return EALREADY_DETECTED; // Flag already set => ignore
	}

	// (STREAM_IN): Check if the fd is a socket
	// (STREAM_OUT): Check if the fd is a pipe
	if((streamIdx == STREAM_IN && !(fd_node->hed_flags & HED_TYPE_SOCKET)) 
	|| (streamIdx == STREAM_OUT && !(fd_node->hed_flags & HED_TYPE_PIPE))){
		return -ETYPE_INCORRECT;
	}
	
	// Check excess of the Chain Length Limit
	if((fd_node->len_sum + len) > hed_get_current_cll()){
		if(fd_node->tbox){
			// Cancel the timeout
			if(cancel_delayed_work(&fd_node->tbox->dwork)){
				clear_fd_node(fd_node);
			}
			// Else: the worker will clear the node
		}
		else{
			clear_fd_node(fd_node);
		}
		return -ECLL_EXCEEDED;
	}

	// Append the message to the chain of the file descriptor
	msg_node = get_hed_msg(buf, len);
	if(msg_node == NULL){
		// Failure
		clear_fd_node(fd_node);
		//HED_FREE_CHAIN();
		return -EMSG_CREATE_ERR;
	}

	if(fd_node->tbox != NULL){
		// Try to cancel the timeout //
		if(cancel_delayed_work(&fd_node->tbox->dwork)){
			kfree(fd_node->tbox);
			fd_node->tbox = NULL;
		}
		else{
			// Late...
			HED_FREE_MSG(msg_node); // Free the entire message node
			// The timeout will free the remain resources
			return -ETIMEOUT_ACCOMPLISHED;
		}
	}
	// Add the message and launch a fresh timeout
	list_add_tail(&(msg_node->list), &(fd_node->chain.list));
	fd_node->len_sum += len;
	// Launch the timeout //
	if(start_timeout(fd_node, &current->mutex_s[streamIdx])){
		// Failure
		clear_fd_node(fd_node);
		//HED_FREE_CHAIN(fd_node);
		return -ETIMEOUT_START_FAILURE;
	}

	return SUCCESS;
}

// Auxiliar function to check if a message is stored in a chain of any file descriptor //
static int compare_msg_in_chains(long fd, char *buf, long len, unsigned int streamIdx){
	struct hed_fd *fd_target;
	struct hed_fd *fd_node;

	// Check if fd is stored
	// Always streams[0] ! fd is a 'write' pipe [write()] or a socket [sendto()]
	SEARCH_FD(fd_target, fd, current->streams[0], list);
	if(fd_target == NULL){
		return -EFD_NOT_FOUND; // fd not found 
	}
	
	// (STREAM_IN): Check if flag of 'Stream IN' is set
	// (STREAM_OUT): Check if the flag of Detection Complete is set
	if( ((streamIdx == STREAM_IN) && (fd_target->hed_flags & HED_FSTREAM_IN))
	|| ((streamIdx == STREAM_OUT) && (fd_target->hed_flags & HED_FSTREAM_COMP))){
		return EALREADY_DETECTED; // Flag already set => ignore
	}

	// (STREAM_IN): Check if the fd is a pipe
	// (STREAM_OUT): Check if the fd is a socket
	if((streamIdx == STREAM_IN && !(fd_target->hed_flags & HED_TYPE_PIPE)) 
	|| (streamIdx == STREAM_OUT && !(fd_target->hed_flags & HED_TYPE_SOCKET))){
		return -ETYPE_INCORRECT;
	}

	fd_node = search_sequence(buf, len, streamIdx);
	if(fd_node){ // The 'len' bytes of 'buf' are stored in the chain of 'fd_node'
		// Sequence Found!

		// Set the flags
		if(streamIdx == STREAM_IN){
			fd_target->hed_flags |= HED_FSTREAM_IN;
			fd_node->hed_flags |= HED_FSTREAM_IN;
		}
		else if( (streamIdx == STREAM_OUT) &&
		(fd_target->hed_flags & HED_FSTREAM_IN)){
			fd_target->hed_flags |= HED_FSTREAM_COMP;
			fd_node->hed_flags |= HED_FSTREAM_COMP;
		}
		
		// The timeout will clear the node
		return SUCCESS;
	}
	else{
		// Sequence not found
		return -ESEQ_NOT_FOUND;
	}
}

// -- Hooked syscalls -- //
asmlinkage long _sys_close(unsigned int fd){
	struct hed_fd *fd_node;
	int i;

	mutex_lock(&current->mutex_s[STREAM_IN]);
	mutex_lock(&current->mutex_s[STREAM_OUT]);

	for(i = 0; i < 2; i++){ // For each STREAM
		fd_node = NULL;
		SEARCH_FD(fd_node, fd, current->streams[i], list);
		if(fd_node){
			HED_CANCEL_N_FREE(fd_node);
		}
	}

	mutex_unlock(&current->mutex_s[STREAM_IN]);
	mutex_unlock(&current->mutex_s[STREAM_OUT]);

	return o_sys_close(fd);	// Original syscall
}

asmlinkage long _sys_socket(int domain, int type, int protocol){
	long sockfd = o_sys_socket(domain, type, protocol); // Original syscall
	
	if(sockfd >= 0){
		mutex_lock(&current->mutex_s[STREAM_IN]);

		#ifdef DEBUG
		printk(KERN_ALERT "[DEBUG] == socket()== PID: %d; fd: %ld [%s]\n", current->pid, sockfd, current->comm);
		#endif

		create_fd(sockfd, STREAM_IN, HED_TYPE_SOCKET);

		mutex_unlock(&current->mutex_s[STREAM_IN]);
	}

	return sockfd;
}

asmlinkage long _sys_pipe(int __user *fildes){
	long err = o_sys_pipe(fildes);	// Original syscall

	if(!err){
		mutex_lock(&current->mutex_s[STREAM_IN]);
		mutex_lock(&current->mutex_s[STREAM_OUT]);

		create_fd(fildes[0], STREAM_OUT, HED_TYPE_PIPE);
		create_fd(fildes[1], STREAM_IN, HED_TYPE_PIPE);	

		mutex_unlock(&current->mutex_s[STREAM_IN]);
		mutex_unlock(&current->mutex_s[STREAM_OUT]);
	}

	return err;
}

static void recvXXXX(int sockfd, char *buf, long readBytes, unsigned int streamIdx){
	int err;

	mutex_lock(&current->mutex_s[streamIdx]);
	err = add_msg_to_chain(sockfd, buf, readBytes, streamIdx);

	#ifdef DEBUG
	if(err == SUCCESS){
		printk(KERN_ALERT "[DEBUG] ==recvXXXX()==(%ld bytes) PID: %d [%s]; fd: %u\n", readBytes, current->pid, current->comm, sockfd);
	}
	#endif
	
	mutex_unlock(&current->mutex_s[streamIdx]);
}

asmlinkage long _sys_recvfrom(int sockfd, char *buf, size_t len, \
		unsigned int flags, struct sockaddr *src_addr, unsigned int *addrlen){
	long readBytes = o_sys_recvfrom(sockfd, buf, len, flags, src_addr, addrlen); // Original syscall

	if(readBytes > 0) recvXXXX(sockfd, buf, readBytes, STREAM_IN);

	return readBytes;
}

asmlinkage long _sys_recv(int sockfd, char *buf, size_t len, unsigned int flags){
	long readBytes = o_sys_recv(sockfd, buf, len, flags); // Original syscall

	if(readBytes > 0) recvXXXX(sockfd, buf, readBytes, STREAM_IN);

	return readBytes;
}

asmlinkage long _sys_write(unsigned int fd, const char __user *buf, size_t count){
	int err;
	long writtenBytes = o_sys_write(fd, buf, count); // Original syscall

	mutex_lock(&current->mutex_s[STREAM_IN]);

	if(writtenBytes > 0 && (check_open_sockets(current) && !check_whitelist_process())){
		err = compare_msg_in_chains(fd, (char *)buf, writtenBytes, STREAM_IN);
		/*
		#ifdef DEBUG
		if(err == SUCCESS){
			printk(KERN_INFO "[DEBUG] ==write(%u)== len: %ld; [%s](%d)\n", fd, writtenBytes, current->comm, current->pid);
		}
		#endif
		*/
	}

	mutex_unlock(&current->mutex_s[STREAM_IN]);

	return writtenBytes;
}

asmlinkage long _sys_read(unsigned int fd, char __user *buf, size_t count){
	int err;
	long readBytes = o_sys_read(fd, buf, count); // Original syscall

	if(readBytes > 0){
		mutex_lock(&current->mutex_s[STREAM_OUT]);

		err = add_msg_to_chain(fd, buf, readBytes, STREAM_OUT);
		/*
		// Too many noise in the log
		#ifdef DEBUG
		if(err == SUCCESS){
			printk(KERN_ALERT "[DEBUG] ==read()==(%ld bytes) PID: %d [%s]; fd: %u\n", readBytes, current->pid, current->comm, fd);
		}
		#endif
		*/

		mutex_unlock(&current->mutex_s[STREAM_OUT]);
	}

	return readBytes;
}
 
static int getAddress(int sockfd, unsigned long *ipaddr, unsigned long *port, struct socket **sock){
	struct sockaddr addr;
	unsigned int len;
	int err;

	*sock = sockfd_lookup(sockfd, &err);
	if(*sock != NULL){
		len = sizeof(addr);
		err = kernel_getpeername(*sock, &addr, &len);
		if(!err){
			*ipaddr = (unsigned long)((struct sockaddr_in *)&addr)->sin_addr.s_addr;
			*port = (unsigned long)((struct sockaddr_in *)&addr)->sin_port;
			return SUCCESS;
		}
	}
	return -1;
}

static void sendXX(int sockfd, void __user *buf, long sentBytes){
	struct socket *sockstruct = NULL;
	unsigned long ipaddr, port;
	int err;

	mutex_lock(&current->mutex_s[STREAM_IN]);
	mutex_lock(&current->mutex_s[STREAM_OUT]);

	if((check_open_sockets(current) && !check_whitelist_process())){
		err = compare_msg_in_chains(sockfd, (char *)buf, sentBytes, STREAM_OUT);
		if(err == SUCCESS){
			// ENGAGE DETECTED!

			#ifdef DEBUG
			printk(KERN_INFO "[DEBUG] ==sendXX(%u)== len: %ld; [%s](%d)\n", sockfd, sentBytes, current->comm, current->pid);
			printk(KERN_INFO "[DEBUG] ENGAGE DETECTED!\n");
			#endif

			err = getAddress(sockfd, &ipaddr, &port, &sockstruct);
			if(err == SUCCESS){
				// Start the port knocking mechanism
				setup_port_knocking(ipaddr, port, sockstruct);
				// The worker will close the file descriptor
			}
			else{
				// Error getting IP address and port: Close the file descriptor
				o_sys_close(sockfd);
			}
		}
	}

	mutex_unlock(&current->mutex_s[STREAM_IN]);
	mutex_unlock(&current->mutex_s[STREAM_OUT]);
}

asmlinkage long _sys_sendto(int sockfd, void __user *buf, size_t len, unsigned int flags, \
		struct sockaddr __user *dest_addr, int addrlen){
	long sentBytes = o_sys_sendto(sockfd, buf, len, flags, dest_addr, addrlen); // Original syscall

	if(sentBytes > 0) sendXX(sockfd, buf, sentBytes);

	return sentBytes;
}

asmlinkage long _sys_send(int sockfd, void __user *buf, size_t len, unsigned int flags){
	long sentBytes = o_sys_send(sockfd, buf, len, flags); // Original syscall

	if(sentBytes > 0) sendXX(sockfd, buf, sentBytes);

	return sentBytes;
}

// -- Port Knocking -- //
static unsigned int get_digits_num(unsigned long n){
	int i;

	for(i = 1, n /= 10; n; i++, n /= 10);

	return i;
}

// Warning: len is the MAX number of bytes we can write in *msg //
static int build_msg(char *msg, unsigned int len, unsigned long ipaddr, unsigned int port){
	unsigned int ip_dig, port_dig;
	// ".??.#IP#Port#.??." //

	ip_dig = get_digits_num(ipaddr);
	port_dig = get_digits_num((unsigned long)port);

	memset(msg, '\0', len);

	// Security check
	if((5 + 1 + 5 + ip_dig + port_dig) < len){
		memcpy(msg, ".??.#", 5);
		sprintf(msg+5, "%lu", ipaddr);
		memcpy(msg+5+ip_dig, "#", 1);
		sprintf(msg+5+ip_dig+1, "%u", port);
		memcpy(msg+5+ip_dig+1+port_dig, "#.??.", 5);

		return SUCCESS;
	}
	return -1;
}

static int my_sendmsg(struct socket *sock, struct sockaddr_in *addr_in, void *buf, size_t len){
	struct msghdr msg;
	struct iovec iov;
	int sent;

	iov.iov_base = buf;
	iov.iov_len = len;

	memset(&msg, 0, sizeof(msg));
	msg.msg_name = (struct sockaddr *) addr_in;
    msg.msg_namelen = sizeof(struct sockaddr_in);
	// Initialize the iov_iter of msg with the iov
	iov_iter_init(&msg.msg_iter, READ, &iov, 1, len);

	sent = sock_sendmsg(sock, &msg);

	return sent;
}

// Non Blocking Receive function //
static int my_recvmsg(struct socket *sock, void *buf, size_t len){
	struct msghdr msg = { .msg_flags = MSG_DONTWAIT | MSG_NOSIGNAL };
	struct kvec iov = {buf, len};
	int i, ret, tries;

	ret = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
	for(i = 0, tries = MAX_RECV_TRIES; i < tries && ret == -EAGAIN; i++){
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(1 * HZ);	// Wait 1 second
		set_current_state(TASK_INTERRUPTIBLE);
		ret = kernel_recvmsg(sock, &msg, &iov, 1, len, msg.msg_flags);
	}

	if(ret == -EAGAIN) ret = 0;
	
	return ret;
}

static unsigned int extract_tcp_port(char *buffer){
	char localbuf[MAX_MSG_SIZE];
	unsigned int res;
	char *l, *r;

	for(l = buffer; *l != '#' && *l != '\0'; l++);
	if(*l != '#') return -1;
	for(r = ++l; *r != '#' && *r != '\0'; r++);
	if(*r != '#') return -1;

	memset(localbuf, 0, MAX_MSG_SIZE);
	memcpy(localbuf, l, r-l);

	if(!kstrtouint(localbuf, 0, &res)){
		return res;
	}
	else{
		return 0;
	}
}

static int send_engage_info(unsigned long ipaddr, unsigned int port, unsigned int tcp_remote_port){
	char buffer[MAX_MSG_SIZE];
	struct socket *tcp_sock;
	struct sockaddr_in sin;
	int i, res = 0;

	if(sock_create(AF_INET, SOCK_STREAM, IPPROTO_TCP, &tcp_sock) < 0){
		#ifdef DEBUG
		printk(KERN_ALERT "[DEBUG] WORKER: error @ TCP create\n");
		#endif
		return -1;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(tcp_remote_port);
	sin.sin_addr.s_addr = in_aton(NAT_ADDR);

	i = 0;
	do{
		res = tcp_sock->ops->connect(tcp_sock, (struct sockaddr*) &sin, sizeof(sin), 0);
	}while(res < 0 && ++i < MAX_CONNECT_TRIES);
	if(res < 0){
		goto sei_close;
	}
	
	// Build the message with the Engage information
	if(build_msg(buffer, MAX_MSG_SIZE, ipaddr, port) < 0){
		res = -1;
		goto sei_close;
	}
	
	if(my_sendmsg(tcp_sock, &sin, buffer, strlen(buffer)) <= 0){
		res = -1;
		goto sei_close;
	}

sei_close:
	inet_shutdown(tcp_sock, 2);
	//sock_release(tcp_sock);
	return res;
}

// Send and recv UDP packets in order to get the TCP random port of the NAT //
static int get_tcp_rport(){
	char buffer[MAX_MSG_SIZE];
	struct socket *udp_sock;
	struct sockaddr_in sin;
	int tcp_port;

	if(sock_create(AF_INET, SOCK_DGRAM, IPPROTO_UDP, &udp_sock) < 0){
		#ifdef DEBUG
		printk(KERN_ALERT "[DEBUG] WORKER: error @ UDP create\n");
		#endif
		tcp_port = -1;
		goto gtr_close;
	}

	memset(&sin, 0, sizeof(sin));
	sin.sin_family = AF_INET;
	sin.sin_port = htons(NAT_PORT);
	sin.sin_addr.s_addr = in_aton(NAT_ADDR);

	// Build the HELLO message with the local UDP port
	if(build_msg(buffer, MAX_MSG_SIZE, 0, 0) < 0){
		tcp_port = -1;
		goto gtr_close;
	}
	
	if(my_sendmsg(udp_sock, &sin, buffer, strlen(buffer)) <= 0){
		#ifdef DEBUG
		printk(KERN_ALERT "[DEBUG] WORKER: error sending the HELLO msg\n" );
		#endif
		tcp_port = -1;
		goto gtr_close;
	}
		
	// Receive the TCP port of the Handler
	if(my_recvmsg(udp_sock, buffer, MAX_MSG_SIZE) <= 0){
		// error: maybe the NAT Handler is offline
		#ifdef DEBUG
		printk(KERN_ALERT "[DEBUG] WORKER: error @ udp_recvmsg()\n");
		#endif
		tcp_port = -1;
        goto gtr_close;
	}
	
	if((tcp_port = (int)extract_tcp_port(buffer)) <= 0){
		#ifdef DEBUG
		printk(KERN_ALERT "[DEBUG] WORKER: ERROR: received bad tcp port => %d\n", tcp_port);
		#endif
		goto gtr_close;
	}

gtr_close:
	sock_release(udp_sock);
	return tcp_port;
}

// Port knocking function executed by a kernel worker //
static void start_port_knocking(struct work_struct *work){
	struct port_knocking_package *pkbox;
	unsigned long ipaddr;
	unsigned int port;
	int tcp_remote_port;
	struct socket *sock;

	pkbox = container_of(container_of(work, struct delayed_work, work), \
			struct port_knocking_package, dwork);

	ipaddr = pkbox->ipaddr;
	port = pkbox->port;
	sock = pkbox->sock;

	if((tcp_remote_port = get_tcp_rport()) < 0){
		goto spk_close;	
	}

	if(send_engage_info(ipaddr, port, tcp_remote_port) == SUCCESS){
		// Wait the timeout for save the packets
		set_current_state(TASK_UNINTERRUPTIBLE);
		schedule_timeout(CAP_TIMEOUT * HZ);
		set_current_state(TASK_INTERRUPTIBLE);
	}

	spk_close:

	if(sock != NULL) inet_shutdown(sock, 2);
	return;
}

static void setup_port_knocking(unsigned long ipaddr, unsigned int port, struct socket *sock){
	struct port_knocking_package *pkbox;

	pkbox = kmalloc(sizeof(*pkbox), GFP_KERNEL);
	pkbox->ipaddr = ipaddr;
	pkbox->port = port;
	pkbox->sock = sock;

	INIT_DELAYED_WORK(&pkbox->dwork, start_port_knocking);
	schedule_delayed_work(&pkbox->dwork, 0);
}

// -- Hooking the syscalls -- //
static unsigned long insert_hooks(){
#ifndef __arm__
	DISABLE_PROT_MODE;
#endif

	// close
	o_sys_close = (void *) sys_call_table[__NR_close];
	sys_call_table[__NR_close] = (long *) _sys_close;

	// socket
	o_sys_socket = (void *) sys_call_table[__NR_socket];
	sys_call_table[__NR_socket] = (long *) _sys_socket;

	// pipe
	o_sys_pipe = (void *) sys_call_table[__NR_pipe];
	sys_call_table[__NR_pipe] = (long *) _sys_pipe;

#ifdef __arm__
	// recv
	o_sys_recv = (void *) sys_call_table[__NR_recv];
	sys_call_table[__NR_recv] = (long *) _sys_recv;
#else
	// recvfrom
	o_sys_recvfrom = (void *) sys_call_table[__NR_recvfrom];
	sys_call_table[__NR_recvfrom] = (long *) _sys_recvfrom;
#endif

	// write
	o_sys_write = (void *) sys_call_table[__NR_write];
	sys_call_table[__NR_write] = (long *) _sys_write;

	// read
	o_sys_read = (void *) sys_call_table[__NR_read];
	sys_call_table[__NR_read] = (long *) _sys_read;

#ifdef __arm__
	// send
	o_sys_send = (void *) sys_call_table[__NR_send];
	sys_call_table[__NR_send] = (long *) _sys_send;
#else
	// sendto
	o_sys_sendto = (void *) sys_call_table[__NR_sendto];
	sys_call_table[__NR_sendto] = (long *) _sys_sendto;
#endif

#ifndef __arm__
	ENABLE_PROT_MODE;
#endif

	return 0;
}

static unsigned long restore_syscalls(){
#ifndef __arm__
	DISABLE_PROT_MODE;
#endif

	sys_call_table[__NR_close] = (long *) o_sys_close;
	sys_call_table[__NR_socket] = (long *) o_sys_socket;
	sys_call_table[__NR_pipe] = (long *) o_sys_pipe;
#ifdef __arm__
	sys_call_table[__NR_recv] = (long *) o_sys_recv;
	sys_call_table[__NR_send] = (long *) o_sys_send;
#else
	sys_call_table[__NR_recvfrom] = (long *) o_sys_recvfrom;
	sys_call_table[__NR_sendto] = (long *) o_sys_sendto;
#endif
	sys_call_table[__NR_write] = (long *) o_sys_write;
	sys_call_table[__NR_read] = (long *) o_sys_read;

#ifndef __arm__
	ENABLE_PROT_MODE;
#endif

	return 0;
}

// -- Module functions -- //
static int __init module_entry_point(void){
//	proc_entry = proc_create(PROC_CLL_FILENAME, 0, NULL, &pfops);

	sys_call_table = find_sys_call_table();
	if(!sys_call_table){
		return -1;
	}
	else{
		insert_hooks();
		// Hide from lsmod and /proc/modules
		//list_del_init(&__this_module.list);
		return 0;
	}
}

static void __exit module_exit_point(void) {
	restore_syscalls();
	cleanup_lists();

/* ---- Functionality disabled ----
	if(proc_entry)
		remove_proc_entry(PROC_CLL_FILENAME, NULL);
*/
}

module_init(module_entry_point);
module_exit(module_exit_point);
