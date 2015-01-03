/*
 * sniffer skeleton (Linux kernel module)
 *
 * Copyright (C) 2014 Ki Suh Lee <kslee@cs.cornell.edu>
 * based on netslice implementation of Tudor Marian <tudorm@cs.cornell.edu>
 */

#include <linux/module.h>
#include <linux/cdev.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/moduleparam.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <linux/netfilter_ipv4.h>
#include <linux/inet.h>
#include <linux/mm.h>
#include <linux/udp.h>
#include <linux/fs.h>
#include <net/ip.h>
#include <net/tcp.h>
#include <linux/sched.h>
#include <linux/mm.h> 
#include <linux/proc_fs.h>
#include "sniffer_ioctl.h"

MODULE_AUTHOR("");
MODULE_DESCRIPTION("CS5413 Packet Filter / Sniffer Framework");
MODULE_LICENSE("Dual BSD/GPL");

static dev_t sniffer_dev;
static struct cdev sniffer_cdev;
static int sniffer_minor = 1;
atomic_t refcnt;
atomic_t rule_lock;
static int hook_chain = NF_INET_LOCAL_IN;
static int hook_prio = NF_IP_PRI_FIRST;
struct nf_hook_ops nf_hook_ops;
static DECLARE_WAIT_QUEUE_HEAD(wq);
static int flag = 0;

// skb buffer between kernel and user space
struct list_head *skbs,*n;

// skb wrapper for buffering
struct skb_list 
{
    struct list_head list;
    struct sk_buff *skb;
};
struct skb_list skb_head;
struct skb_list *skb_trav,*skb_new;

//Rule list
struct sniffer_rule_list {
    struct sniffer_flow_entry *data;
    struct sniffer_rule_list *next;
};
struct sniffer_rule_list *head,*curr,*to_add = NULL;

static inline struct tcphdr * ip_tcp_hdr(struct iphdr *iph)
{
    struct tcphdr *tcph = (void *) iph + iph->ihl*4;
    return tcph;
}

/* From kernel to userspace */
static ssize_t 
sniffer_fs_read(struct file *file, char __user *buf, size_t count, loff_t *pos)
{
    unsigned long len;
    struct skb_list *skb_item = NULL;
    local_irq_disable();
    if(atomic_read(&refcnt) >0){
    	printk(KERN_DEBUG "Value is greater than 0");
    	return 0;
    }
    atomic_inc(&refcnt);
    flag = 0;
    len = 0;
   
    list_for_each_safe(skbs,n,&skb_head.list){

    	printk(KERN_DEBUG "Came here\n");
	skb_item = list_entry(skbs,struct skb_list,list);
	list_del(&skb_item->list);
	if(skb_item){
	  break;
	}
    }
    
    if(!skb_item){
    	printk(KERN_DEBUG "process %i (%s) going to sleep\n",
	            current->pid, current->comm);
	local_irq_enable();
	wait_event_interruptible(wq, flag != 0);
	local_irq_disable();
	flag = 0;
	printk(KERN_DEBUG "awoken %i (%s)\n", current->pid, current->comm);
    	
	list_for_each(skbs,&skb_head.list){
    		printk(KERN_DEBUG "Came here\n");
		skb_item = list_entry(skbs,struct skb_list,list);
		list_del(&skb_item->list);
		if(skb_item){
	  		break;
		}
	}
    }

    if(skb_item){ 
    	len = skb_item->skb->len;
    	if(count <len){
    		len = count ;
    	}
    	if (copy_to_user(buf,skb_item->skb->data, len) !=0 ){
		len = -EFAULT;
    	}
    	kfree_skb(skb_item->skb);
    	kfree(skb_item);
    }
    
    atomic_dec(&refcnt);
    local_irq_enable();
    return len;
}

static int sniffer_fs_open(struct inode *inode, struct file *file)
{
    struct cdev *cdev = inode->i_cdev;
    int cindex = iminor(inode);
    
    if (!cdev) {
        printk(KERN_ERR "cdev error\n");
        return -ENODEV;
    }

    if (cindex != 0) {
        printk(KERN_ERR "Invalid cindex number %d\n", cindex);
        return -ENODEV;
    }

    return 0;
}

static int sniffer_fs_release(struct inode *inode, struct file *file)
{
    return 0;
}

static long sniffer_fs_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    long err =0 ;
    int found =0;
    struct sniffer_flow_entry *new_flow; 
    struct sniffer_rule_list *new_rule; 
   
    if (_IOC_TYPE(cmd) != SNIFFER_IOC_MAGIC)
        return -ENOTTY; 
    if (_IOC_NR(cmd) > SNIFFER_IOC_MAXNR)
        return -ENOTTY;
    if (_IOC_DIR(cmd) & _IOC_READ)
        err = !access_ok(VERIFY_WRITE, (void __user *)arg, _IOC_SIZE(cmd));
    if (_IOC_DIR(cmd) & _IOC_WRITE)
        err = !access_ok(VERIFY_READ, (void __user *)arg, _IOC_SIZE(cmd));
    if (err)
        return -EFAULT;

    switch(cmd) {
    
    case SNIFFER_FLOW_ENABLE:
    case SNIFFER_FLOW_DISABLE:
   	local_irq_disable();
   	new_flow = (struct sniffer_flow_entry*)arg;
	if(head == NULL){
		new_rule = kmalloc(sizeof (struct sniffer_rule_list), GFP_ATOMIC);
		if (!new_rule){
			printk(KERN_ERR "Not enough memory\n");
			err = -ENOMEM;
			break;
		}
		new_rule->data = kmalloc(sizeof(struct sniffer_flow_entry),GFP_ATOMIC);
		if (!new_rule->data){
			err = -ENOMEM;
			printk(KERN_ERR "Not enough memory for data\n");
			break;
		}
		memcpy(&new_rule->data->mode,&new_flow->mode,sizeof(new_rule->data->mode));
		memcpy(&new_rule->data->source_ip,&new_flow->source_ip,sizeof(new_rule->data->source_ip));
		memcpy(&new_rule->data->dest_ip,&new_flow->dest_ip,sizeof(new_rule->data->dest_ip));
		memcpy(&new_rule->data->action,&new_flow->action,sizeof(new_rule->data->action));
		new_rule->data->source_port = new_flow->source_port;
		new_rule->data->dest_port = new_flow->dest_port;

		new_rule->next = NULL;
	    	head = new_rule;
	} else{
	    curr = head;
	    while(curr!= NULL){
	    	if((curr->data->source_port == new_flow->source_port || curr->data->source_port == -1) && (!strcmp(curr->data->source_ip,new_flow->source_ip) || !strcmp(curr->data->source_ip,"any")) && ( !strcmp(curr->data->dest_ip,new_flow->dest_ip) || !strcmp(curr->data->dest_ip,"any")) && (curr->data->dest_port == new_flow->dest_port || curr->data->dest_port == -1)){
			printk(KERN_ERR "Rule Matched\n");			
			found = 1;
			break;
		}
		to_add = curr;
	    	curr = curr->next;
	    }
	    if(found){
		memcpy(&curr->data->mode,&new_flow->mode,sizeof(curr->data->mode));
		memcpy(&curr->data->source_ip,&new_flow->source_ip,sizeof(curr->data->source_ip));
		memcpy(&curr->data->dest_ip,&new_flow->dest_ip,sizeof(curr->data->dest_ip));
		memcpy(&curr->data->action,&new_flow->action,sizeof(curr->data->action));
		curr->data->source_port = new_flow->source_port;
		curr->data->dest_port = new_flow->dest_port;
	    }else{
		new_rule = kmalloc(sizeof (struct sniffer_rule_list), GFP_ATOMIC);
		if (!new_rule){
			printk(KERN_ERR "Not enough memory\n");
			err = -ENOMEM;
			break;
		}
		new_rule->data = kmalloc(sizeof(struct sniffer_flow_entry),GFP_ATOMIC);
		if (!new_rule->data){
			printk(KERN_ERR "Not enough memory for data\n");
			err = -ENOMEM;
			break;
		}
		memcpy(&new_rule->data->mode,&new_flow->mode,sizeof(new_rule->data->mode));
		memcpy(&new_rule->data->source_ip,&new_flow->source_ip,sizeof(new_rule->data->source_ip));
		memcpy(&new_rule->data->dest_ip,&new_flow->dest_ip,sizeof(new_rule->data->dest_ip));
		memcpy(&new_rule->data->action,&new_flow->action,sizeof(new_rule->data->action));
		new_rule->data->source_port = new_flow->source_port;
		new_rule->data->dest_port = new_flow->dest_port;
		new_rule->next = NULL;
	    	to_add->next = new_rule;
	    }

	}
		
	break;
    default:
        printk(KERN_DEBUG "Unknown command\n");
        err = -EINVAL;
    }
    local_irq_enable();
    return err;
}

static struct file_operations sniffer_fops = {
    .open = sniffer_fs_open,
    .release = sniffer_fs_release,
    .read = sniffer_fs_read,
    .unlocked_ioctl = sniffer_fs_ioctl,
    .owner = THIS_MODULE,
};

int sniffer_read_procmem(char *buf, char **start, off_t offset,
                   int count, int *eof, void *data)
{
	int len = 0;
	char *str = "#     [command]     [src_ip]      [src_port]     [dst_ip]     [dst_port]     [action]";
	char *mode;
	char *src_ip;
	char *dst_ip;
	char *action;
	int src_port;
	int dst_port;
	char *src_port_char;
	char *dst_port_char;
	int i = 0;
	
	len +=sprintf(buf+len,"%s\n",str);
	curr = head;	
	while(curr != NULL){
		i++;
		len +=sprintf(buf+len,"%d",i);
		
		mode = curr->data->mode;
		len +=sprintf(buf+len,"       %s",mode);

		src_ip = curr->data->source_ip;
		len +=sprintf(buf+len,"       %s",src_ip);

		if(curr->data->source_port == -1){
		       src_port_char = "any";
		       len +=sprintf(buf+len,"          %s",src_port_char);
		} else {
		       src_port = curr->data->source_port;
		       len +=sprintf(buf+len,"          %d",src_port);

		}
		
		dst_ip = curr->data->dest_ip;
		len +=sprintf(buf+len,"             %s",dst_ip);
		
		
		if(curr->data->dest_port == -1){
		       dst_port_char = "any";
		       len +=sprintf(buf+len,"            %s",dst_port_char);
		} else {
		       dst_port = curr->data->dest_port;
			len +=sprintf(buf+len,"               %d",dst_port);
		}
		
		action = curr->data->action;
		len +=sprintf(buf+len,"             %s",action);
		len +=sprintf(buf+len,"\n");
		curr= curr->next;
	}
	return len;
}
int packet_capture(struct sk_buff* skb){
	skb_new = kmalloc(sizeof(*skb_new),GFP_ATOMIC);
	if(skb_new == NULL){
		printk(KERN_DEBUG "Memory allocation failed!! \n");
		return -ENOMEM;
	}
	skb_new->skb = skb_copy(skb,GFP_ATOMIC);
	list_add(&(skb_new->list), &(skb_head.list));
        printk(KERN_DEBUG "process %i (%s) awakening the readers...\n",
	            current->pid, current->comm);
	flag = 1;
	wake_up_interruptible(&wq);
	return 0;
}

int packet_dpi(unsigned char* pkt,int len){
	int i;
	unsigned char s[] = {0x76,0x69,0x72,0x75,0x73}; /* HEX CODE for VIRUS*/
	//unsigned char s[] = {0x67,0x6f,0x74}; /*HEX CODE FOR got*/
	for(i = 0; i<len; i++){
		if(i+sizeof(s) <= len)
		{
			if(!memcmp(&pkt[i],s,sizeof(s)))
	 		{
	 			printk(KERN_DEBUG" Packet signature found!!\n");
	 			return 1;
			}
		}
	}
	return 0;
}
	
static unsigned int sniffer_nf_hook(unsigned int hook, struct sk_buff* skb,
        const struct net_device *indev, const struct net_device *outdev,
        int (*okfn) (struct sk_buff*))
{
    struct iphdr *iph = ip_hdr(skb);
    int found =0,ret;
    char source[16];
    char dest[16];
    struct sniffer_rule_list *new_rule; 
    if (iph->protocol == IPPROTO_TCP) {
        struct tcphdr *tcph = ip_tcp_hdr(iph);
			
        if (ntohs(tcph->dest) == 22)
            return NF_ACCEPT;

        if (ntohs(tcph->dest ) != 22) {
   	snprintf(source, 16, "%pI4", &iph->saddr);
	snprintf(dest, 16, "%pI4", &iph->daddr);

	local_irq_disable();
	curr = head;	
	while(curr != NULL){
	    	if((curr->data->source_port == ntohs(tcph->source) || curr->data->source_port == -1) && (!strcmp(curr->data->source_ip,source) || !strcmp(curr->data->source_ip,"any")) && (curr->data->dest_port == ntohs(tcph->dest) || curr->data->dest_port == -1)){
			found = 1;
			break;
		}
		curr= curr->next;
	}
	 if(found){
	 	//mode - enable
	 	if(!strcmp(curr->data->mode,"enable")){
                	printk(KERN_DEBUG "ENABLE Accepted DESTPORT%d %s SOURCEPORT%d %s\n", ntohs(tcph->dest), dest,ntohs(tcph->source),source);
			if(!strcmp(curr->data->action,"capture")){

			   ret = packet_capture(skb);
			   if(ret != 0){
			 	printk(KERN_DEBUG "Packet Capture Failed!!\n");
			   }
			
			}else if (!strcmp(curr->data->action,"dpi")){
			   ret = packet_dpi(skb->data,skb->len);
			   if(ret){
				if(head == NULL){
					new_rule = kmalloc(sizeof(struct sniffer_rule_list), GFP_ATOMIC);
					if(new_rule == NULL){
						printk(KERN_ERR "Not enough memory\n");
					        goto done;	
					}
					strncpy(new_rule->data->mode,"disable",sizeof(new_rule->data->mode));
					strncpy(new_rule->data->source_ip,source,sizeof(new_rule->data->source_ip));
					strncpy(new_rule->data->dest_ip,dest,sizeof(new_rule->data->dest_ip));
					strncpy(new_rule->data->action,"none",sizeof(new_rule->data->action));
					new_rule->data->source_port = ntohs(tcph->source);
					new_rule->data->dest_port = ntohs(tcph->dest);
					new_rule->next = NULL;
			    		head = new_rule;
				}
				else {
	    			curr = head;
				found =0;
	    			while(curr!= NULL){
	    				if((curr->data->source_port == ntohs(tcph->source)  || curr->data->source_port == -1) && (!strcmp(curr->data->source_ip,source) || !strcmp(curr->data->source_ip,"any")) && ( !strcmp(curr->data->dest_ip,dest) || !strcmp(curr->data->dest_ip,"any")) && (curr->data->dest_port == ntohs(tcph->dest) || curr->data->dest_port == -1)){

						found = 1;
						break;
					}
					to_add = curr;
	    				curr = curr->next;
	    			}
	    			if(found){
					strncpy(curr->data->mode,"disable",sizeof(new_rule->data->mode));
					strncpy(curr->data->source_ip,source,sizeof(new_rule->data->source_ip));
					strncpy(curr->data->dest_ip,dest,sizeof(new_rule->data->dest_ip));
					strncpy(curr->data->action,"none",sizeof(new_rule->data->action));
					curr->data->source_port = ntohs(tcph->source);
					curr->data->dest_port = ntohs(tcph->dest);
	    			}else{
					new_rule = kmalloc(sizeof (struct sniffer_rule_list), GFP_ATOMIC);
					if (!new_rule){
						printk(KERN_ERR "Not enough memory\n");
						goto done;
					}
					strncpy(new_rule->data->mode,"disable",sizeof(new_rule->data->mode));
					strncpy(new_rule->data->source_ip,source,sizeof(new_rule->data->source_ip));
					strncpy(new_rule->data->dest_ip,dest,sizeof(new_rule->data->dest_ip));
					strncpy(new_rule->data->action,"none",sizeof(new_rule->data->action));
					new_rule->data->source_port = ntohs(tcph->source);
					new_rule->data->dest_port = ntohs(tcph->dest);
					new_rule->next = NULL;
	    				to_add->next = new_rule;
				    }
				}
				done:
				local_irq_enable();
				return NF_DROP;
			   }
			}
			local_irq_enable();
			return NF_ACCEPT;
		}else {
			printk(KERN_DEBUG "DISABLE Rejected DESTPORT %d %s SOURCEPORT %d %s\n", ntohs(tcph->dest),dest,ntohs(tcph->source),source);
	               if(!strcmp(curr->data->action,"capture")){

			   ret = packet_capture(skb);
			   if(ret != 0){
			 	printk(KERN_DEBUG "Packet Capture Failed!!\n");
			   }
			
			}else if (!strcmp(curr->data->action,"dpi")){
			   ret = packet_dpi(skb->data,skb->len);
			   if(ret){
				if(head == NULL){
					new_rule = kmalloc(sizeof(struct sniffer_rule_list), GFP_ATOMIC);
					if(new_rule == NULL){
						printk(KERN_ERR "Not enough memory\n");
					        goto done_disable;	
					}
					strncpy(new_rule->data->mode,"disable",sizeof(new_rule->data->mode));
					strncpy(new_rule->data->source_ip,source,sizeof(new_rule->data->source_ip));
					strncpy(new_rule->data->dest_ip,dest,sizeof(new_rule->data->dest_ip));
					strncpy(new_rule->data->action,"none",sizeof(new_rule->data->action));
					new_rule->data->source_port = ntohs(tcph->source);
					new_rule->data->dest_port = ntohs(tcph->dest);
					new_rule->next = NULL;
			    		head = new_rule;
				}
				else {
	    			curr = head;
				found =0;
	    			while(curr!= NULL){
	    				if((curr->data->source_port == ntohs(tcph->source)  || curr->data->source_port == -1) && (!strcmp(curr->data->source_ip,source) || !strcmp(curr->data->source_ip,"any")) && ( !strcmp(curr->data->dest_ip,dest) || !strcmp(curr->data->dest_ip,"any")) && (curr->data->dest_port == ntohs(tcph->dest) || curr->data->dest_port == -1)){

						found = 1;
						break;
					}
					to_add = curr;
	    				curr = curr->next;
	    			}
	    			if(found){
					strncpy(curr->data->mode,"disable",sizeof(new_rule->data->mode));
					strncpy(curr->data->source_ip,source,sizeof(new_rule->data->source_ip));
					strncpy(curr->data->dest_ip,dest,sizeof(new_rule->data->dest_ip));
					strncpy(curr->data->action,"none",sizeof(new_rule->data->action));
					curr->data->source_port = ntohs(tcph->source);
					curr->data->dest_port = ntohs(tcph->dest);
	    			}else{
					new_rule = kmalloc(sizeof (struct sniffer_rule_list), GFP_ATOMIC);
					if (!new_rule){
						printk(KERN_ERR "Not enough memory\n");
						goto done_disable;
					}
					strncpy(new_rule->data->mode,"disable",sizeof(new_rule->data->mode));
					strncpy(new_rule->data->source_ip,source,sizeof(new_rule->data->source_ip));
					strncpy(new_rule->data->dest_ip,dest,sizeof(new_rule->data->dest_ip));
					strncpy(new_rule->data->action,"none",sizeof(new_rule->data->action));
					new_rule->data->source_port = ntohs(tcph->source);
					new_rule->data->dest_port = ntohs(tcph->dest);
					new_rule->next = NULL;
	    				to_add->next = new_rule;
				    }
				}
				done_disable:
				local_irq_enable();
				return NF_DROP;
			   }
			}
		
			local_irq_enable();
			return NF_DROP;
		}
	 }
 	 else{ 
	        printk(KERN_DEBUG "Rejected DESTPORT%d IP%s SOURCEPORT%d %s\n", ntohs(tcph->dest),dest,ntohs(tcph->source),source);
		local_irq_enable();
		return NF_DROP;
	   }
        }

    }
    return NF_ACCEPT;
}

static int __init sniffer_init(void)
{
    int status = 0;
    printk(KERN_DEBUG "sniffer_init\n"); 

    status = alloc_chrdev_region(&sniffer_dev, 0, sniffer_minor, "sniffer");
    if (status <0) {
        printk(KERN_ERR "alloc_chrdev_retion failed %d\n", status);
        goto out;
    }

    cdev_init(&sniffer_cdev, &sniffer_fops);
    status = cdev_add(&sniffer_cdev, sniffer_dev, sniffer_minor);
    if (status < 0) {
        printk(KERN_ERR "cdev_add failed %d\n", status);
        goto out_cdev;
        
    }

    atomic_set(&refcnt, 0);
    INIT_LIST_HEAD(&skb_head.list);

    /* register netfilter hook */
    memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    nf_hook_ops.hook = sniffer_nf_hook;
    nf_hook_ops.pf = PF_INET;
    nf_hook_ops.hooknum = hook_chain;
    nf_hook_ops.priority = hook_prio;
    status = nf_register_hook(&nf_hook_ops);
    if (status < 0) {
        printk(KERN_ERR "nf_register_hook failed\n");
        goto out_add;
    }
    create_proc_read_entry("sniffer", 0, NULL, sniffer_read_procmem, NULL);
    return 0;

out_add:
    cdev_del(&sniffer_cdev);
out_cdev:
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
out:
    return status;
}

static void __exit sniffer_exit(void)
{

    struct skb_list *skb_item = NULL;
    struct sniffer_rule_list* next_ele;
    if (nf_hook_ops.hook) {
        nf_unregister_hook(&nf_hook_ops);
        memset(&nf_hook_ops, 0, sizeof(nf_hook_ops));
    }

    list_for_each_safe(skbs,n,&skb_head.list){
	skb_item = list_entry(skbs,struct skb_list,list);
	list_del(&skb_item->list);
	if(skb_item){
      		printk(KERN_DEBUG "inside Freed capture\n"); 
    		kfree_skb(skb_item->skb);
    		kfree(skb_item);
	}
    }
    local_irq_disable();
    curr = head;
        
    while (curr != NULL)
    {
      next_ele = curr->next;
      kfree(curr);
      curr = next_ele;
    }
    head = NULL;

    local_irq_enable();
    cdev_del(&sniffer_cdev);
    unregister_chrdev_region(sniffer_dev, sniffer_minor);
    remove_proc_entry("sniffer", NULL);
}

module_init(sniffer_init);
module_exit(sniffer_exit);
