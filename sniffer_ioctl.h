#ifndef __SNIFFER_IOCTL_
#define __SNIFFER_IOCTL__

struct sniffer_flow_entry {
    int source_port;
    int dest_port;
    char source_ip[16];
    char dest_ip[16];
    char action[8];
    char mode[8];
};

#define SNIFFER_IOC_MAGIC       'p'

#define SNIFFER_FLOW_ENABLE     _IOW(SNIFFER_IOC_MAGIC, 0x1, struct sniffer_flow_entry)
#define SNIFFER_FLOW_DISABLE    _IOW(SNIFFER_IOC_MAGIC, 0x2, struct sniffer_flow_entry)

#define SNIFFER_IOC_MAXNR   0x3


#define SNIFFER_ACTION_NULL     0x0
#define SNIFFER_ACTION_CAPTURE  0x1
#define SNIFFER_ACTION_DPI      0x2

#endif /* __SNIFFER_IOCTL__ */
