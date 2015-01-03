#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <fcntl.h>
#include <getopt.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <errno.h>
#include "sniffer_ioctl.h"

static char * program_name;
static char * dev_file = "sniffer.dev";

void usage() 
{
    fprintf(stderr, "Usage: %s [parameters]\n"
                "parameters: \n"
                "    --mode [enable|disable]\n"
                "    --src_ip [url|any] : default is any \n"
                "    --src_port [XXX|any] : default is any \n"
                "    --dst_ip [url|any] : default is any \n" 
                "    --dst_port [XXX|any] : default is any \n"
                "    --action [capture|dpi] : default is null\n", program_name);
    exit(EXIT_FAILURE);
}

int sniffer_send_command(struct sniffer_flow_entry *flow)
{
    int ret_val,file_desc;
    file_desc = open(dev_file, O_WRONLY);
    if (file_desc < 0) {
	printf("Can't open device file: %s\n", dev_file);
	exit(-1);
    }
    
    if(!strcmp(flow->mode,"enable")){
	    ret_val = ioctl(file_desc, SNIFFER_FLOW_ENABLE, flow);
    	    if (ret_val < 0) {
 		printf("ioctl_enable failed:%d\n", ret_val);
    		close(file_desc);
        	exit(-1);
    	     }	
    }
    else if(!strcmp(flow->mode,"disable")){
	    ret_val = ioctl(file_desc, SNIFFER_FLOW_DISABLE, flow);
    	    if (ret_val < 0) {
 		printf("ioctl_disable failed:%d\n", ret_val);
    		close(file_desc);
        	exit(-1);
    	     }	
    }
    close(file_desc);
    return 0;
}

int main(int argc, char **argv)
{
    int c;
    program_name = argv[0];
    struct sniffer_flow_entry flow;
    struct hostent *returned_host;
    strncpy(flow.source_ip,"any",sizeof(flow.source_ip));
    flow.source_port = -1;
    strncpy(flow.dest_ip,"any",sizeof(flow.dest_ip));
    flow.dest_port = -1;
    strncpy(flow.action,"none",sizeof(flow.action));

    while(1) {
        static struct option long_options[] = 
        {
            {"mode", required_argument, 0, 0},
            {"src_ip", required_argument, 0, 0},
            {"src_port", required_argument, 0, 0},
            {"dst_ip", required_argument, 0, 0},
            {"dst_port", required_argument, 0, 0},
            {"action", required_argument, 0, 0},
            {"dev", required_argument, 0, 0},
            {0, 0, 0, 0}
        };
        int option_index = 0;
        c = getopt_long (argc, argv, "", long_options, &option_index);

        if (c == -1)
            break;

        switch (c) {
        case 0:
            printf("option %d %s", option_index, long_options[option_index].name);
            if (optarg)
                printf(" with arg %s", optarg);
            printf("\n");
            switch(option_index) {
            case 0:     // mode
		strncpy(flow.mode,optarg,sizeof(flow.mode));;		
		break;
            case 1:     // src_ip
		if(strcmp(optarg,"any")){
		returned_host=gethostbyname(optarg);
		if(returned_host == NULL){
			printf("Error in decoding host name\n");
			exit(1);
		}
		inet_ntop(AF_INET,(void *)*returned_host->h_addr_list,flow.source_ip,sizeof(flow.source_ip));
		}
                break;
            case 2:     // src_port
	    	if(strcmp(optarg,"any")){
		flow.source_port = atoi(optarg);
		}
		break;
            case 3:     // dst_ip
		if(strcmp(optarg,"any")){
		returned_host=gethostbyname(optarg);
		if(returned_host == NULL){
			printf("Error in decoding host name\n");
			exit(1);
		}
		printf("Returned host is %s",returned_host->h_name);
		inet_ntop(AF_INET,(void *)*returned_host->h_addr_list,flow.dest_ip,sizeof(flow.dest_ip));
                }
		break;
            case 4:     // dst_port
	    	if(strcmp(optarg,"any")){
	    	flow.dest_port = atoi(optarg);
		}
                break;
            case 5:     // action
		strncpy(flow.action,optarg,sizeof(flow.action));
		printf("Action is %s\n",optarg);
                break;
            case 6:     // dev
		dev_file = optarg;
		break;
            }
            break;
        default:
            usage();
        }
    }
    sniffer_send_command(&flow);
    return 0;
}
