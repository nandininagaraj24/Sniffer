#define _BSD_SOURCE
#define __FAVOR_BSD

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/ioctl.h>
#include <unistd.h>
#include <getopt.h>
#include <fcntl.h>
#include <netinet/ip.h>   /* Internet Protocol  */
#include <netinet/tcp.h>   /* Internet Protocol  */
#include <arpa/inet.h>
#include "sniffer_ioctl.h"

static char * program_name;
static char * dev_file = "sniffer.dev";
char *buff;
char *input_file, *output_file = NULL;
FILE *f = NULL;

void usage() 
{
    fprintf(stderr, "Usage: %s [-i input_file] [-o output_file]\n", program_name);
    exit(EXIT_FAILURE);
}

int print_packet(char * pkt, int len)
{
    /* print format is :
     * src_ip:src_port -> dst_ip:dst_port
     * pkt[0] pkt[1] ...    pkt[64] \n
     * ...
     * where pkt[i] is a hex byte */
    
    int i;
    struct ip *iph = NULL;          
    struct tcphdr *tcph = NULL;
    
    iph = (struct ip *)(pkt);
    tcph = (struct tcphdr*)(pkt+20);
    
    if(!output_file){	
    	printf("%s:%d -> %s:%d\n",inet_ntoa(iph->ip_src),ntohs(tcph->th_sport),inet_ntoa(iph->ip_dst),ntohs(tcph->th_dport));
    	for(i =0 ; i<len;i++){
    		printf("%.2x",(unsigned char)pkt[i]);
    	}
    	printf("\n");
    }
    if(output_file){
    	fprintf(f,"%s:%d -> %s:%d\n",inet_ntoa(iph->ip_src),ntohs(tcph->th_sport),inet_ntoa(iph->ip_dst),ntohs(tcph->th_dport));
    	for(i =0 ; i<len;i++){
    		fprintf(f,"%.2x",(unsigned char)pkt[i]);
    	}
    	fprintf(f,"\n");
	fflush(f);
    }
    return 0;
}

int main(int argc, char **argv)
{
    int c;
    program_name = argv[0];

    input_file= dev_file;

    while((c = getopt(argc, argv, "i:o:")) != -1) {
        switch (c) {
        case 'i':
	    input_file = optarg;
            break;
        case 'o':
	    output_file = optarg;
	    if(output_file){
		f = fopen(output_file, "w");
		if (f == NULL)
		{
		    printf("Error opening output file!\n");
		    exit(1);
		}
	    } 
            break;
        default:
            usage();
        }
    }
    
    int ret_val,file_desc;	
    file_desc = open(input_file, O_RDONLY);
    if (file_desc < 0) {
	printf("Can't open device file: %s\n", dev_file);
	exit(-1);
    }
    
    while(1){
      buff= (char*)malloc(2048);
      ret_val = read(file_desc,buff,2048);
      if(ret_val < 0){
        free(buff);
    	printf("Error reading!!");
	break;
      } else if(ret_val == 0 ){
      }
      else {
	print_packet(buff,ret_val);
	free(buff);
      }
    }
    close(file_desc);
    if(output_file){
    	fclose(f);
    }
    return 0;
}
