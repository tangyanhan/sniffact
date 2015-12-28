/*Send packets read from given file.
 *Usage:
 * ./pcapSender -i(input) file.pcap -t(interval) 1 -d(device) lo
 * It must run with root permission under Linux/Unix systems.
 */
#include <sys/types.h>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <time.h>
#include <cstring>
#include <vector>
#include <cassert>
#include <unistd.h>
#include <getopt.h>

typedef struct pcap_pkthdr PacketHeader;

typedef unsigned char Byte;

#define TR {printf("\n----------File:%s  Line:%d----------\n",__FILE__,__LINE__);fflush(stdout);}
#define OT(s) {puts(s);fflush(stdout);}

pcap_t *offlineDevice =NULL;
pcap_t *onlineDevice  =NULL;
pcap_dumper_t *dumper =NULL;

void initOfflineSniff(const char *fileName) {
	char errBuf[PCAP_ERRBUF_SIZE];
	offlineDevice =pcap_open_offline(fileName, errBuf);
	if(!offlineDevice) {
		printf("Error initiating sniffer : %s",errBuf);
		exit(1);
	}
}

void initOnlineSniff(const char *deviceName ) {
	char errBuf[PCAP_ERRBUF_SIZE];
	onlineDevice =pcap_open_live(deviceName,65536,0,2000,errBuf);
	if(!onlineDevice) {
		TR
		printf("Error initiating sending device :%s",errBuf);
		exit(1);
	}
}

void initOutput(const char *fileName) {
	dumper =pcap_dump_open(offlineDevice,fileName);
	if(!dumper)  {
		printf("Error initiating dumper");
		exit(1);
	}
}

void printPacket(PacketHeader *header,const Byte *packet)
{
    int lineCount=0;
    puts("\n-------------------Packet Read From File-------------------");
    static long start=time(0);
    printf("\nTime: %lds %ld us\n",header->ts.tv_sec-start,header->ts.tv_usec);
    printf("Content:\n");
    for(unsigned int i=0;i<header->caplen;++i,++lineCount){
        if(lineCount==0)
            printf("\t");
        printf("%02x",packet[i]);
        switch(lineCount){
        case 7:printf("   ");break;
        case 15:printf("\n");
            lineCount=-1;
            break;
        default:
            printf(" ");
            break;
        }
    }
    puts("\n---------------------------------------------------------\n");
}

int main(int args, char**argv) {
	char *inputFileName =NULL;
	char *sendDevice =NULL;
	int  interval =500;  //milliseconds

	const char *shortOptions ="i:t:d:";
	option longOptions[]= {
		{"input",0,0,'i'},
		{"interval",0,0,'t'},
		{"device",0,0,'d'},
		{0,0,0,0}  
	};
	
	int ret =0;
	
	while( (ret =getopt_long(args, argv, shortOptions,longOptions,NULL)) != -1) {
		switch(ret) {
		case 'i': inputFileName =optarg;break;
		case 'd': sendDevice =optarg;break;
		case 't': sscanf(optarg,"%d",&interval);break;
		default :
			printf("Unknown argument");
			exit(1);
			break;
		}
	}
	
	if(!(inputFileName && sendDevice ) ) {
		printf("Argument error : input file or send device not specified");
		exit(1);
	}
	
	initOfflineSniff(inputFileName);
	initOnlineSniff(sendDevice);
	PacketHeader *packetHeader;
    const Byte *packetContent;
    static int count =0;
    while(1){
        int ret=pcap_next_ex(offlineDevice,&packetHeader,&packetContent);
        if(ret==0)
            continue;
        else if(ret>0){
            printPacket(packetHeader,packetContent);
            ret =pcap_sendpacket(onlineDevice,packetContent, packetHeader->caplen);
            sleep(interval);
            if(ret) {
				printf("Error while sending packets. Device may not support sending packets");
				exit(1);
			}
            printf("\nLength , Offline: %d  Online :%d",packetHeader->caplen,packetHeader->len);
        }else if(ret ==-2) {
			printf("\n\tReading Complete !");
			goto End;
		}else{
            printf("Error while sniffing:%s",pcap_geterr(offlineDevice));
            break;
        }
    }
    End:
	if(dumper)
		pcap_dump_close(dumper);
	pcap_close(offlineDevice);
	pcap_close(onlineDevice);
	return 0;
}
