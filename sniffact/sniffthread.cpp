#include "sniffthread.h"
#include "packetbuffer.h"
#include "tempfile.h"
#include <sys/types.h>
#include <QMutexLocker>
#include <QString>


SniffThread::SniffThread()
{
    adapter =NULL;
    dumper =NULL;
}

void SniffThread::initSniff(const SniffSettings *settings)
{
    initSniff(settings->adapterName,settings->promiscous,settings->filterString);
}

void SniffThread::initDumper()
{
    //Clear previous dumper and file handle of TempFile
    TempFile::removeInstance(); //Try to remove previous temp file

    TempFile *tmpFile =TempFile::getInstance();

    dumper =pcap_dump_fopen(adapter, tmpFile->getFileHandle());

    if(!dumper) {
        Exception e("Unable to create a dumper");
        throw e;
        return;
    }
}

/* Initialize the listen thread using specified adapter*/
void SniffThread::initSniff(QString adapterName,int promisc,QString filterString)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    if(isRunning()){
        Exception e(tr("Please stop the last sniffer thread first！"));
        throw e;
        return;
    }

    adapter=pcap_open_live(adapterName.toAscii(),65536,promisc,2000,errBuf);

    if(!adapter){
        Exception e(tr("Adapter Init Error:%3").arg(errBuf));
        throw e;
        return;
    }
    if(!filterString.isEmpty()) {
        struct bpf_program bpfProgram;
        bpf_u_int32 netMask=0xffffff;
        char filter[500];
        strcpy(filter,filterString.toAscii());
        if(pcap_compile(adapter, &bpfProgram, filter, 1, netMask) < 0) {
            pcap_close(adapter);
            Exception e(tr("Error compiling filter:%1").arg(pcap_geterr(adapter)));
            throw e;
            return;
        }
        //set the filter
        if(pcap_setfilter(adapter, &bpfProgram)<0) {
            pcap_close(adapter);
            Exception e(tr("Error setting the filter:%1").arg(pcap_geterr(adapter)));
            throw e;
            return;
        }
    }
}

//Init SniffThread from an offline packetfile
void SniffThread::initSniff(QString fileName)
{
    char errBuf[PCAP_ERRBUF_SIZE];
    adapter =pcap_open_offline(fileName.toAscii(),errBuf);
    if(!adapter) {
        Exception e(tr("Error while initializing offline sniff :%1").arg(errBuf));
        throw e;
    }
}

/* Main part of listening thread */
void SniffThread::run()
{
try{
    PacketHeader *packetHeader =NULL;
    const Byte *packetContent  =NULL;

    stopped=false;

    initDumper();//
    PacketBuffer::removeInstance(); //Clear Buffer

    PacketBuffer *packetBuffer =PacketBuffer::getInstance();
    int ret =0;

    while(!stopped){
        ret=pcap_next_ex(adapter,&packetHeader,&packetContent);
        if(ret==0)
            continue;
        else if(ret>0){
            Packet *packet =packetBuffer->addPacket(packetHeader,packetContent);
            emit signalPacketReceived(packet);
            if(dumper) {
                pcap_dump((u_char*)dumper,packetHeader,packetContent);
            }
        }else if(ret ==-2){
            stopped =true;
            break;
        }else{
            emit error(tr("Error while sniffing:%1").arg(pcap_geterr(adapter)));
            stopped=true;
            break;
        }
    }

    // Handle exceptions
    }catch(MemoryException &e) {
        PacketBuffer::removeInstance();
        emit error(e.what());
    }catch(Exception &e) {
        emit error(e.what());
    }catch(std::exception &e) {
        //Okay, we can die now
        PacketBuffer::removeInstance();
        emit error(e.what());
    }

    pcap_close(adapter);
    adapter =NULL;
}

#include "header.h"
/* Stop the sniff thread */
void SniffThread::stop()
{
    stopped=true;
    //Remove instances. Actually those pointers are not worthy doing this.
    EtherHeader::removeInstance();
    PPPoEHeader::removeInstance();
    IPv4Header::removeInstance();
    IPv6Header::removeInstance();
    TCPHeader::removeInstance();
    UDPHeader::removeInstance();
}

