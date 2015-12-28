#include "packet.h"
#include <sys/types.h>
#include <stdio.h>
#include "header.h"

Packet::Packet()
{

}

/**
  Who will tell you I set off a chain reaction 'cause the const below?
  */
Packet::Packet(PacketHeader *header,const Byte *content)
{
    if(!(header || content)) {
        Exception e("Invalid packet received.Abort construction");
        throw e;
        return;
    }

    memcpy(&(this->header),header,sizeof(PacketHeader));
    size_t len =header->caplen;
    data =(Byte*)PacketPool::allocateMemoryForArray(len,sizeof(Byte));
    memcpy(data,content,len);

    time =header->ts.tv_sec+header->ts.tv_usec/1000000.0;
    analyzePacket(content);
}

Packet::Packet(const Packet &packet)
{
    srcAddr =packet.srcAddr;
    dstAddr =packet.dstAddr;
    protoName =packet.protoName;

    memcpy(data,packet.data,packet.header.caplen);
    time =packet.time;
}

void Packet::analyzePacket(const Byte *packet)
{
    try{
        EtherHeader *ethHeader =NULL;
        IPHeader *ipHeader =NULL;
        Header *header =EtherHeader::getInstance(packet,this->getDataLength());
        protoName =header->getNextProtocolName();

        ethHeader =dynamic_cast<EtherHeader*>(header);
        if(ethHeader) {
            dstAddr =ethHeader->getDstMACAddrAsString();
            srcAddr =ethHeader->getSrcMACAddrAsString();
        }else {
            Exception e("Cast failed while trying type EtherHeader*");
            throw e;
        }

        header =header->getNextHeader();
        while(header) {
            if((ipHeader =dynamic_cast<IPHeader*>(header)) !=NULL ){
                dstAddr =ipHeader->getDstAddrAsString();
                srcAddr =ipHeader->getSrcAddrAsString();
            }
            protoName =header->getNextProtocolName();
            header =header->getNextHeader();
        }

    }catch(BrokenPacketException &e) {
        protoName ="<font color=red>Broken Packet</font>";
    }
}

qreal Packet::getTime()
{
    return time;
}

QString Packet::getDstAddr()
{
    return dstAddr;
}

QString Packet::getSrcAddr()
{
    return srcAddr;
}

QString Packet::getProtocolName()
{
    return protoName;
}

Byte Packet::getDataElement(size_t offset)
{
    if(offset>getDataLength()) {
        Exception e("Offset out of range");
        throw e;
    }
    return data[offset];
}

Byte * Packet::getData()
{
    return data;
}

size_t Packet::getDataLength()
{
    return header.caplen;
}


string Packet::toAsciiString()
{
    string asciiString;
    size_t len =getDataLength();

    for(size_t i=0;i<len;++i)
        if(isprint(data[i])){
            char c=(char)data[i];
            asciiString +=c;
        }else
            asciiString +=".";
    return asciiString;
}

string Packet::toHexString()
{
    string hexString;
    char str[5]={0};
    size_t len =getDataLength();
    for(size_t i=0,count =0;i<len;++i,++count) {
        sprintf(str,"%02x ",data[i]);
        hexString.append(str);
        if(count && count %8 ==0) {
            if(count%16 ==0)
                hexString.append("\n");
            else
                hexString.append("   ");
        }
    }
    return hexString;
}

//A function for debug. Output data of the packet on the console
void Packet::printPacket(PacketHeader *header,const Byte *packet)
{
    int lineCount=0;
    puts("\n-------------------Packet Read From File-------------------");
    //static long start=time(0);
    printf("\nTime: %lds %ld us\n",header->ts.tv_sec-0,header->ts.tv_usec);
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
