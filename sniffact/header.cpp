#include "header.h"
#include <cstring>

/**
  A Field structure is as a record of an Byte array and its length.
  In this file it's used to describe a field in the Header structure.
  */
struct Field {
    Byte *field; //The byte array
    int  length; //Available length of the array which field holds
};

typedef vector<Field> FieldVector;

/// Tool functions to copy packet to mutiple fields
inline FieldVector fillVector(Field *fields, int size);
inline Byte* multiFieldCopy(const Byte *begin,FieldVector &fields);

// Initialization of the instance pointer in each Header class.
Header *EtherHeader::instance =NULL;
Header *PPPoEHeader::instance =NULL;
Header *IPv4Header::instance  =NULL;
Header *IPv6Header::instance  =NULL;
Header *TCPHeader::instance   =NULL;
Header *UDPHeader::instance   =NULL;


void EtherHeader::initFields(const Byte * packet , size_t size)
{
    if(size<14) {
        BrokenPacketException e("Broken Packet");
        throw e;
    }
    remainSize =size-14;

    Field fields[]={ {dstMACAddr,6},{srcMACAddr,6},{protocol,2}};
    FieldVector fieldVector=fillVector(fields,3);
    offset =multiFieldCopy(packet,fieldVector);
}

void EtherHeader::analyzeProtocol()
{
    unsigned int protocolValue =(protocol[0]<<8) + protocol[1];
    switch(protocolValue) {
    case 0x0800:
        nextProtocolName ="IPv4";
        next=IPv4Header::getInstance(offset,remainSize);
        break;
    case 0x0806:
        nextProtocolName ="ARP";
        break;
    case 0x0004:
        nextProtocolName ="802.2LLC";
        break;
    case 0x86dd:
        nextProtocolName ="IPv6";
        next=IPv6Header::getInstance(offset,remainSize);
        break;
    case 0x8863:
        nextProtocolName ="PPPoED";
        next =NULL;
        break;
    case 0x8864:
        nextProtocolName ="PPPoE";
        next=PPPoEHeader::getInstance(offset,remainSize);
        break;
    case 0x0069: //Possible spanning tree protocol
        if(dstMACAddr[0]==0x01 && dstMACAddr[1] == 0x80 &&
                dstMACAddr[2]==0xc2 && dstMACAddr[3] ==0 &&
                dstMACAddr[4] ==0 && dstMACAddr[5]==0)
            nextProtocolName ="STP";
        else
            nextProtocolName ="Unknown";
        next =NULL;
        break;
    default:
        nextProtocolName ="Unknown";
        next=NULL;
        break;
    }
}

QString EtherHeader::getDstMACAddrAsString()
{
    char addrString[18];
    sprintf(addrString,"%02x:%02x:%02x:%02x:%02x:%02x",
            dstMACAddr[0],dstMACAddr[1],dstMACAddr[2],
            dstMACAddr[3],dstMACAddr[4],dstMACAddr[5]);
    addrString[17]='\0';
    QString result=addrString;
    return result;
}

QString EtherHeader::getSrcMACAddrAsString()
{
    char addrString[18];
    sprintf(addrString,"%02x:%02x:%02x:%02x:%02x:%02x",
            srcMACAddr[0],srcMACAddr[1],srcMACAddr[2],
            srcMACAddr[3],srcMACAddr[4],srcMACAddr[5]);
    addrString[17]='\0';
    return QString::fromAscii(addrString,17);
}

void PPPoEHeader::initFields(const Byte * packet , size_t size)
{
    if(size<8) {
        BrokenPacketException e("Broken Packet");
        throw e;
    }
    remainSize =size-8;

    Field fields[]= { {&versionType,1},{&code,1},
                      {sessionID,2}, {payloadLength,2},
                      {nextProtocol,2}};
    FieldVector fieldVector =fillVector(fields,5);
    offset =multiFieldCopy(packet,fieldVector);
}

void PPPoEHeader::analyzeProtocol()
{
    unsigned int protocolValue = (nextProtocol[0]<<8) + nextProtocol[1];
    switch( protocolValue ) {
    case 0x0021:
        nextProtocolName ="IPv4";
        next =IPv4Header::getInstance(offset,remainSize);
        break;
    case 0x0057:
        nextProtocolName ="IPv6";
        next =IPv6Header::getInstance(offset,remainSize);
        break;
    case 0xc021:
        nextProtocolName ="PPP LCP";
        next=NULL;
        break;
    default:
        nextProtocolName ="PPPoE Session";
        next=NULL;
        break;
    }
}

void IPv4Header::initFields(const Byte * packet , size_t size)
{
    if(size<20) {
        BrokenPacketException e("Broken Packet");
        throw e;
    }
    remainSize =size-20;

    Field fields[]= { {&versionHeaderLength,1}, {&differentiatedServiceField,1},
                      {totalLength,2}, {identification,2}, {flagsFragments,2},
                      {&timeToLive,1},{&nextProtocol,1},{headerChecksum,2},
                      {srcAddr,4},{dstAddr,4}
    };
    FieldVector fieldVector =fillVector(fields,10);
    offset =multiFieldCopy(packet,fieldVector);
}

void IPv4Header::analyzeProtocol()
{
    switch( nextProtocol ) {
    case 0x01:
        nextProtocolName ="ICMP";
        next=NULL;
        break;
    case 0x02:
        nextProtocolName ="IGMP";
        next =NULL;
        break;
    case 0x06:
        nextProtocolName ="TCP";
        next=TCPHeader::getInstance(offset,remainSize);
        break;
    case 0x11:
        nextProtocolName ="UDP";
        next=UDPHeader::getInstance(offset,remainSize);
        break;
    default:
        nextProtocolName ="IPv4";
        next=NULL;
        break;
    }
}

QString IPv4Header::getDstAddrAsString()
{
    char addrString[16]={0};
    sprintf(addrString,"%d.%d.%d.%d",
            dstAddr[0],dstAddr[1],dstAddr[2],dstAddr[3]);
    return QString::fromAscii(addrString);
}

QString IPv4Header::getSrcAddrAsString()
{
    char addrString[16]={0};
    sprintf(addrString,"%d.%d.%d.%d",
            srcAddr[0],srcAddr[1],srcAddr[2],srcAddr[3]);
    return QString::fromAscii(addrString);
}

/// IPv6Header

void IPv6Header::initFields(const Byte *packet,size_t size)
{
    if(size<40) {
        BrokenPacketException e("Broken Packet");
        throw e;
    }
    remainSize =size-40;

    Field fields[] = { {versionTrafficClassFlowLabel,4},
                       {payloadLength,2},
                       {&nextHeader,1},
                       {&hopLimit,1},
                       {srcAddr,16},
                       {dstAddr,16}
                     };
    FieldVector fieldVector =fillVector(fields,6);
    offset =multiFieldCopy(packet,fieldVector);
}

void IPv6Header::analyzeProtocol()
{
    bool isFirstHeaderChecked =false;
    ProtocolAnalysis:
    switch(nextHeader) {
    case 0x00://IPv6 Hop-by-Hop Option, should be a header, and here use this ugly solution for time.
        memcpy(&nextHeader,offset,1);
        offset += 8;
        if(isFirstHeaderChecked) { //Somebody must be plotting on my program if it happens!
            printf("Alert : Possible Hacking on this software. You're welcome if you mail me the detail\n");
            nextProtocolName ="IPv6";
            next =NULL;
            break;
        }
        isFirstHeaderChecked =true;
        goto ProtocolAnalysis;
    case 0x3a:
        nextProtocolName ="ICMPv6";
        next =NULL;
        break;
    case 0x06:
        nextProtocolName ="TCP";
        next =TCPHeader::getInstance(offset,remainSize);
        break;
    case 0x11:
        nextProtocolName ="UDP";
        next =UDPHeader::getInstance(offset,remainSize);
        break;
    default:
        nextProtocolName ="IPv6";
        next =NULL;
        break;
    }
}

QString IPv6Header::getDstAddrAsString()
{
    return tool_ConvertArrayToIPv6AddrString(dstAddr);
}

QString IPv6Header::getSrcAddrAsString()
{
    return tool_ConvertArrayToIPv6AddrString(srcAddr);
}

QString IPv6Header::tool_ConvertArrayToIPv6AddrString(Byte *addr)
{
    QString resultString;
    unsigned short addrValue[8];

    //Turn the address into 16bit format
    int neighborRepeatZero =-1;
    for(int i=0;i<8;i++) {
        int tmpOffset =i*2;
        addrValue[i]= (addr[tmpOffset]<<8) + addr[tmpOffset+1];
        if(i>0 && (neighborRepeatZero == -1) &&
            (addrValue[i] ==0) &&
            (addrValue[i-1] ==0)) {
            neighborRepeatZero =i-1;
        }
    }

    //Reassemble the value to a string.
    for(int i=0;i<8;i++) {
        if(i==neighborRepeatZero) {
            if(resultString.endsWith(":"))
                resultString += ":";
            else
                resultString += "::";
            while(i<8 && addrValue[i] ==0) i++;
            if(i == 8) break;
        }

        QString piece;
        resultString +=piece.sprintf("%x",addrValue[i]);
        if(i!=7)
            resultString +=":";
    }

    return resultString;
}

/// TCPHeader
//For TCP header, protocol mark is got from the port field.
//Problem with current solution is that the server surely use
//the wellknown ports, while the client uses a random one. In most cases
//we simply find a '80' in the dst or src port is enough for HTTP ,
//but what will happen when the client uses a famous port as well( like 110)?
//One solution say that we can get the IP of the client to identify the incoming and
//outgoing packets, yet in a promiscous environment, it's too complicated to
//get the IP of all clients.
void TCPHeader::initFields(const Byte * packet , size_t size)
{
    if(size<18) {
        BrokenPacketException e("Broken Packet");
        throw e;
    }
    remainSize =size-18;

    Field fields[]= { {srcPort,2}, {dstPort,2},
                      {sequenceNumber,4},{ackNumber,4},
                      {headerLengthReserveFlags,2},
                      {windowSize,2},{checksum,2}
    };

    FieldVector fieldVector =fillVector(fields,7);
    multiFieldCopy(packet,fieldVector);
    //Get the headerLength Field.Note that this field is counted by 4 bytes.
    int headerLength = (headerLengthReserveFlags[0] & 0xf0) >>4;
    offset =(Byte*)packet + headerLength *4;
}

void TCPHeader::analyzeProtocol()
{
    unsigned int dstPortValue = (dstPort[0]<<8) + dstPort[1];
    unsigned int srcPortValue = (srcPort[0]<<8) + srcPort[1];

    switch (dstPortValue ) {
    case 80:
        nextProtocolName ="HTTP";
        next=NULL;
        break;
    case 53:
        nextProtocolName ="DNS";
        next=NULL;
        break;
    default:
        nextProtocolName ="TCP";
        next=NULL;
        break;
    }

    if(nextProtocolName == "TCP") {
        switch (srcPortValue ) {
        case 80:
            nextProtocolName ="HTTP";
            next =NULL;
            break;
        case 53:
            nextProtocolName ="DNS";
            next =NULL;
            break;
        default:
            nextProtocolName ="TCP";
            next=NULL;
            break;
        }
    }
}

void UDPHeader::initFields(const Byte * packet , size_t size)
{
    if(size<8) {
        BrokenPacketException e("Broken Packet");
        throw e;
    }
    remainSize =size-8;

    Field fields[]={
        {srcPort,2},
        {dstPort,2},
        {length,2},
        {checksum,2}
    };
    FieldVector fieldVector =fillVector(fields,4);
    offset =multiFieldCopy(packet,fieldVector);
}

void UDPHeader::analyzeProtocol()
{
    unsigned int dstPortValue =(dstPort[0]<<8) + dstPort[1];
    unsigned int srcPortValue =(srcPort[0]<<8) + srcPort[1];


    switch(dstPortValue) {
    case 67:
        nextProtocolName ="DHCP";
        next =NULL;
        break;
    case 68:
        nextProtocolName ="DHCP";
        next =NULL;
        break;
    case 123:
        nextProtocolName ="NTP";
        next =NULL;
        break;
    case 137:
        nextProtocolName ="NBNS";
        next =NULL;
        break;
    case 546:
        nextProtocolName ="DHCPv6";
        next =NULL;
        break;
    case 547:
        nextProtocolName ="DHCPv6";
        next =NULL;
        break;
    case 1900:
        nextProtocolName ="SSDP";
        next =NULL;
        break;
    case 5353:
        nextProtocolName ="MDNS";
        next =NULL;
        break;
    case 5355:
        nextProtocolName ="LLMNR";
        next =NULL;
        break;
    case 8000:
        nextProtocolName =="QICQ";
        next =NULL;
        break;
    default:
        nextProtocolName ="UDP";
        next =NULL;
        break;
    }
    if(nextProtocolName=="UDP") {
        switch(srcPortValue) {
        case 67:
            nextProtocolName ="DHCP";
            next =NULL;
            break;
        case 68:
            nextProtocolName ="DHCP";
            next =NULL;
            break;
        case 8000:
            nextProtocolName =="QICQ";
            next =NULL;
            break;
        default:
            nextProtocolName ="UDP";
            next =NULL;
            break;
        }
    }
}


//[Tool Functions]

inline FieldVector fillVector(Field *fields, int size) {
    FieldVector fieldVector;
    for(int i=0; i<size; i++)
        fieldVector.push_back(fields[i]);
    return fieldVector;
}

inline Byte* multiFieldCopy(const Byte *begin,FieldVector &fields) {
    int offset=0;
    for(size_t i=0; i<fields.size(); i++) {
        Field field =fields.at(i);
        memcpy(field.field, (Byte*)(begin+offset),field.length);
        offset +=field.length;
    }
    return (Byte*)(begin + offset);
}// [Tool Functions]
