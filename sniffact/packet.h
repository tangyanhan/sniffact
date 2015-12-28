#ifndef PACKET_H
#define PACKET_H

#include "common.h"
#include "packetpool.h"
#include <string>
using std::string;

const int MAX_ADDR_LEN=25;

class Packet :public PacketPool{
    double time;
    PacketHeader header;
    Byte *data;
    QString srcAddr;
    QString dstAddr;
    QString protoName;

    void analyzePacket(const Byte *packet);

public:
    Packet(PacketHeader *header,const Byte *content);
    //Constructor
    Packet();
    Packet(const Packet&);

    qreal getTime();
    QString getDstAddr();
    QString getSrcAddr();
    QString getProtocolName();

    Byte getDataElement(size_t offset);
    Byte *getData();
    size_t getDataLength();
    string toAsciiString();
    string toHexString();

    static void printPacket(PacketHeader *header,const Byte *packet);
};

#endif // PACKET_H
