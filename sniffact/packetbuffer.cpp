#include "packetbuffer.h"

PacketBuffer * PacketBuffer::instance =NULL;

PacketBuffer::PacketBuffer()
{
#if 0
    printf("Constructor called : PacketBuffer");
#endif
}

PacketBuffer::~PacketBuffer()
{
#if 0
    printf("Destructor called : PacketBuffer");
#endif
    clear();
}

Packet * PacketBuffer::addPacket(PacketHeader *header,
                                   const Byte *content)
{
    Packet *packet=new Packet(header,content);

    packetBuffer.push_back(packet);
    return packet;
}

Packet * PacketBuffer::addPacket(Packet &pPacket)
{
    assert(0);
    Packet *packet=new Packet(pPacket);
    packetBuffer.push_back(packet);
    return packet;
}

Packet * PacketBuffer::getPacket(size_t elemNum)
{
    if(elemNum >= packetBuffer.size()) {
        Exception e("Requested Packet index out of range :"+
                       QObject::tr("Requested %1, Actual Size %2")
                       .arg(elemNum).arg(packetBuffer.size()));
        throw e;
    }
    return packetBuffer.at(elemNum);
}

void PacketBuffer::clear()
{
    packetBuffer.clear();
    PacketPool::releasePool();
}
