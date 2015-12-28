#ifndef PACKETBUFFER_H
#define PACKETBUFFER_H
#include "common.h"
#include "packet.h"
#include "packetpool.h"

/*This class is used to store packets received by the listen thread.
  It uses vector to store pointers of packets, in the hope that
  it will be more efficient.
  This PacketBuffer is designed to be singleton .
  */
class PacketBuffer
{
    //Constructor
    PacketBuffer();
    //Vector to store packets
    vector<Packet *>packetBuffer;

    static PacketBuffer *instance;
public:
    ~PacketBuffer();

    Packet* addPacket(PacketHeader *header,const Byte *content);
    Packet* addPacket(Packet &);
    Packet* getPacket(size_t elemNum);

    void clear();

    //Static parts
    static PacketBuffer *getInstance() {
        if(!instance)
            instance =new PacketBuffer();

        return instance;
    }

    static void removeInstance() {
        delete instance;
        instance =NULL;
    }
};


#endif // PACKETBUFFER_H
