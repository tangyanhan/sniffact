#ifndef HEADER_H
#define HEADER_H

/**  File: header.h
  *  Description: Prototype of several kinds of header for protocol analysis
  *
  *  NOTICE:
  *  NAME STYLE of this file:
  *  When naming those fields in the protocol headers, I'll use its full spell
  *  as much as possible. Yet for some wellknown short words such like use
  *  'src' for 'source', 'dst' for 'destination', and 'ack' for 'acknowledgement',
  *  and 'len' for 'length' if the word is already too long. For some case, two
  *  fields of the header occupies one byte together, and such is represented with
  *  the name of the two fields combined without 'and'. It may looks weird.
  *  [History Modification]
  *  .Class HeaderInterface and Header removed for the reason above.
  *  .Class Header returned for a better design. I'm fully confirmed that
  *   it worthy the sacrifice on time, and I'll use memory pool to compensate the loss of efficiency.
  *
  *   Important Designation Issues
  *   All sub-classes of Header are designed Singleton,considering that the nextHeader pointer will cause
  *   a lot trouble if we simply use new. Plus, unique existence of each class makes release of pointer easier.
**/

#include "common.h"

/** Notice for Header and its sub-classes.
    The initial value is initiated from a Byte* parameter in the function initFields.
**/
class Header {
public:
    /// Data Field
    Byte  *offset;
    Header *next;
    QString nextProtocolName;

    /// Functions
    Header* getNextHeader() {
        return next;
    }
    QString getNextProtocolName(){
        return nextProtocolName;
    }

    /// interface to be implemented.
    virtual void initFields(const Byte * packet) {
        memcpy(&offset,&packet,4);
        next =NULL;
    }
    Header(const Byte * packet =NULL) {
        initFields(packet);
    }
};

//Ethernet Header
//Analysis on the packet always start from this header.
class EtherHeader :public Header{
    Byte dstMACAddr[6];
    Byte srcMACAddr[6];
    Byte protocol[2];

    EtherHeader(const Byte * packet):Header(packet) {
        initFields(packet);
    }

public:
    void initFields( const Byte *);
    QString getDstMACAddrAsString();
    QString getSrcMACAddrAsString();
    /// Static Parts
    static Header *instance;
    static Header *getInstance(const Byte * packet){
        if(instance) {
            instance->initFields(packet);
            return instance;
        }else
            return new EtherHeader(packet);
    }
    static void removeInstance() {
        if(instance) delete instance;
        instance =NULL;
    }
};

//PPPoE Header
//PPPoE runs on LLC layer.
class PPPoEHeader :public Header{
    Byte versionType;
    Byte code;
    Byte sessionID[2];
    Byte payloadLength[2];
    Byte nextProtocol[2];

    PPPoEHeader(const Byte * packet) :Header(packet){
        initFields(packet);
    }

public:
    void initFields(const Byte *);

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet){
        if(instance) {
            instance->initFields(packet);
            return instance;
        }else
            return new PPPoEHeader(packet);
    }
    static void removeInstance() {
        if(instance) delete instance;
        instance =NULL;
    }
};

//IPv4 Header
class IPv4Header :public Header{
    /// Data Field
    Byte versionHeaderLength;
    Byte differentiatedServiceField;
    Byte totalLength[2];
    Byte identification[2];
    Byte flagsFragments[2];
    Byte timeToLive;
    Byte nextProtocol;
    Byte headerChecksum[2];
    Byte srcAddr[4];
    Byte dstAddr[4];

    /// Constructor
    IPv4Header(const Byte * packet):Header(packet) {
        initFields(packet);
    }
public:
    void initFields( const Byte *);

    QString getDstIPAddrAsString();
    QString getSrcIPAddrAsString();

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet){
        if(instance) {
            instance->initFields(packet);
            return instance;
        }else
            return new IPv4Header(packet);
    }
    static void removeInstance() {
        if(instance) delete instance;
        instance =NULL;
    }
};

//IPv6 Header
class IPv6Header :public Header{
    Byte versionTrafficClassFlowLabel[4];// Compound of 3 fields:
                                    //  Version(4 bit),
                                    //Traffic Class (8 bit)
                                    //Flow Label (20 bit)
    Byte payloadLength[2];
    Byte nextHeader;
    Byte hopLimit;
    Byte srcAddr[16];
    Byte dstAddr[16];

    /// Constructor
    IPv6Header(const Byte * packet):Header(packet) {
        initFields(packet);
    }
    //Tool Functions
    QString tool_ConvertArrayToIPv6AddrString(Byte *);
public:
    // Interface Implimention
    void initFields( const Byte *);

    // Unique Functions
    QString getSrcAddrAsString();
    QString getDstAddrAsString();

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet){
        if(instance) {
            instance->initFields(packet);
            return instance;
        }else
            return new IPv6Header(packet);
    }
    static void removeInstance() {
        if(instance) delete instance;
        instance =NULL;
    }
};

//TCP Header
/// Notice
/** This TCP header only shows the fixed 20byte part, but the real TCP header length
  * is always 20bytes+ and its real header length is represented in the headerLength
  * field. So this will change the way to calculate offset if you want to analyze a
  * hipher protocol.
  */
class TCPHeader :public Header{
    Byte srcPort[2];
    Byte dstPort[2];
    Byte sequenceNumber[4];
    Byte ackNumber[4];
    Byte headerLengthReserveFlags[2];//Triple fields here.
    Byte windowSize[2];
    Byte checksum[2];

    TCPHeader(const Byte * packet):Header(packet) {
        initFields(packet);
    }

public:
    void initFields( const Byte *);

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet){
        if(instance) {
            instance->initFields(packet);
            return instance;
        }else
            return new TCPHeader(packet);
    }
    static void removeInstance() {
        if(instance) delete instance;
        instance =NULL;
    }
};

//UDP Header
class UDPHeader  :public Header{
    Byte srcPort[2];
    Byte dstPort[2];
    Byte length[2];
    Byte checksum[2];

    UDPHeader(const Byte * packet):Header(packet) {
        initFields(packet);
    }

public:
    void initFields( const Byte *);

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet){
        if(instance) {
            instance->initFields(packet);
            return instance;
        }else
            return new UDPHeader(packet);
    }
    static void removeInstance() {
        if(instance) delete instance;
        instance =NULL;
    }
};

#endif // HEADER_H
