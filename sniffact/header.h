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

/**  BrokenPacketException
  *  This exception is thrown when we encountered a broken packet when making analysis,
  *  say, a packet thought to be an UDP header and actually get less than 8 bytes in remain size.
  *  Such packets being found usually indicates a severe network problem or potential attack
 **/
class BrokenPacketException :public Exception {
public:
    BrokenPacketException(const QString &pReason):Exception(pReason){}
    BrokenPacketException(const char* pReason):Exception(pReason){}
};

/** Notice for Header and its sub-classes.
    The initial value is initiated from a Byte* parameter in the function initFields.
**/
class Header {
public:
    /// Data Field
    Byte  *offset;
    size_t remainSize;
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
    virtual void initFields(const Byte * packet , size_t) {
        memcpy(&offset,&packet,4);
        next =NULL;
    }
    virtual void analyzeProtocol() {

    }

    Header(const Byte * packet =NULL , size_t size =0) {
        initFields(packet,size);
    }
};

//Ethernet Header
//Analysis on the packet always start from this header.
class EtherHeader :public Header{
    Byte dstMACAddr[6];
    Byte srcMACAddr[6];
    Byte protocol[2];

    EtherHeader(const Byte * packet , size_t size):Header(packet,size) {
        initFields(packet,size);
        analyzeProtocol();
    }

public:
    //Interfaces
    void initFields( const Byte * , size_t size);
    void analyzeProtocol();

    QString getDstMACAddrAsString();
    QString getSrcMACAddrAsString();
    /// Static Parts
    static Header *instance;
    static Header *getInstance(const Byte * packet , size_t size){
        if(instance) {
            instance->initFields(packet,size);
            instance->analyzeProtocol();
            return instance;
        }else
            return new EtherHeader(packet,size);
    }
    static void removeInstance() {
        if(instance) {
            EtherHeader *ptr =(EtherHeader*)instance;
            delete ptr;
        }
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

    PPPoEHeader(const Byte * packet , size_t size) :Header(packet,size){
        initFields(packet,size);
        analyzeProtocol();
    }

public:
    //Interfaces
    void initFields( const Byte * , size_t size);
    void analyzeProtocol();

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet , size_t size){
        if(instance) {
            instance->initFields(packet,size);
            instance->analyzeProtocol();
            return instance;
        }else
            return new PPPoEHeader(packet,size);
    }
    static void removeInstance() {
        if(instance) {
            PPPoEHeader *ptr =(PPPoEHeader*)instance;
            delete ptr;
        }
        instance =NULL;
    }
};

//super class for IPv4 and IPv6 headers
class IPHeader: public Header {
public:
    //Constructor
    //Constructor of a super class has to be public
    IPHeader(const Byte* packet, size_t size):Header(packet, size) {}

    //Interfaces
    virtual QString getDstAddrAsString(){
        assert(0);
        return QString::fromAscii(NULL);
    }
    virtual QString getSrcAddrAsString(){
        assert(0);
        return QString::fromAscii(NULL);
    }

    //Interface of Header
    void initFields(const Byte *,size_t) {
        //Should never go here
        assert(0);
    }
    void analyzeProtocol() {
        //Should never go here
        assert(0);
    }
};

//IPv4 Header
class IPv4Header :public IPHeader{
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
    IPv4Header(const Byte * packet, size_t size):IPHeader(packet, size) {
        initFields(packet, size);
        analyzeProtocol();
    }
public:
    //Interfaces of Header
    void initFields( const Byte *,size_t);
    void analyzeProtocol();

    //Interfaces of IPHeader
    QString getDstAddrAsString();
    QString getSrcAddrAsString();

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet, size_t size){
        if(instance) {
            instance->initFields(packet, size);
            instance->analyzeProtocol();
            return instance;
        }else
            return new IPv4Header(packet,size);
    }
    static void removeInstance() {
        if(instance) {
            IPv4Header *ptr =(IPv4Header*)instance;
            delete ptr;
        }
        instance =NULL;
    }
};

//IPv6 Header
class IPv6Header :public IPHeader{
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
    IPv6Header(const Byte * packet, size_t size):IPHeader(packet, size) {
        initFields(packet,  size);
        analyzeProtocol();
    }
public:
    // Interface of Header
    void initFields( const Byte *, size_t);
    void analyzeProtocol();

    // Interface of IPHeader
    QString getSrcAddrAsString();
    QString getDstAddrAsString();
    //Tool Functions
    QString tool_ConvertArrayToIPv6AddrString(Byte *);

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet, size_t size){
        if(instance) {
            instance->initFields(packet, size);
            instance->analyzeProtocol();
            return instance;
        }else
            return new IPv6Header(packet, size);
    }
    static void removeInstance() {
        if(instance) {
            IPv6Header *ptr =(IPv6Header*)instance;
            delete ptr;
        }
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

    TCPHeader(const Byte * packet, size_t size):Header(packet, size) {
        initFields(packet, size);
        analyzeProtocol();
    }

public:
    //Interfaces of Header
    void initFields( const Byte *,size_t);
    void analyzeProtocol();

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet, size_t size){
        if(instance) {
            instance->initFields(packet, size);
            instance->analyzeProtocol();
            return instance;
        }else
            return new TCPHeader(packet,size);
    }
    static void removeInstance() {
        if(instance) {
            TCPHeader *ptr =(TCPHeader*)instance;
            delete ptr;
        }
        instance =NULL;
    }
};

//UDP Header
class UDPHeader  :public Header{
    Byte srcPort[2];
    Byte dstPort[2];
    Byte length[2];
    Byte checksum[2];

    UDPHeader(const Byte * packet, size_t size):Header(packet,size) {
        initFields(packet,size);
        analyzeProtocol();
    }

public:
    void initFields( const Byte *,size_t);
    void analyzeProtocol();

    /// Static Fields
    static Header *instance;
    static Header *getInstance(const Byte * packet, size_t size){
        if(instance) {
            instance->initFields(packet, size);
            instance->analyzeProtocol();
            return instance;
        }else
            return new UDPHeader(packet, size);
    }
    static void removeInstance() {
        if(instance) {
            UDPHeader *ptr =(UDPHeader*)instance;
            delete ptr;
        }
        instance =NULL;
    }
};

#endif // HEADER_H
