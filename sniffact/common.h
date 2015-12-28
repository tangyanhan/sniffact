#ifndef PUBLIC_HEADER_H
#define PUBLIC_HEADER_H

#include <QTextStream>
#include <QtDebug>
#include <QVector>
#include <QMutex>
#include <string>
#include <cstdio>
#include <cstdlib>
#include <cctype>
#include <ctime>
#include <cstring>
#include <vector>

#include <sys/types.h>
#include <pcap.h>

#define ON   1
#define OFF  0
#define TEST ON

#if TEST
#define NDEBUG
#endif

#include <cassert>
typedef struct pcap_pkthdr PacketHeader;
typedef u_char Byte;
using std::vector;

#if TEST
#define TR {printf("\n----------File:%s  Line:%d----------\n",__FILE__,__LINE__);fflush(stdout);}
#define OT(s) {puts(s);fflush(stdout);}
#else
#define TR
#define OT
#endif

/** Class Exception
  * An Exception similar to that of Java.
  */
class Exception{
    public:
        Exception(const QString &pReason):reason(pReason){}
        Exception(const char *pReason) {
            reason=QString::fromAscii(pReason);
        }

        QString what(){ return reason; }
        QString reason;
};

class MemoryException: public Exception {
public:
    MemoryException(const QString &pReason):Exception(pReason){}
    MemoryException(const char *pReason):Exception(pReason){}
};

#endif // PUBLIC_HEADER_H
