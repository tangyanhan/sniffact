#ifndef PUBLIC_HEADER_H
#define PUBLIC_HEADER_H
#include <sys/types.h>
#include <QTextStream>
#include <QtDebug>
#include <QVector>
#include <QMutex>
#include <string>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <pcap.h>
#include <time.h>
#include <cstring>
#include <vector>
typedef struct pcap_pkthdr PacketHeader;
typedef u_char Byte;
using std::vector;

#define TR {printf("\n----------File:%s  Line:%d----------\n",__FILE__,__LINE__);fflush(stdout);}
#define OT(s) {puts(s);fflush(stdout);}

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

#endif // PUBLIC_HEADER_H
