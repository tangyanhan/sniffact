#ifndef TEMPFILE_H
#define TEMPFILE_H

#include "common.h"

#include <QFile>
#include <cstdio>
#include <cstdlib>
#include <cerrno>

/** Class TempFile
    TempFile is used to keep a handle of a temp file
    which will can later write into a normal file using
    saveFile()
    The file handle in the class will be releases on the
    destructior being called or exit of program.
*/

class TempFileException:public Exception {
public:
    TempFileException(const QString &pReason):Exception(pReason){}
    TempFileException(const char *pReason):Exception(pReason){}

    //Construct an exception from errno.
    TempFileException(int errorNo):Exception(NULL) {
        if(!errorNo) {
            reason ="Some stupid guy throw me and I don't know why";
            return;
        }
        reason =QString::fromAscii(strerror(errorNo));
    }
};

class TempFile {
    FILE *fileHandle;

    static TempFile*  instance;
public:
    TempFile();
    ~TempFile();

    FILE* getFileHandle();

    void saveFile(const QString &fileName);

    static TempFile* getInstance() {
        if(!instance)
            instance =new TempFile();

        return instance;
    }
    static void removeInstance() {
        if(instance) {
            delete instance;
            instance =NULL;
        }
    }
};

#endif // TEMPFILE_H
