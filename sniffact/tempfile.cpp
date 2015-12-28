#include "tempfile.h"

TempFile * TempFile::instance =NULL;

TempFile::TempFile() {
    errno =0;

    fileHandle =tmpfile();
    if(errno) {
        TempFileException e(errno);
        throw e;
    }
}

TempFile::~TempFile() {
    fclose(fileHandle);
    fileHandle =NULL;
}

FILE * TempFile::getFileHandle() {
    return fileHandle;
}


void   TempFile::saveFile(const QString & fileName)
{
    QFile file;
    if(file.open(fileHandle,QIODevice::ReadOnly)) {
            if(file.seek(0)) {
                QFile copy(fileName);
                if(copy.open(QIODevice::WriteOnly)) {
                    copy.write(file.readAll());
                }else {
                    TempFileException e(QObject::tr("Unable to open file %1 for writing").arg(fileName));
                    throw e;
                }
                file.close();
                copy.close();
            }else {
                TempFileException e("Unable to seek temp file to the beginning,temp file closed or removed");
                throw e;
            }
    }else{
        TempFileException e("Unable to open temp file for reading");
        throw e;
    }
}
