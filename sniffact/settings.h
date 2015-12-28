#ifndef SETTINGS_H
#define SETTINGS_H

#include "common.h"

class InvalidSettingsException:public Exception{
    public:
        InvalidSettingsException(const QString pReason):Exception(pReason){}
        InvalidSettingsException(const char *pReason):Exception(pReason){}
};

/** Settings class to store configuration to initialize the threads.
  * Such class is shared between the config dialog and the thread.
  */
class Settings
{
public:
    Settings(){}
    virtual void check(){
        Exception e("Invalid invocation from base class Settings");
        throw e;
    }
};

#endif // SETTINGS_H
