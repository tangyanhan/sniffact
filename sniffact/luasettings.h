#ifndef LUASETTINGS_H
#define LUASETTINGS_H

#include "settings.h"
/**
  *Class to store configuration for LuaThread.
  */
class LuaSettings:public Settings {
    public:
        LuaSettings(QString pFileName, QString pFunctionName):
            fileName(pFileName),functionName(pFunctionName) {}
        LuaSettings() {}

        void check() {
            if(fileName.isEmpty() || functionName.isEmpty()) {
                InvalidSettingsException e("Script name or function name is not set.");
                throw e;
            }
        }

        QString fileName;
        QString functionName;
};

#endif // LUASETTINGS_H
