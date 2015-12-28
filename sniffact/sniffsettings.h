#ifndef SNIFFSETTINGS_H
#define SNIFFSETTINGS_H
#include "settings.h"
/** Class to save settings for SniffThread.
  */
class SniffSettings:public Settings {
    public:
        virtual void check() {
            if(adapterName.isEmpty()) {
                InvalidSettingsException e("No valid adapter selected");
                throw e;
            }
        }

        QString filterString;
        QString adapterName;
        bool promiscous;
};

#endif // SNIFFSETTINGS_H
