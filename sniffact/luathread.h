#ifndef LUATHREAD_H
#define LUATHREAD_H

#include <QThread>
#include <queue>
#include "common.h"
#include "packet.h"
#include "luasettings.h"
using std::queue;

class LuaThread : public QThread
{
    Q_OBJECT
public:
    explicit LuaThread(QObject *parent = 0);
    void init(LuaSettings &settings);
    void init(const QString& fileName,const QString& functionName);
    void reset(QString& fileName,QString& functionName);
    void execLuaFunction(Packet *);
    void stop();
protected:
    virtual void run();
signals:
    void signalLuaResult(QString result);
public slots:
    void slotPacketReceived(Packet*);
private:
    char function[100];
    volatile bool stopped;
    queue<Packet*> packetQueue;
};

#endif // LUATHREAD_H
