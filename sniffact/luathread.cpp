#include "luathread.h"
#include "packet.h"
#include "lua_interface.h"
#include <stdio.h>

LuaThread::LuaThread(QObject *parent) :
    QThread(parent)
{
}

void LuaThread::init(LuaSettings &settings)
{
    settings.check();
    init(settings.fileName,settings.functionName);
}

void LuaThread::init(const QString& fileName,const QString& functionName)
{
    L=lua_open();
    luaopen_sniffact(L);
    luaL_openlibs(L);
    luaL_dofile(L,fileName.toAscii());
    strcpy(function,functionName.toAscii());
}

void LuaThread::reset(QString& fileName, QString& functionName)
{
    if(L)
        lua_close(L);
    init(fileName,functionName);
}

void LuaThread::execLuaFunction(Packet *packet)
{
    lua_getglobal(L,function);
    lua_pushlightuserdata(L,packet);
    lua_call(L,1,1);
    size_t len =0;
    char *result=(char*)lua_tolstring(L,-1,&len);
    if(result) {
        emit signalLuaResult(QString(result));
    }
    lua_pop(L,1);
}

void LuaThread::run()
{
    stopped =false;
    while(!stopped) {
        if(!packetQueue.empty()) {
            execLuaFunction(packetQueue.front());
            packetQueue.pop();
        }
    }
}

void LuaThread::stop()
{
    stopped =true;
}

void LuaThread::slotPacketReceived(Packet *pPacket)
{
    packetQueue.push(pPacket);
}
