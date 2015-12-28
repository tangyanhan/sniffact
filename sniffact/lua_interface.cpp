#include "common.h"
#include "packet.h"
#include "lua_interface.h"

lua_State* L =NULL;

const struct luaL_Reg sniffactLib[] = {
    {"byte",getByte},
    {"len",getLength},
    {"protoName",getProtoName},
    {"srcAddr",getSrcAddr},
    {"dstAddr",getDstAddr},
    {"asciiString",getAsciiString},
    {NULL,NULL}
};

//Register UseData
int luaopen_sniffact(lua_State *L) {
    luaL_register(L,"Packet",sniffactLib);
    lua_pushcfunction(L,getIP);
    lua_setglobal(L,"getIP");
    return 1;
}


int getByte(lua_State *L) {
    Packet *a= (Packet*)lua_touserdata(L,1);
    size_t index =luaL_checkint(L,2);
    luaL_argcheck(L,a!=NULL,1,"'Packet' expected");
    luaL_argcheck(L,index <a->getDataLength(),2,"index out of range");
    lua_pushnumber(L,a->getDataElement(index));
    return 1;
}

int getLength(lua_State *L) {
    Packet *p= (Packet*)lua_touserdata(L,1);
    luaL_argcheck(L,p!=NULL,1,"'Packet' expected");
    lua_pushnumber(L,p->getDataLength());
    return 1;
}

int getSrcAddr(lua_State *L) {
    Packet *p= (Packet*)lua_touserdata(L,1);
    luaL_argcheck(L,p!=NULL,1,"'Packet' expected");
    lua_pushstring(L,p->getSrcAddr().toAscii());
    return 1;
}

int getDstAddr(lua_State *L) {
    Packet *p= (Packet*)lua_touserdata(L,1);
    luaL_argcheck(L,p!=NULL,1,"'Packet' expected");
    lua_pushstring(L,p->getDstAddr().toAscii());
    return 1;
}

int getProtoName(lua_State *L) {
    Packet *p= (Packet*)lua_touserdata(L,1);
    luaL_argcheck(L,p!=NULL,1,"'Packet' expected");
    lua_pushstring(L,p->getProtocolName().toAscii());
    return 1;
}

int getAsciiString(lua_State *L) {
    Packet *p= (Packet*)lua_touserdata(L,1);
    luaL_argcheck(L,p!=NULL,1,"'Packet' expected");
    lua_pushstring(L,p->toAsciiString().c_str());
    return 1;
}

#include <netdb.h>
#include <netinet/in.h>
#include <arpa/inet.h>
int getIP(lua_State *L) {
    const char *hostName=luaL_checkstring(L,1);
    struct hostent *h;
    if((h= gethostbyname(hostName)) == NULL) {
        lua_pushstring(L,NULL);
        return 0;
    }
    lua_pushstring(L,inet_ntoa(*((struct in_addr*)h->h_addr)));
    return 1;
}
