#ifndef LUA_INTERFACE_H
#define LUA_INTERFACE_H

#include <lua5.1/lua.hpp>

extern lua_State *L;
int luaopen_sniffact(lua_State *L);

int getByte(lua_State *L);
int getLength(lua_State *L);
int getSrcAddr(lua_State *L);
int getDstAddr(lua_State *L);
int getProtoName(lua_State *L);
int getAsciiString(lua_State *L);

int getIP(lua_State *L);
#endif // LUA_INTERFACE_H
