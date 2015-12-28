sed -i -e "s/LuaSetDialog/LuaSetDialog/g" *.*
sed -i -e "s/actionsettingdialog\.h/luasetdialog.h/g" *.*
sed -i -e "s/LUASETDIALOG/LUASETDIALOG/g" *.*

sed -i -e "s/SniffSetDialog/SniffSetDialog/g" *.*
sed -i -e "s/setadapterdialog\.h/sniffsetdialog.h/g" *.*
sed -i -e "s/SNIFFSETDIALOG/SNIFFSETDIALOG/g" *.*


sed -i -e "s/LuaThread/LuaThread/g" *.*
sed -i -e "s/actthread\.h/luathread.h/g" *.*
sed -i -e "s/LUATHREAD/LUATHREAD/g" *.*


