#include "../header.h"
#include <QStringList>

class Ipv6ConvertTestTest
{
    vector<Byte*>data;
    QStringList stringList;
public:
    Ipv6ConvertTestTest();
    void ipv6AddressTest();
    void ipv6AddressTest_data();
};

Ipv6ConvertTestTest::Ipv6ConvertTestTest()
{
}

void Ipv6ConvertTestTest::ipv6AddressTest()
{
    Byte emptyPacket[100]={0};
    Header *header =IPv6Header::getInstance(emptyPacket,100);
    IPv6Header *ipv6Header =dynamic_cast<IPv6Header*>(header);

    for(int i=0;i<data.size();i++) {
        QString actual =ipv6Header->tool_ConvertArrayToIPv6AddrString(data.at(i));
        QString result =stringList.at(i);
        qDebug()<<i<<" th case  :"<<endl;
        if(actual != result)
            qDebug()<<"Actual:\t"<<actual<<"\nExpect:\t"<<result<<endl;
        else
            qDebug()<<"Pass"<<endl;
    }
    fflush(stdout);
}

void Ipv6ConvertTestTest::ipv6AddressTest_data()
{
    static unsigned char test[][16] ={
        {1,2, 3,4, 5,6, 7,8, 9,10, 11,12, 13,14, 15,16}, //0
        {0,0, 0,0, 5,6, 7,8, 9,10, 11,12, 13,14, 15,16}, //1
        {0,0, 0,0, 0,0, 7,8, 9,10, 11,12, 13,14, 15,16}, //2
        {1,2, 3,4, 5,6, 0,0, 0,0,  11,12, 13,14, 15,16},  //3
        {1,2, 3,4, 5,6, 7,8, 9,0,  0, 0,  0, 0,  0, 0},   //4
        {1,2, 0,0, 0,0, 7,8, 9,10,  0, 0, 0, 0,  0,0}  //5
    };

    for(int i=0;i<6;i++)
        data.push_back(test[i]);

    stringList<<"102:304:506:708:90a:b0c:d0e:f10";
    stringList<<"::506:708:90a:b0c:d0e:f10";
    stringList<<"::708:90a:b0c:d0e:f10";
    stringList<<"102:304:506::b0c:d0e:f10";
    stringList<<"102:304:506:708:900::";
    stringList<<"102::708:90a:0:0:0";
}

int main() {
    Ipv6ConvertTestTest test;
    test.ipv6AddressTest_data();
    test.ipv6AddressTest();
    return 0;
}
