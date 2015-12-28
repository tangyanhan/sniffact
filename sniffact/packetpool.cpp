#include "packetpool.h"

#define  MEMORY_POOL_TEST OFF

PacketPool::PacketPool()
{
}

PacketPool::~PacketPool()
{
    PacketPool::releasePool();
}


//const size_t POOL_UNIT_SIZE =100; //Small size for test

vector<unsigned char*> PacketPool::units;

size_t         PacketPool::sizeLeftInUnit =0;

unsigned char* PacketPool::currentPosition =NULL;

void  PacketPool::releasePool() {
        vector<unsigned char*> ::iterator iter =units.begin();
        while(iter !=units.end() ) {
                free(*iter);//If you use delete here it will be nested call!
                iter ++;  //Forgetting to add ++ causes release error
        }
        units.clear();
        sizeLeftInUnit  =0;
        currentPosition =NULL;
#if TEST
        printf("Release Pool Complete\n");
#endif
}

#if MEMORY_POOL_TEST

class Packet :public PacketPool{
        char a[1001];
        public:
        Packet() {}
};

int main() {
        Packet *a[10];
        try{
                for(int i=0;i<10;i++) {
                        a[i]=new Packet();
                        printf("\nAllocated Address :%x\n",(unsigned int)a[i]);
                }
        PacketPool::releasePool();
        }catch(Exception &e) {
                cout<<e.what()<<endl;
        }
        return 0;
}

#endif
