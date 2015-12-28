#ifndef PACKETPOOL_H
#define PACKETPOOL_H

#include "common.h"

/** This memory pool is designed to be 'multi-allocate, release once'.
 *  As this is also the right feature of memory usage in a sniffer.
 */

const size_t POOL_UNIT_SIZE =1048576;

class PacketPool {
public:
    PacketPool();
    virtual ~PacketPool();

    /// Body of function has to be put here, or else it will not be found by the linker
    inline void * operator new (size_t size) {
            return allocateMemory(size);
    }

    static inline void * allocateMemoryForArray(size_t elemNum, size_t elemSize) {
            //TODO: Check if multiple result of two unsigned value is wrong.

            return allocateMemory(elemNum * elemSize);
    }


    //Exceptions are thrown in such cases:
    //1.Value of parameter 'size' is bigger than POOL_UNIT_SIZE
    //2.Not enough memory for new pool unit.
    static inline void * allocateMemory(size_t size) {
        if(size > POOL_UNIT_SIZE) {
                Exception e("Size too big for a pool unit");
                throw e;
        }
        if(sizeLeftInUnit <size) { //If not enough, just expand it!
#if TEST
                printf("Expanding pool...\n");
#endif
                unsigned char *unit =(unsigned char*)malloc(POOL_UNIT_SIZE);
                if(!unit) {
                        MemoryException e("Not enough memory for new packets");
                        throw e;
                        return NULL;
                }
                units.push_back(unit);
                currentPosition =unit;
                sizeLeftInUnit =POOL_UNIT_SIZE;
#if 0
                printf("Expanding pool !Pool Address :%x",(unsigned int)currentPosition);
#endif
        }
        //Allocation
        sizeLeftInUnit -=size;
        unsigned char* oldPosition =currentPosition;
        currentPosition +=size;
        return oldPosition;
    }

    inline void operator delete(void *) {
            //It's just too dangerous!
    }

    static void releasePool();

private:

    static size_t         sizeLeftInUnit;
    static unsigned char *currentPosition;
    static vector<unsigned char*> units;
};

#endif // PACKETPOOL_H
