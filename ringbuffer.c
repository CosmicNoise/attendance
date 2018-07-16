#undef NDEBUG
#include <assert.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ringbuffer.h"
#include "bstrlib.h"
#include "debug.h"

RingBuffer *RingBuffer_create(int length)
{
    RingBuffer *buffer = calloc(1, sizeof(RingBuffer));
    buffer->length = length + 1;
    buffer->start = 0;
    buffer->end = 0;
    buffer->buffer = calloc(buffer->length, 1);
    return buffer;
}

void RingBuffer_destroy(RingBuffer * buffer)
{
    if (buffer) {
        free(buffer->buffer);
        free(buffer);
    }
}

int RingBuffer_write(RingBuffer * buffer, char *data, int length)
{
    if (RingBuffer_available_data(buffer) == 0) {
        buffer->start = buffer->end = 0;
    }

    if(length > RingBuffer_available_space(buffer)){
		debug(LOG_INFO, "Not enough space: %d request, %d available\n",
            RingBuffer_available_data(buffer), length);
		return -1;
	}

    void *result = memcpy(RingBuffer_ends_at(buffer), data, length);
    if(result == NULL){
		debug(LOG_INFO, "Failed to write data into buffer.\n");
		return -1;
	}

    RingBuffer_commit_write(buffer, length);

//	debug(LOG_INFO, "data is:%d space is:%d\n", RingBuffer_available_data(buffer), RingBuffer_available_space(buffer));
    return length;
}

int RingBuffer_read(RingBuffer * buffer, char *target, int amount)
{
	if(amount > RingBuffer_available_data(buffer)){
		debug(LOG_INFO, "Not enough in the buffer: has %d, needs %d\n",
            RingBuffer_available_data(buffer), amount);
		return -1;
	}

    void *result = memcpy(target, RingBuffer_starts_at(buffer), amount);
    if(result == NULL){
		debug(LOG_INFO, "Failed to write buffer into data.\n");
		return -1;
	}

    RingBuffer_commit_read(buffer, amount);

    if (buffer->end == buffer->start) {
        buffer->start = buffer->end = 0;
    }

    return amount;
}

bstring RingBuffer_gets(RingBuffer * buffer, int amount)
{
    if(amount < 0) {
		debug(LOG_INFO, "Need more than 0 for gets, you gave: %d \n",
            amount);
		return NULL;
	}
    if(amount > RingBuffer_available_data(buffer)){
           debug(LOG_INFO, "Not enough in the buffer.\n");
		return NULL;
	}

    bstring result = blk2bstr(RingBuffer_starts_at(buffer), amount);
    if(result == NULL){
		debug(LOG_INFO, "Failed to create gets result.\n");
		return NULL;
	}
    if(blength(result) != amount){
		debug(LOG_INFO, "Wrong result length.\n");
		return NULL;
	}

    RingBuffer_commit_read(buffer, amount);
    assert(RingBuffer_available_data(buffer) >= 0
            && "Error in read commit.");

    return result;
}
