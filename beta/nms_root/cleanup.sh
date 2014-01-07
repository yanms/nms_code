#!/bin/bash

SHMKEY=0x000017de
SEMKEY=NMSSemKey

#Remove the shared memory segment with key 6110 (0x17de)
ipcrm -M $SHMKEY

#Remove the named semaphore NMSSemKey
rm -f /dev/shm/sem.$SEMKEY