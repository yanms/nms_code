#!/bin/bash

# A cleanup script to remove the SHM and SEM created by the application if needed
#
# Copyright (c) 2014 Remy Bien, Sebastiaan Groot, Wouter Miltenburg and Koen Veelenturf
#
# This program is free software; you can redistribute it and/or modify it
# under the terms of the GNU General Public License as published by the Free
# Software Foundation; either version 2 of the License, or (at your option) 
# any later version.


SHMKEY=0x000017de
SEMKEY=NMSSemKey

#Remove the shared memory segment with key 6110 (0x17de)
ipcrm -M $SHMKEY

#Remove the named semaphore NMSSemKey
rm -f /dev/shm/sem.$SEMKEY