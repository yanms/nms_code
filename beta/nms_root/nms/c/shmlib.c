/*
 * A small library used in passwordstore.py to access shared memory
 *
 * Copyright (c) 2014 Remy Bien, Sebastiaan Groot, Wouter Miltenburg and Koen Veelenturf
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 2 of the License, or (at your option) 
 * any later version.
 */

#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <semaphore.h>
#include <fcntl.h>
#include <stdlib.h>

#define SHMLEN 17
#define SHMKEY 6110

#define ESHMGET   -1
#define ESHMAT    -2

#define SEMNAME   "NMSSemKey"

#define ESEMOPEN  -1

static char *shm = (char *) -1; // Equals the error return value of shmat
static sem_t *sem_id = SEM_FAILED;

static int init_sem(void)
{
   sem_id = sem_open(SEMNAME, O_CREAT, 0600, 1);
   if (sem_id == SEM_FAILED)
   {
      return ESEMOPEN;
   }
   return 0;
}

static int init_shm(void)
{
   int shmid;
   key_t key;

   key = SHMKEY;

   if ((shmid = shmget(key, SHMLEN, IPC_CREAT | 0600)) < 0)
   {
      return ESHMGET;
   }

   if ((shm = shmat(shmid, NULL, 0)) == (char *) -1)
   {
      return ESHMAT;
   }
   return 0;
}

void store_password(char *password, int n)
{
   int i;
   if (shm == (char *) -1)
   {
      if (init_shm() < 0)
      {
         return;
      }
   }
   if (sem_id == SEM_FAILED)
   {
      init_sem();
      if (sem_id == SEM_FAILED)
      {
         return;
      }
   }
   
   sem_wait(sem_id);
   for (i = 0; i < n; i++)
   {
      shm[i] = password[i];
   }
   shm[i] = '\0';
   sem_post(sem_id);
}

char *get_password(void)
{
   if (shm == (char *) -1)
   {
      if (init_shm() < 0)
      {
         return NULL;
      }
   }
   return shm;
}
