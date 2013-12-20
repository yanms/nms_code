#include <sys/types.h>
#include <sys/ipc.h>
#include <sys/shm.h>
#include <stdlib.h>

#define SHMLEN 17
#define SHMKEY 6110

#define ESHMGET   -1
#define ESHMAT    -2

static char *shm = (char *) -1; // Equals the error return value of shmat

static int init_shm(void)
{
   int shmid;
   key_t key;

   key = SHMKEY;

   if ((shmid = shmget(key, SHMLEN, IPC_CREAT | 0666)) < 0)
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
   for (i = 0; i < n; i++)
   {
      shm[i] = password[i];
   }
   shm[i] = '\0';
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
