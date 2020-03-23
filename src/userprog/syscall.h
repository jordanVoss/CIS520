#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H
#include "lib/user/syscall.h"

/* Helper method declarations */
void check_address(void*);
void getArguments(void*, int*, int);

/* System call declarations */
void systemCall_halt(void);
void exit(int);
pid_t systemCall_exec(const char *);
int systemCall_wait(pid_t);
bool systemCall_create(const char *, unsigned int);
bool systemCall_remove(const char *);
int systemCall_open(const char *);
int systemCall_filesize(int);
int systemCall_read(int, void *, unsigned int);
int systemCall_write(int, const void*, unsigned int);
void systemCall_seek(int, unsigned int);
unsigned int systemCall_tell(int);
void systemCall_close(int);



#endif /* userprog/syscall.h */
