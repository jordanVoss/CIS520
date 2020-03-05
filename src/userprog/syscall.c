/*
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"

static void syscall_handler (struct intr_frame *);

void
syscall_init (void) 
{
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  printf ("system call!\n");
  thread_exit ();
}
*/
#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "threads/palloc.h"
#include "threads/synch.h"
#include "devices/shutdown.h"
#include "devices/input.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"
#include "userprog/exception.h"
#include "lib/string.h"
#include "lib/user/syscall.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include "filesys/free-map.h"
#include "filesys/inode.h"
#include "filesys/directory.h"
#include "devices/input.h"
#include "threads/pte.h"

static void syscall_handler (struct intr_frame *);
void halt(void);
void exit(int status);
pid_t exec(const char *comd_line);
int wait(pid_t pid);
bool create(const char *file, unsigned initial_size);
bool remove(const char *file);
int open(const char *file);
int filesize(int fd);
int read(int fd, void *buffer, unsigned size);
void seek(int fd, unsigned position);
unsigned tell(int fd);
void close(int fd);

struct lock filesys_lock; //Lock used for filesys applications

void
syscall_init (void) 
{
  lock_init(&filesys_lock);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

//-----------------------------------
//Struct used to keep track of file descriptors ofr open and closed
//fd is a positive int, but never 0 or 1
struct
process_file {
  struct file* file_ptr;             //Pointer to the file being used
  struct list_elem file_elem;        //List element
  int fd;                            //File Descriptor
};

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  int *esp = (int *)f->esp;
  //get word from esp
  //case statement to send shit off
  int system_call = *esp;

  switch (system_call)
  {
  case(SYS_HALT):;
    halt();
    break;
  
  case(SYS_EXIT):;
    int arg1 = *(esp + 1);
    exit(arg1);
    break;

  case(SYS_EXEC):;
    char* arg2 = *(esp + 1); //gets the argument off of the stack
    pid_t EAX = exec(arg2);  //accuires output from method call
    f->eax = (uint32_t)EAX;  //assigns output to volitile register
    break;

  case(SYS_WAIT):;
    pid_t arg3 = *(esp + 1);
    int EAX_new = wait(arg3);
    f->eax = (uint32_t)EAX_new;
    break;

  case(SYS_CREATE):;
    char *arg4 = *(esp + 1);
    unsigned arg5 = *(esp + 2);
    f->eax = (uint32_t)create(arg4, arg5);
    break;

  case(SYS_REMOVE):;
    char *arg6 = *(esp + 1);
    f->eax = (uint32_t)remove(arg6);
    break;

  case(SYS_OPEN):;
    char *arg7 = *(esp + 1);
    f->eax = (uint32_t)open(arg7);
    break;
  
  case(SYS_FILESIZE):;
    int arg8 = *(esp + 1);
    f->eax = (uint32_t)filesize(arg8);
    break;

  case(SYS_READ):;
    int arg9 = *(esp + 1);
    void *arg10 = *(esp + 2);
    unsigned arg11 = *(esp + 3);
    f->eax = (uint32_t)read(arg9, arg10, arg11);
    break;

  case(SYS_WRITE):;
    printf("\n\nI am in SYS_WRITE\n\n");
    break;

  case(SYS_SEEK):;
    printf("\n\nI am in SYS_SEEK\n\n");
    break;

  case(SYS_TELL):;
    printf("\n\nI am in SYS_TELL\n\n");
    break;

  case(SYS_CLOSE):;
    printf("\n\nI am in SYS_CLOSE\n\n");
    break;
    
  default:;
    //printf("How did you even get here???");
    printf("Default %d\n", *esp);
    //break;
  }
  //thread_exit ();
}






void halt(void)
{
  shutdown_power_off();
}


void exit(int status)
{
  //insert gold here
}


pid_t exec(const char *comd_line)
{
  lock_acquire(&filesys_lock); //Grab the lock

  //Get the first element of the comand line (filename)
  char *token = malloc(strlen(comd_line)+1);
  strlcpy(token, comd_line, strlen(comd_line)+1);

  //Set token to the first element
  char* save_ptr;
  token = strtok_r(&token, " ", &save_ptr);

  //Open the file
  struct file* f = filesys_open(token);

  //If file could not be opened, return -1
  if (f == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }

  //close the file
  file_close(f);

  //release the lock
  lock_release(&filesys_lock);

  //return the execution of the file
  return process_execute(comd_line);
}


int wait(pid_t pid)
{
  int temp;
  return temp;
}


bool create(const char *file, unsigned initial_size)
{
  bool temp;
  return temp;
}


bool remove(const char *file)
{
  bool temp;
  return temp;
}


int open(const char *file)
{
  lock_acquire(&filesys_lock);
  
  struct file* f = filesys_open(file); //Get the actual file

  //Check if the file is NULL
  if (f == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }
  
  struct process_file* pfile = malloc(sizeof(struct process_file));
  pfile->file_ptr = f;
  pfile->fd = thread_current()->fd;
  thread_current()->fd++; //Increment file descriptor
  list_push_front(&thread_current()->file_descriptors, &pfile->file_elem); //Add the process file to the thread lsit of file_descriptors

  lock_release(&filesys_lock); //Unlock the system
  return pfile->fd;

  //NEED TO INIT FILE_DESCRIPTORS LIST IN THREADS.C
}


//-------------------------THIS FUNCTION IS NOT WORKING--------------------------//
//SEEK_END is undeclared
int filesize(int fd)
{
  /*
  int size = lseek(fd, 0, SEEK_END);
  return size;
  */
 return -1;
}


int read(int fd, void *buffer, unsigned size)
{
  int temp;
  return temp;
}


void seek(int fd, unsigned position)
{
  //more gold please
}


unsigned tell(int fd)
{
  unsigned temp;
  return temp;
}


void close(int fd)
{
  //last bit of gold
}

