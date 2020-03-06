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
void systemCall_halt(void);
void systemCall_exit(int status);
pid_t systemCall_exec(const char *comd_line);
int systemCall_wait(pid_t pid);
bool systemCall_create(const char *file, unsigned initial_size);
bool systemCall_remove(const char *file);
int systemCall_open(const char *file);
int systemCall_filesize(int fd);
int systemCall_read(int fd, void *buffer, unsigned size);
int systemCall_write(int fd, void *buffer, unsigned size);
void systemCall_seek(int fd, unsigned position);
unsigned systemCall_tell(int fd);
void systemCall_close(int fd);
struct process_file *search(struct list* files, int fd);



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
  /* Gets the effective address of esp */
  int *esp = (int *)f->esp;

  /* Dereference esp to get the system call */  
  int system_call = *esp;
  
  /* Switch for finding the correct method
    * for the system_call param */
  switch (system_call)
  {
    /* System Call: Halt
       Status: Done
    */
    case(SYS_HALT):;
      systemCall_halt();
      break;
    
    /* System Call: Exit
       Status: Needs implemented
    */
    case(SYS_EXIT):;
      int exitStatus = *(esp + 1);
      systemCall_exit(exitStatus);
      break;

    /* System Call: Exec
       Status: Think we are correct
    */
    case(SYS_EXEC):;
      char* arg2 = *(esp + 1); //gets the argument off of the stack
      pid_t EAX = systemCall_exec(arg2);  //accuires output from method call
      f->eax = (uint32_t)EAX;  //assigns output to volitile register
      break;

    /* System Call: Wait
       Status: Needs implemented
    */
    case(SYS_WAIT):;
      pid_t arg3 = *(esp + 1);
      f->eax = systemCall_wait(arg3);
      break;

    /* System Call: Create
       Status: Needs implemented
    */
    case(SYS_CREATE):;
      char *arg4 = *(esp + 1);
      unsigned arg5 = *(esp + 2);
      f->eax = (uint32_t)systemCall_create(arg4, arg5);
      break;

    /* System Call: Remove
       Status: Needs implemented
    */
    case(SYS_REMOVE):;
      char *arg6 = *(esp + 1);
      f->eax = (uint32_t)systemCall_remove(arg6);
      break;

    /* System Call: Open
       Status: Think we are correct
    */
    case(SYS_OPEN):;
      char *arg7 = *(esp + 1);
      //char *tempvar = *(esp + 2);
      //printf("%s\n\n",&tempvar);
      f->eax = (uint32_t)systemCall_open(arg7);
      break;
    
    /* System Call: Filesize
       Status: Needs implemented
    */
    case(SYS_FILESIZE):;
      int arg8 = *(esp + 1);
      f->eax = (uint32_t)systemCall_filesize(arg8);
      break;

    /* System Call: Read
       Status: Needs implemented
    */
    case(SYS_READ):;
      int arg9 = *(esp + 1);
      void *arg10 = *(esp + 2);
      unsigned arg11 = *(esp + 3);
      f->eax = (uint32_t)systemCall_read(arg9, arg10, arg11);
      break;

    /* System Call: Write
       Status: Actively working
    */  
    case(SYS_WRITE):;
      //int arg12 = *((int*)*(esp + 1));
      //void *arg13 = (void*) (*((int*)*(esp + 2)));
      //unsigned arg14 = *((unsigned*)*(esp + 3));
      int arg12 = *(esp + 1);
      void *arg13 = *(esp + 2);
      unsigned arg14 = *(esp + 3);
      //unsigned arg14 = 2;
      f->eax = systemCall_write(arg12, arg13, arg14);
      //printf("\n\nI am in SYS_WRITE\n\n");
      break;

    /* System Call: Create
       Status: Needs implemented
    */
    case(SYS_SEEK):;
      printf("\n\nI am in SYS_SEEK\n\n");
      break;

    /* System Call: Create
       Status: Needs implemented
    */  
    case(SYS_TELL):;
      printf("\n\nI am in SYS_TELL\n\n");
      
      break;

    /* System Call: Create
       Status: Needs implemented
    */
    case(SYS_CLOSE):;
      printf("\n\nI am in SYS_CLOSE\n\n");
      break;


    default:;
      printf("Default %d\n", *esp);
  }
}

/* The halt system call */
void systemCall_halt(void)
{
  shutdown_power_off();
}


void systemCall_exit(int exitStatus)
{
  thread_current()->exit_status = exitStatus;
  printf("%s is exiting with status: %d\n", thread_current()->name, exitStatus);
  thread_exit();
}


pid_t systemCall_exec(const char *comd_line)
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

/* The wait system call */
int systemCall_wait(pid_t pid)
{
  return process_wait(pid);
  //return temp;
}

/* The create file system call */
bool systemCall_create(const char *file, unsigned initial_size)
{
  lock_acquire(&filesys_lock);
  
  bool result = filesys_create(file, initial_size);
  lock_release(&filesys_lock);
  return result;
}


bool systemCall_remove(const char *file)
{
  lock_acquire(&filesys_lock);
  bool result;
  if (filesys_remove(*file) == NULL)
    result = false;
  else
    result = true;
  
  lock_release(&filesys_lock);
  
  return result;
}


int systemCall_open(const char *file)
{
  lock_acquire(&filesys_lock);
  
  struct file* f = filesys_open(file); //Get the actual file

  //Check if the file is NULL
  if (f == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }
  
  struct process_file *pfile = malloc(sizeof(struct process_file));
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
int systemCall_filesize(int fd)
{
  /*
  int size = lseek(fd, 0, SEEK_END);
  return size;
  */
 
 return -1;
}


int systemCall_read(int fd, void *buffer, unsigned size)
{
  int temp;
  return temp;
}

int systemCall_write(int fd, void *buffer, unsigned size)
{
  lock_acquire(&filesys_lock);

  
  if (fd == 1)
  {
    putbuf(buffer, size);
    lock_release(&filesys_lock);
    return size;
  }
  
  struct process_file *p_file = search(&thread_current()->file_descriptors, fd);

  if (p_file == NULL)
  {
    lock_release(&filesys_lock);
    return -1;
  }


  lock_release(&filesys_lock);
  return file_write(p_file->file_ptr, buffer, size);
}


void systemCall_seek(int fd, unsigned position)
{
  //more gold please
}


unsigned systemCall_tell(int fd)
{
  unsigned temp;
  return temp;
}


///
void systemCall_close(int fd)
{
  //last bit of gold
}

struct process_file *search(struct list* files, int fd)
{
    struct list_elem* elem;

    for (elem = list_begin(files); elem != list_end(files); elem = list_next(files))
    {
      struct process_file* file = list_entry(elem, struct process_file, file_elem);

      if (file->fd == fd)
      {
        return file;
      }
    }
    return NULL;
}

/* Removes all files from the list and closes them
  Reference: https://github.com/rida300/520Pintos/blob/master/cis520/pintos/src/userprog/syscall.c
*/
void
close_all_files(struct list* files)
{
  struct list_elem* e;

  while (!list_empty(files))
  {
    e = list_pop_front(files);
    struct process_file *f = list_entry(e, struct process_file, file_elem);

    file_close(f->file_ptr);
    list_remove(e);
    free(f);
  }
}