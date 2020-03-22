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
struct lock filesys_lock;

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


/* Checks to see if the passed in address is valid. If it's not then the system exits. */
void
address_check(void *address) {

  if(!is_user_vaddr(address)) {
    exit(-1);
  }

}

/* Gets the passed in number of arguments off of the user's stack and checks to make sure they are valid addresses. */
void
copy_args(void *esp, int numArgs, int *args) {

  void *tempE = esp;
  for(int i = 0; i < numArgs; i++) {
    tempE += 4;
    address_check(tempE);
    args[i] = (int)tempE;
  }

}


static void
syscall_handler (struct intr_frame *f UNUSED) 
{
  /* Each system call requires a different amount of arguments */
  int numberOfArgumentsNeededForCall;
  
  /* The arguments can be held in a list like this */
  int *arguments;

  /* Gets the effective address of esp and makes sure it is valid */
  int *esp = (int *)f->esp;
  address_check(esp);
  
  /* Dereference esp to get the system call */  
  int system_call = (int)*esp;

  /* Switch for finding the correct method
    * for the system_call param */
  switch (system_call)
  {
    /* System Call: Halt
       Status: Done
    */
    case SYS_HALT:
      systemCall_halt();
      break;
    
    /* System Call: Exit
       Status: Needs implemented
    */
    case SYS_EXIT:
      arguments = (int*)malloc(1*sizeof(int));

      copy_args(esp, 1, arguments);

      address_check(*(esp+1));
      int *exitStatus = (int *)arguments[0];
      systemCall_exit(exitStatus);

      free(arguments);
      break;


    /* System Call: Exec
       Status: Think we are correct
    */
    case SYS_EXEC:
      arguments = (int*)malloc(1*sizeof(int));

      address_check((void*)(esp + 1));  //These check the address validity for the entire string by first checking the pointer
      address_check((void*)*(esp + 1)); //, then dereferenceing it and checking again

      copy_args(esp, 1, arguments); //gets the argument off of the stack

      char* arg2 = (char*)arguments[0]; 
      pid_t EAX = systemCall_exec(arg2);  //accuires output from method call
      f->eax = (uint32_t)EAX;  //assigns output to volitile register

      free(arguments);
      break;
    /* System Call: Wait
       Status: Needs implemented
    */
    case SYS_WAIT:
      arguments = (int*)malloc(1*sizeof(int));

      address_check((void*)(esp+1));

      copy_args(esp, 1, arguments);
      pid_t arg3 = (pid_t)arguments[0];
      f->eax = systemCall_wait(arg3);

      free(arguments);
      break;
    /* System Call: Create
       Status: Needs implemented
    */
    case SYS_CREATE:
      arguments = (int*)malloc(2*sizeof(int));

      address_check((void*)(esp+1));
      address_check((void*)*(esp+1));
      address_check((void*)(esp+2));

      copy_args(esp, 2, arguments);

      char *arg4 = (char*)arguments[0];
      unsigned arg5 = (unsigned)arguments[1];
      f->eax = (uint32_t)systemCall_create(arg4, arg5);

      free(arguments);
      break;
    /* System Call: Remove
       Status: Needs implemented
    */
    case SYS_REMOVE:
      arguments = (int*)malloc(1*sizeof(int));

      address_check((void*)(esp+1));
      address_check((void*)*(esp+1));

      copy_args(esp, 1, arguments);
      char *arg6 = (char*)arguments[0];
      f->eax = (uint32_t)systemCall_remove(arg6);

      free(arguments);
      break;
    /* System Call: Open
       Status: Think we are correct
    */
    case SYS_OPEN:
      arguments = (int*)malloc(1*sizeof(int));

      address_check((void*)(esp+1));
      address_check((void*)*(esp+1));

      copy_args(esp, 1, arguments);

      char *arg7 = (char*)arguments[0];
      //char *tempvar = *(esp + 2);
      //printf("%s\n\n",&tempvar);
      f->eax = (uint32_t)systemCall_open(arg7);

      free(arguments);
      break;
    
    /* System Call: Filesize
       Status: Needs implemented
    */
    case SYS_FILESIZE:
      arguments = (int*)malloc(1*sizeof(int));

      address_check((void*)(esp+1));
      copy_args(esp, 1, arguments);
      
      int arg8 = (int)arguments[0];
      f->eax = (uint32_t)systemCall_filesize(arg8);
      
      free(arguments);
      break;
    /* System Call: Read
       Status: Needs implemented
    */
    case SYS_READ:
      arguments = (int*)malloc(3*sizeof(int));

      address_check((void*)(esp+1));
      address_check((void*)(esp+2));
      address_check((void*)(esp+3));
      address_check((void*)*(esp+2));
      copy_args(esp, 3, arguments);

      int arg9 = (int)arguments[0];
      void *arg10 = (void*)arguments[1];
      unsigned arg11 = (unsigned)arguments[2];
      f->eax = (uint32_t)systemCall_read(arg9, arg10, arg11);

      free(arguments);
      break;
    /* System Call: Write
       Status: Actively working
    */  
    case SYS_WRITE:
      arguments = (int*)malloc(3*sizeof(int));
      
      address_check((void*)(esp+1));
      address_check((void*)(esp+2));
      address_check((void*)*(esp+2));
      address_check((void*)(esp+3));

      int arg12 = (int)arguments[0];
      void *arg13 = (void*)arguments[1];
      unsigned arg14 = (unsigned)arguments[2];
      //unsigned arg14 = 2;
      f->eax = systemCall_write(arg12, arg13, arg14);
      //printf("\n\nI am in SYS_WRITE\n\n");
      free(arguments);
      break;
    /* System Call: Create
       Status: Needs implemented
    */
    case SYS_SEEK:
      printf("\n\nI am in SYS_SEEK\n\n");
      arguments = (int*)malloc(2*sizeof(int));
      address_check((void*)(esp+1));
      address_check((void*)(esp+2));
      copy_args(esp, 2, arguments);
      int arg15 = (int)arguments[0];
      unsigned arg16 = (unsigned)arguments[1];
      systemCall_seek(arg15, arg16);
      free(arguments);
      break;
    /* System Call: Create
       Status: Needs implemented
    */  
    case SYS_TELL:
    int i = 0;
      printf("\n\nI am in SYS_TELL\n\n");
      arguments = (int*)malloc(1*sizeof(int));
      address_check((void*)(esp+1));
      copy_args(esp, 1, arguments);
      int arg17 = (int)arguments[0];
      systemCall_tell(arg17);
      free(arguments);
      break;
    /* System Call: Create
       Status: Needs implemented
    */
    case SYS_CLOSE:
      printf("\n\nI am in SYS_CLOSE\n\n");
      arguments = (int*)malloc(1*sizeof(int));
      address_check((void*)(esp+1));
      copy_args(esp, 1, arguments);
      int arg18 = (int)arguments[0];
      systemCall_close(arg18);
      free(arguments);
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
  struct thread* cur = thread_current();
  cur->exit = exitStatus;

  /* Iterate through the open pages and close them all
    to prevent resource leakage */
  for(int i = 0; i < 128; i++)
    if(cur->file_table[i] != NULL)
      close(i);



  /* Prints the exit stuff: Required by proj */
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