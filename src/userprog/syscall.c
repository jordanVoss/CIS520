#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include "threads/interrupt.h"
#include "threads/thread.h"
#include "devices/shutdown.h"
#include "threads/vaddr.h"
#include "userprog/process.h"
#include "filesys/filesys.h"
#include "filesys/file.h"
#include <string.h>
#include "devices/input.h"
#include "threads/malloc.h"

/* System call handler declaration */
static void syscall_handler (struct intr_frame *);

/* To protect the file disk, we use a binary semaphore to prevent file conflicts */
struct semaphore filesys_sema;

/*
* Method: syscall_init
* Purpose: Initializes the binary semaphore, sets the syscall handler method pointer
*/
void syscall_init (void)
{
  sema_init(&filesys_sema, 0);
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}


/*
* Method: checkAddress
* Purpose: Ensures that esp is in the memory space of the thread and not in the kernels.
*/
void checkAddress(void *addr)
{
  if (!is_user_vaddr(addr))
    exit(-1);
}


/*
* Method: getArguments
* Purpose: Grab all the arguments needed for the syscall
*/
void getArguments(void *esp, int *arg, int count)
{
  /* Grab all of the arguments for the current thread */
  for (int i = 0; i < count; i++)
  {
    esp += 4;               /* Since the arguments are integer, integers take 4 bytes of memory. We increment esp by 4 */
    checkAddress(esp);     /* Ensure address is valid. Will not return if it is not */
    arg[i]= (int)esp;
  }
  esp -= (4 * count);       /* Reset esp to original position */
}


/*
* Method: systemCall_halt
* Purpose: Shuts down the system. 
*/
void systemCall_halt ()
{
  shutdown_power_off();
}


/*
* Method: exit 
* Purpose: Closes all of the active pages for the thread. Assigns the exit status, and sends to kernel
              0 means exited fine
              anything else means something happened
*/
void exit (int status)
{
  struct thread* currentThread = thread_current();
  currentThread->exit_status = status;

  for (int i = 3; i < 128; i++) 
  {
      if (currentThread->file_table[i] != NULL) 
      {
          file_close(currentThread->file_table[i]);
          currentThread->file_table[i] = NULL;
      }
  }
  printf("%s: exit(%d)\n", currentThread->name, status); /* This is how the tests wants things printed */
  thread_exit();
}


/*
* Method: systemCall_exec
* Purpose: Runs command passed in through the command line. Creates a child and finds its pid
*/
pid_t systemCall_exec (const char *cmd_line) 
{
  pid_t child_pid = (pid_t)process_execute(cmd_line);
  struct thread *child_proc = findChildThread((int)child_pid);

  if(child_proc == NULL)
    return -1;
  
  else
    if(child_proc->load_flag == 1) /* Check to ensure the child was loaded correctly */
      return child_pid;
    
    else                           /* Child was not loaded correctly */
      return -1;
}


/*
* Method: systemCall_wait
* Purpose: Threads might need to wait on other threads. This method indicates when the process is finished
*/
int systemCall_wait (pid_t pid) 
{
  return process_wait(pid);
}


/*
* Method: systemCall_create
* Purpose: Creates a file called file with the size of initial_size
            This assumes file is not NULL
*/
bool systemCall_create (const char *file, unsigned int initial_size) 
{
  if (file == NULL) 
    exit(-1);
  else 
    return filesys_create(file, initial_size);
}


/*
* Method: systemCall_remove
* Purpose: Removes the file called file from the file disk
*/
bool systemCall_remove (const char *file) 
{
  return filesys_remove(file);
}


/*
* Method: systemCall_open
* Purpose: Opens the file called 'file' after ensuring that
              everything is OK
*/
int systemCall_open (const char *file)
{
  int fd = -1;
  struct thread *cur = thread_current();
  
  /* Grab the lock so we are the only one editing the file system */
  if(sema_try_down(&filesys_sema))
  {
    sema_down(&filesys_sema);

    /* If file is NULL just quit */
    if (file == NULL)
      fd = -1;
    
    /* File is not NULL */
    else 
    {
      struct file* open_file = filesys_open (file);
      
      /* Ensure the file actually opened */
      if(open_file != NULL)
      {
        if(strcmp(cur->name,file) == 0)
          file_deny_write(open_file);   /* File is now open. No editing can be done outside of this thread */

        /* Allocate the page table information so the thread can run */
        cur->file_table[cur->next_fd] = open_file;
        fd = cur->next_fd;
        for (int i = 3 ;i < 128; i++) 
        {
          if (cur->file_table[i] == NULL) 
          {
            cur->next_fd = i;
            break;
          }
        }
      }

      /* File didnt open */
      else
        fd = -1;
    }
    sema_up(&filesys_sema);
  }
  return fd;
}


/*
* Method: systemCall_filesize
* Purpose: Grabs the size of the file at fd and returns in bits
*/
int systemCall_filesize(int fd)
{
  struct file* read_file = thread_current()->file_table[fd];
  return file_length(read_file);
}


/*
* Method: systemCall_read 
* Purpose: Gets the number bytes till the end of the file
*/
int systemCall_read(int fd, void *buffer, unsigned int size)
{
  struct file* read_file;
  struct thread *cur = thread_current();
  int read_bytes = 0;
  
  if(sema_try_down(&filesys_sema))
  {
    sema_down(&filesys_sema);
    
    if(fd == 0)
    {
      for(int i = 0; (unsigned)i < size; i++)
        *((char *)buffer + i) = input_getc();

      read_bytes = size;
    } 
    else 
    {
      if(cur->file_table[fd] != NULL)
      {
        read_file = cur->file_table[fd];
        read_bytes = file_read(read_file, buffer, size);
      }

      else
        read_bytes = -1;
    }
    sema_up(&filesys_sema);
  }
  return read_bytes;
}


/*
* Method: systemCall_write
* Purpose: Writes the buffer to file descriptor fd and returns the number of bytes written to the file
            Note: it is possible for not all of the bytes to be written
*/
int systemCall_write(int fd, const void *buffer, unsigned int size)
{
  struct file* write_file;
  struct thread *cur = thread_current();
  int write_bytes = 0;

  if(sema_try_down(&filesys_sema))
  {
    sema_down(&filesys_sema);
    
    if(fd == 1)
    {
      putbuf(buffer, size);
      write_bytes = size;
    }
    else
    {
      if(cur->file_table[fd] != NULL)
      {
        write_file = cur->file_table[fd];
        write_bytes = file_write(write_file, buffer, size);
      }

      else
        write_bytes = 0;
    }
    sema_up(&filesys_sema);
  }
  return write_bytes;
}


/*
* Method: systemCall_seek
* Purpose: Changes the next byte to be read or written in fd 
*/
void systemCall_seek (int fd, unsigned int position)
{
  struct thread *cur = thread_current();
  
  /* If the file is NULL just quit */
  if(cur->file_table[fd] == NULL)
    exit(-1);
  
  /* Change the byte on the file */
  else
    file_seek(cur->file_table[fd],position);
}


/*
* Method: systemCall_tell
* Purpose: Returns the next byte to be read or written from fd
*/
unsigned int systemCall_tell (int fd)
{
  struct thread *cur = thread_current();
  
  /* If the file is NULL just quit */
  if(cur->file_table[fd] == NULL)
    exit(-1);
  
  /* Return the next byte in the descriptor */
  else
    return file_tell(cur->file_table[fd]);
}


/*
* Method: systemCall_close
* Purpose: Closes the file descriptor fd
*/
void systemCall_close (int fd)
{
  struct thread *cur = thread_current();
  
  if(cur->file_table[fd] != NULL)
  {
    file_close(cur->file_table[fd]);
    cur->file_table[fd] = NULL;
  }
}


/*
* Method: syscall_handler
* Purpose: Switch statement that sets up everything needed for the system calls
*/
static void syscall_handler (struct intr_frame *f) 
{
  int count;                  /* Number of arguments needed for the system call */
  int *arg;                   /* List of arguments for the system call */

  int *callAddress = f->esp;  /* Grab the call number */
  checkAddress(callAddress); /* Ensure valid address */
  
  /* Cast into a system call number 
      Enter the switch based on call number */
  int SYS_NUM = (int)*callAddress;  
  switch (SYS_NUM)
  {
    /* The most arguments a syscall needs is three 
          Declared here for readability */
    int *argument1;
    int *argument2;
    int *argument3;
    
    case SYS_HALT:
      systemCall_halt();
    break;

    case SYS_EXIT:
      /* Check addresses of arguments */
      checkAddress((void *)(callAddress + 1)); 
      
      /* Initialize variables */
      count = 1;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grab the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
      
      /* Calls the system call and free the variables */
      exit(*argument1);
      free(arg);
    break;

    case SYS_EXEC:
      /* Check addresses of arguments */
      checkAddress((void *)(callAddress + 1));
      
      /* Initialize variables */
      count = 1;
      arg = (int *)malloc(count*sizeof(int));

      /* Grabs the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];

      /* Calls the system call and frees the variables */
      f->eax = systemCall_exec((const char *)*argument1);
      free(arg);
    break;

    case SYS_WAIT:
      /* Check addresses of arguments */
      checkAddress((void *)(callAddress+1));
      
      /* Initialize variables */
      count = 1;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grabs the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];

      /* Ensures that there is an actual argument */
      if((int)*argument1 == -1)
        f->eax = -1;
      else
        f->eax = systemCall_wait((int)*(argument1));
      
      /* Free memory */
      free(arg);
    break;
 
   case SYS_CREATE:
      /* Check addresses of arguments */
      checkAddress((void *)(callAddress + 1));
      checkAddress((void *)(callAddress + 2));

      /* Initialize variables */
      count = 2;
      arg = (int *)malloc(count*sizeof(int));

      /* Grabs the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
      argument2 = (int *)arg[1];
      
      /* Calls the system call and frees the variables */
      f->eax = systemCall_create((const char *)*argument1, (unsigned int)*argument2);
      free(arg);
    break;
 
   case SYS_REMOVE:
      /* Check addresses of arguments */
      checkAddress((void *)(callAddress + 1));

      /* Initialize variables */
      count = 1;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grabs the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
      
      /* Calls the system call and frees the variables */
      f->eax = systemCall_remove((const char *)*(argument1 + 1));
      free(arg);
    break;

    case SYS_OPEN:
      /* Check addresses of arguments */      
      checkAddress((void *)(callAddress + 1)); 

      /* Initialize variables */
      count = 1;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grabs the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
      
      /* Calls the system call and frees the variables */
      f->eax = systemCall_open((const char *)*argument1); 
      free(arg);
    break;

    case SYS_FILESIZE:
      /* Check addresses of arguments */     
      checkAddress((void *)(callAddress + 1)); 
      
      /* Initialize variables */
      count = 1;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grabs the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
           
      /* Calls the system call and frees the variables */
      f->eax = systemCall_filesize(*argument1); 
      free(arg);
    break;

    case SYS_READ:
      /* Check addresses of arguments */    
      checkAddress((void *)(callAddress + 1));
      checkAddress((void *)(callAddress + 2));
      checkAddress((void *)(callAddress + 3));

      /* Initialize variables */
      count = 3;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grabs the arguments */      
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
      argument2 = (int *)arg[1];
      argument3 = (int *)arg[2];
      
      /* Calls the system call and frees the variables */      
      f->eax = systemCall_read((int)*argument1,(void *)*argument2,(unsigned int)*argument3); 
      free(arg);
    break;

    case SYS_WRITE:
      /* Check addresses of arguments */      
      checkAddress((void *)(callAddress + 1));
      checkAddress((void *)(callAddress + 2));
      checkAddress((void *)(callAddress + 3));

      /* Initialize variables */
      count = 3;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grabs the arguments */      
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
      argument2 = (int *)arg[1];
      argument3 = (int *)arg[2];
      
      /* Calls the system call and frees the variables */      
      f->eax = systemCall_write((int)*argument1,(const void*)*argument2,(unsigned int)*argument3);
      free(arg);
    break;

    case SYS_SEEK:
      /* Check addresses of arguments */
      checkAddress((void *)(callAddress + 1));
      checkAddress((void *)(callAddress + 2));
      
      /* Initialize variables */
      count = 2;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grabs the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
      argument2 = (int *)arg[1];
      
      /* Calls the system call and frees the variables */
      systemCall_seek((int)*argument1,(unsigned int)*argument2);
      free(arg);
      break;

    case SYS_TELL:
      /* Check addresses of arguments */
      checkAddress((void *)(callAddress + 1));
      
      /* Initialize variables */
      count = 1;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grabs the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
      
      /* Calls the system call and frees the variables */
      f->eax = systemCall_tell((int)*argument1);
      free(arg);
      break;

    case SYS_CLOSE:
      /* Check addresses of arguments */      
      checkAddress((void *)(callAddress + 1)); 
      
      /* Initialize variables */
      count = 1;
      arg = (int *)malloc(count*sizeof(int));
      
      /* Grabs the arguments */
      getArguments(f->esp, arg, count); 
      argument1 = (int *)arg[0];
      
      /* Calls the system call and frees the variables */
      systemCall_close(*argument1); 
      free(arg);
      break;
  }
}