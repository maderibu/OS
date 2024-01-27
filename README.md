# 实验一 开发环境准备

## 一、实验内容

为了进行接下来的实验，首先需要在电脑上安装相应的开发工具，以能够对编写的代码进行测试、提交等操作。

具体是要安装gcc等编译C语言的工具、克隆实验代码、qemu虚拟化模拟器、配置环境变量等。

## 二、实验步骤

1. 安装git工具

```
sudo apt-get update
sudo apt-get install git
```

2. 克隆实验代码仓库

使用以下指令克隆：

```
git clone https://gitlab.etao.net/zjutosd/fa23.git
```

3. 安装qemu虚拟化模拟器

安装指令如下：

```
sudo apt install qemu-system
```

4. 配置环境变量

```
export PATH=$PATH:~/new/fa23/pintos/src/utils
```

这样配置环境变量后，我可以在命令行中直接运行 `pintos` 相关的实用工具，而无需输入完整的路径。

## 三、实验结果

进入threads目录后，执行`make`和`make check`指令，结果如下图：

<img src="https://i0.imgs.ovh/2024/01/25/xzDw2.png" alt="xzDw2.png" style="zoom: 67%;" />

由于尚未编写代码，故大部分测试点未通过。

# 实验二、shell

## 一、实验目的

1. **理解Shell基本结构：** 学习Shell的基本结构、输入输出处理、命令解析等。
2. **掌握进程管理：** 了解fork()函数的使用，理解父子进程之间的关系，以及子进程如何执行外部程序。
3. **熟悉信号处理：** 学会使用signal()函数处理信号，比如在子进程中忽略SIGINT、SIGTSTP、SIGTTOU等信号。
4. **实现内置命令：** 编写内置命令的处理函数，例如cd、pwd等。
5. **支持I/O重定向：** 理解文件描述符的概念，实现简单的输入输出重定向功能。
6. **命令解析和执行：** 使用Tokenizer库解析用户输入的命令，并执行相应的操作。
7. **掌握基本的进程控制：** 使用waitpid()等函数等待子进程完成执行，以及恢复Shell为前台进程组。
8. **实现帮助命令：** 编写help命令，用于显示Shell支持的命令及其简要描述。

## 二、实验内容

在原始代码中，已经支持两个内置命令，分别是`exit`和`help`。用户可以通过输入这些命令来退出Shell或者获取内置命令的帮助信息。Shell在初始化时检查是否连接到实际终端，如果是交互式Shell，则通过信号(SIGTTIN)确保Shell在前台运行。用户输入的命令行会被解析成单词，然后查找内置命令表以确定要执行的命令。执行`exit`命令将导致Shell退出，而执行`help`命令则显示内置命令的帮助信息。在交互式Shell中，会打印简单的提示符。尽管代码中的外部程序执行部分被注释掉，但这是一个基础框架，接下来根据实验目标逐步扩展和完善。

1. cd命令的实现在函数`cmd_cd`中。以下是对该函数的分析：

   ```c
   int cmd_cd(struct tokens* tokens) {
        if (tokens_get_length(tokens) != 2)
        {
   	printf("cd: need path！\n");
   	    return 1;
        }
       char* dir = tokens_get_token(tokens, 1);
       if (chdir(dir) == -1) {
           perror("cd error");
           return 1;
       }
       return 0;
   }
   ```

   **参数检查：** 首先，函数检查`tokens`中是否包含了两个参数，即命令本身和目标目录的路径。如果参数数量不是2，就打印错误信息并返回1。

   ```c++
   1. if (tokens_get_length(tokens) != 2)
      {
          printf("cd: need path！\n");
          return 1;
      }
   ```

   **获取目标目录：** 通过`tokens_get_token(tokens, 1)`获取目标目录的路径。

   ```c
   char* dir = tokens_get_token(tokens, 1);
   ```

   **执行`chdir`：** 使用`chdir`函数改变当前工作目录到目标目录。如果执行成功，`chdir`返回0；否则，返回-1，并打印错误信息。

   ```c++
   if (chdir(dir) == -1) {
       perror("cd error");
       return 1;
   }
   ```

   **返回结果：** 如果`chdir`成功，函数返回0表示执行成功。否则，返回1表示执行失败。

   ```c
   return 0;
   ```

2. `pwd`命令的实现在函数`cmd_pwd`中。以下是对该函数的分析：

   ```c
   int cmd_pwd(struct tokens* tokens) {
       char cwd[2048];
       if (getcwd(cwd, sizeof(cwd)) != NULL) {
           printf("%s\n", cwd);
       } 
       else {
           perror("pwd error");
       }
       return 1;
   }
   ```

   **获取当前工作目录：** 使用`getcwd`函数获取当前工作目录的绝对路径，并将结果存储在`cwd`数组中。

   ```c
   if (getcwd(cwd, sizeof(cwd)) != NULL) {
           printf("%s\n", cwd);
       } 
   ```

   **打印当前工作目录：** 如果`getcwd`执行成功，将当前工作目录打印到标准输出。

   ```c
   printf("%s\n", cwd);
   ```

   **错误处理：** 如果`getcwd`执行失败，使用`perror`打印错误信息。

   ```c
   else {
       perror("pwd error");
   }
   ```

   **返回结果：** 无论成功与否，函数都返回1。在实际情况下，`pwd`命令通常不需要返回状态，因此这里直接返回1。

   ```c
   return 1;
   ```

   总体而言，`cmd_pwd`函数实现了`pwd`命令，用于获取并打印当前工作目录的绝对路径。如果获取失败，函数会打印错误信息。

3. `cmd_exe_prog`函数是用于执行外部程序的命令，支持重定向输入和输出。以下是对该函数的分析：

   ```c
   int cmd_exe_prog(struct tokens* tokens) {
   
       int num_tokens = tokens_get_length(tokens);
       if (num_tokens < 1)
       {
           printf("run: Requires at least one command or executable program path\n");
           return 1;
       }
       char *program_path = resolve_path(tokens_get_token(tokens, 0));
       if (program_path == NULL)
       {
           printf("can't find program！\n");
           return 1;
       }
       int is_redirect = 0;
       if (num_tokens >= 3)
       {
   
           if (strcmp(tokens_get_token(tokens, num_tokens - 2), ">") == 0)
           {
               is_redirect = 1;
               if (redirect_output(tokens_get_token(tokens, num_tokens - 1)) != 0)
               {
                   return 1;
               }
           }
   
           else if (strcmp(tokens_get_token(tokens, num_tokens - 2), "<") == 0)
           {
               is_redirect = 1;
               if (redirect_input(tokens_get_token(tokens, num_tokens - 1)) != 0)
               {
                   return 1;
               }
           }
       }
       // Create a child process
       pid_t pid = fork();
   
       if (pid == -1) {
           perror("create child process error");
           return 1;
       }
       else if (pid == 0) {
           // Child process
   
           setpgid(0, 0);
   
           signal(SIGINT, SIG_DFL);
           signal(SIGTSTP, SIG_DFL);
           signal(SIGTTOU, SIG_DFL);
   
           int new_argc = num_tokens;
           if (is_redirect == 1)
               new_argc = new_argc - 2;
   
           char **args = malloc((new_argc + 1) * sizeof(char *));
           if (args == NULL)
           {
               perror("error！\n");
               return 1;
           }
           for (size_t i = 0; i < new_argc; ++i) {
               args[i] = tokens_get_token(tokens, i);
           }
           args[new_argc] = NULL;
           execv(program_path, args);
           perror("execv error");
           exit(EXIT_FAILURE);
       }
       else
       {
           signal(SIGINT, SIG_IGN);
           tcsetpgrp(shell_terminal, pid);
           int status;
           waitpid(pid, &status, 0);
           tcsetpgrp(shell_terminal, shell_pgid);
           signal(SIGINT, SIG_DFL);
           reset_stdio();
       }
   
       reset_stdio();
       return 0;
   }
   ```

**参数检查：** 首先，函数检查是否提供了至少一个命令或可执行程序的路径。如果提供的参数少于1，就打印错误信息并返回1。

```C
int num_tokens = tokens_get_length(tokens);
if (num_tokens < 1)
{
    printf("run: Requires at least one command or executable program path\n");
    return 1;
}
```

**解析可执行程序路径：** 使用`resolve_path`函数获取可执行程序的绝对路径。

```c
char *program_path = resolve_path(tokens_get_token(tokens, 0));
if (program_path == NULL)
{
    printf("can't find program！\n");
    return 1;
}
```

**重定向处理：** 检查命令中是否包含重定向符号（`>`或`<`），如果有，则进行相应的输入或输出重定向。

```c
int is_redirect = 0;
if (num_tokens >= 3)
{
    if (strcmp(tokens_get_token(tokens, num_tokens - 2), ">") == 0)
    {
        is_redirect = 1;
        if (redirect_output(tokens_get_token(tokens, num_tokens - 1)) != 0)
        {
            return 1;
        }
    }
    else if (strcmp(tokens_get_token(tokens, num_tokens - 2), "<") == 0)
    {
        is_redirect = 1;
        if (redirect_input(tokens_get_token(tokens, num_tokens - 1)) != 0)
        {
            return 1;
        }
    }
}
```

**创建子进程：** 使用`fork`函数创建一个子进程。

```c
pid_t pid = fork();
if (pid == -1) {
    perror("create child process error");
    return 1;
}
```

**子进程执行：** 在子进程中，设置新的进程组ID，处理信号，解析参数，执行`execv`以替换当前进程为新程序。

```c
else if (pid == 0) {
    // Child process

    setpgid(0, 0);

    signal(SIGINT, SIG_DFL);
    signal(SIGTSTP, SIG_DFL);
    signal(SIGTTOU, SIG_DFL);

    int new_argc = num_tokens;
    if (is_redirect == 1)
        new_argc = new_argc - 2;

    char **args = malloc((new_argc + 1) * sizeof(char *));
    if (args == NULL)
    {
        perror("error！\n");
        return 1;
    }
```

## 三、实验结果

该实验代码通过了大部分的样例。

<img src="https://i0.imgs.ovh/2024/01/25/xJE25.png" style="zoom:67%;" />

接下来进行指令功能测试。

1. **测试`cd`指令**

![xJqUX.png](https://i0.imgs.ovh/2024/01/25/xJqUX.png)

2. **测试`pwd`指令**

![xJGCU.png](https://i0.imgs.ovh/2024/01/25/xJGCU.png)

3. **测试**`exe_prog`指令

​		测试不在shell.c代码中的指令`ls`，执行结果如下：

<img src="https://i0.imgs.ovh/2024/01/25/xzw8V.png" alt="xzw8V.png" style="zoom:67%;" />

4. 测试`help`指令

![xzfFJ.png](https://i0.imgs.ovh/2024/01/25/xzfFJ.png)

可见列出了可用命令列表。

5. 测试`exit`指令

![xzmsW.png](https://i0.imgs.ovh/2024/01/25/xzmsW.png)

可见退出了shell程序。

6. 测试重定向

![xzNjW.png](https://i0.imgs.ovh/2024/01/25/xzNjW.png)

![xzvVv.png](https://i0.imgs.ovh/2024/01/25/xzvVv.png)

output.txt中出现了"hello world"，指令测试成功。

综上所述，各个指令正常运行。

7. 输入重定向测试

先编辑output.txt内容如下所示：

![xUtv3.png](https://i0.imgs.ovh/2024/01/25/xUtv3.png)

再执行`wc`指令。`wc`命令用于统计文件中的行数、字数和字节数。

结果如下图：

![xUJ39.png](https://i0.imgs.ovh/2024/01/25/xUJ39.png)

## 四、Shell实验总结

在本次实验中，我成功实现了一个简单的 Shell 程序，具有基本的交互功能和一些内置命令，包括 `cd`、`pwd`、`exit`、以及新增的 `exe_prog` 命令。`exe_prog` 命令允许用户执行其他程序，并通过解析输入的程序路径实现了基本的程序执行功能。在实现过程中，我学到了如何处理命令行参数、解析输入、以及执行外部程序的基本步骤。同时，通过对文件操作和进程控制的处理，我加深了对系统编程和进程管理的理解。这次实验为我提供了一个良好的机会，通过实际动手操作，更深入地理解了操作系统的底层原理和系统调用的使用。通过不断调试和测试，我确保了 Shell 在各种情况下的稳健性和正确性。总体而言，这次实验增强了我的编程技能，使我更加熟悉系统级编程和操作系统概念。

# 实验三、User Programs

## 一、实验目的

阅读分析Pintos源码，实现User Program部分的以下功能：

- Argument Passing 参数传递
- Process Control Syscalls 进程控制系统调用
- File Operating Syscalls 文件操作系统调用

## 二、实验内容

### 2.1 Argument Passing 参数传递

参数传递主要是通过设置用户线程的初始栈来实现的，具体可以分为以下几个步骤：

**加载可执行文件：** 在`load`函数中，通过打开并读取可执行文件，将可执行文件的内容读入内存。接着，对ELF头和程序头进行验证，然后根据程序头的信息加载相应的段到用户内存空间。

```c
bool load(const char* file_name, void (**eip)(void), void** esp) {
  struct thread* t = thread_current();
  struct Elf32_Ehdr ehdr;
  struct file* file = NULL;
  off_t file_ofs;
  bool success = false;
  int i;

  /* Allocate and activate page directory. */
  t->pcb->pagedir = pagedir_create();
  if (t->pcb->pagedir == NULL)
    goto done;
  process_activate();

  /* Open executable file. */
  file = filesys_open(file_name);
  if (file == NULL) {
    printf("load: %s: open failed\n", file_name);
    goto done;
  }

  /* Read and verify executable header. */
  if (file_read(file, &ehdr, sizeof ehdr) != sizeof ehdr ||
      memcmp(ehdr.e_ident, "\177ELF\1\1\1", 7) || ehdr.e_type != 2 || ehdr.e_machine != 3 ||
      ehdr.e_version != 1 || ehdr.e_phentsize != sizeof(struct Elf32_Phdr) || ehdr.e_phnum > 1024) {
    printf("load: %s: error loading executable\n", file_name);
    goto done;
  }

  /* Read program headers. */
  file_ofs = ehdr.e_phoff;
  for (i = 0; i < ehdr.e_phnum; i++) {
    struct Elf32_Phdr phdr;

    if (file_ofs < 0 || file_ofs > file_length(file))
      goto done;
    file_seek(file, file_ofs);

    if (file_read(file, &phdr, sizeof phdr) != sizeof phdr)
      goto done;
    file_ofs += sizeof phdr;
    switch (phdr.p_type) {
      case PT_NULL:
      case PT_NOTE:
      case PT_PHDR:
      case PT_STACK:
      default:
        /* Ignore this segment. */
        break;
      case PT_DYNAMIC:
      case PT_INTERP:
      case PT_SHLIB:
        goto done;
      case PT_LOAD:
        if (validate_segment(&phdr, file)) {
          bool writable = (phdr.p_flags & PF_W) != 0;
          uint32_t file_page = phdr.p_offset & ~PGMASK;
          uint32_t mem_page = phdr.p_vaddr & ~PGMASK;
          uint32_t page_offset = phdr.p_vaddr & PGMASK;
          uint32_t read_bytes, zero_bytes;
          if (phdr.p_filesz > 0) {
            /* Normal segment.
                     Read initial part from disk and zero the rest. */
            read_bytes = page_offset + phdr.p_filesz;
            zero_bytes = (ROUND_UP(page_offset + phdr.p_memsz, PGSIZE) - read_bytes);
          } else {
            /* Entirely zero.
                     Don't read anything from disk. */
            read_bytes = 0;
            zero_bytes = ROUND_UP(page_offset + phdr.p_memsz, PGSIZE);
          }
          if (!load_segment(file, file_page, (void*)mem_page, read_bytes, zero_bytes, writable))
            goto done;
        } else
          goto done;
        break;
    }
  }

  /* Set up stack. */
  if (!setup_stack(esp))
    goto done;

  /* Start address. */
  *eip = (void (*)(void))ehdr.e_entry;

  success = true;

done:
  /* We arrive here whether the load is successful or not. */
  lock_acquire(&file_lock);
  if (success) {
    file_deny_write(file);
    t->pcb->file = file;
  } else
    file_close(file);
  lock_release(&file_lock);
  return success;
}
```

**设置用户栈：** 在`setup_stack`函数中，为用户线程设置初始栈。首先，通过`palloc_get_page`函数获取一页用户内存空间，并将其清零。然后，调用`install_page`函数将用户栈映射到该内存页上。

```c
static bool setup_stack(void** esp) {
  uint8_t* kpage;
  bool success = false;

  kpage = palloc_get_page(PAL_USER | PAL_ZERO);
  if (kpage != NULL) {
    success = install_page(((uint8_t*)PHYS_BASE) - PGSIZE, kpage, true);
    if (success)
      *esp = PHYS_BASE;
    else
      palloc_free_page(kpage);
  }
  return success;
}
```

**设置线程上下文：** 在`start_pthread`函数中，将线程的初始上下文设置为`stub_fun`指向的函数。同时，为线程设置初始栈指针，确保线程在开始执行时具有正确的上下文和栈。

```c
static void start_pthread(void* exec_) {
  struct start_pthread_args* start_pthread_args = (struct start_pthread_args*)exec_;
  struct thread* t = thread_current();
  struct intr_frame if_;
  struct thread_node* node = get_thread_node(t->tid);
  t->pcb = start_pthread_args->pcb;
  process_activate();

  memset(&if_, 0, sizeof if_);
  if_.gs = if_.fs = if_.es = if_.ds = if_.ss = SEL_UDSEG;
  if_.cs = SEL_UCSEG;
  if_.eflags = FLAG_IF | FLAG_MBS;
  if_.eip = (void (*)(void))start_pthread_args->sf;
  node->load_success = setup_thread(&if_.esp);

  if (node->load_success) {
    list_push_back(&t->pcb->all_threads, &t->p_elem);
    int align_size = 0x08;
    if_.esp -= align_size;
    memset(if_.esp, 0, align_size);

    if_.esp -= sizeof(start_pthread_args->arg);
    *(void**)if_.esp = start_pthread_args->arg;
    if_.esp -= sizeof(start_pthread_args->tf);
    *(void**)if_.esp = start_pthread_args->tf;
    if_.esp -= 0x04;
    memset(if_.esp, 0, 4);
  } else {
    sema_up(&node->load_semaph);
    pthread_exit();
  }
  sema_up(&node->load_semaph);
  asm("fsave (%0)" : : "g"(&if_.fp_regs)); // fill in the frame with current FP registers
  /* Start the user process by simulating a return from an
     interrupt, implemented by intr_exit (in
     threads/intr-stubs.S).  Because intr_exit takes all of its
     arguments on the stack in the form of a `struct intr_frame',
     we just point the stack pointer (%esp) to our stack frame
     and jump to it. */
  asm volatile("movl %0, %%esp; jmp intr_exit" : : "g"(&if_) : "memory");
  NOT_REACHED();
}
```

**处理参数：** 在`pthread_execute`函数中，创建一个新的用户线程，并将`start_pthread_args`结构体作为参数传递给线程。在`start_pthread`函数中，通过解析`start_pthread_args`结构体，获取`sf`（`stub_fun`）、`tf`（`pthread_fun`）和`arg`等参数。然后，将这些参数按照调用函数的规约（calling convention）设置到用户栈上，以便线程在开始执行时能够正确获取参数。

```c
tid_t pthread_execute(stub_fun sf, pthread_fun tf, void* arg) {
  tid_t tid;
  struct thread_node* thread_node = malloc(sizeof(struct thread_node));
  thread_node->exit_status = -1;
  thread_node->already_wait = false;
  thread_node->p_pid = thread_current()->pcb->main_thread->tid;
  thread_node->load_success = false;
  sema_init(&thread_node->semaph, 0);
  sema_init(&thread_node->load_semaph, 0);
  lock_acquire(&thread_lock);
  list_push_back(&thread_nodes_list, &thread_node->elem);
  lock_release(&thread_lock);

  struct start_pthread_args* start_pthread_args = malloc(sizeof(struct start_pthread_args));
  start_pthread_args->sf = sf;
  start_pthread_args->tf = tf;
  start_pthread_args->arg = arg;
  start_pthread_args->pcb = thread_current()->pcb;

  const char* file_name = (char*)tf;
  thread_node->tid = tid = thread_create(file_name, PRI_DEFAULT, start_pthread, (void*)start_pthread_args);
  if (tid == TID_ERROR)  free(start_pthread_args);

  sema_down(&thread_node->load_semaph);
  if (!thread_node->load_success) return TID_ERROR;
  return tid;
}
```

**用户栈布局：** 用户栈的布局在`start_pthread`函数中进行了细致的处理。通过向用户栈上按照规定的布局顺序推送参数，构建了一个仿照函数调用的栈帧。这包括设置栈帧中的返回地址、参数、以及线程执行的入口地址等信息。

### 2.2 Process Control Syscalls 进程控制系统调用

代码实现了一些关于进程控制的系统调用。以下是每个系统调用的简要分析：

1. **`syscall_exit`：**
   - 当系统调用号为 `SYS_EXIT` 时，调用该函数。
   - 将参数传递给用户线程的退出状态，然后调用 `process_exit` 结束当前线程。
2. **`syscall_exec`：**
   - 当系统调用号为 `SYS_EXEC` 时，调用该函数。
   - 检查传递的字符串参数的有效性，然后调用 `process_execute` 启动一个新进程。将新进程的 PID 存储在 `f->eax` 中。
3. **`syscall_create`：**
   - 当系统调用号为 `SYS_CREATE` 时，调用该函数。
   - 检查传递的文件名参数的有效性，然后调用 `filesys_create` 创建一个新文件。
4. **`syscall_remove`：**
   - 当系统调用号为 `SYS_REMOVE` 时，调用该函数。
   - 检查传递的文件名参数的有效性，然后调用 `filesys_remove` 删除文件。
5. **`syscall_open`：**
   - 当系统调用号为 `SYS_OPEN` 时，调用该函数。
   - 检查传递的文件名参数的有效性，然后调用 `open_for_syscall` 打开文件。
6. **`syscall_file_size`：**
   - 当系统调用号为 `SYS_FILESIZE` 时，调用该函数。
   - 根据文件描述符获取对应的文件，并返回该文件的大小。
7. **`syscall_read`：**
   - 当系统调用号为 `SYS_READ` 时，调用该函数。
   - 如果文件描述符为 0（标准输入），则从输入设备读取字符；否则，从文件中读取数据。
8. **`syscall_write`：**
   - 当系统调用号为 `SYS_WRITE` 时，调用该函数。
   - 如果文件描述符为 1（标准输出），则将数据写入控制台；否则，将数据写入文件。
9. **`syscall_seek`：**
   - 当系统调用号为 `SYS_SEEK` 时，调用该函数。
   - 根据文件描述符获取对应的文件，并设置文件位置。
10. **`syscall_tell`：**
    - 当系统调用号为 `SYS_TELL` 时，调用该函数。
    - 根据文件描述符获取对应的文件，并返回当前文件位置。
11. **`syscall_close`：**
    - 当系统调用号为 `SYS_CLOSE` 时，调用该函数。
    - 关闭对应文件描述符的文件。

这些系统调用实现了基本的进程控制功能，包括进程的创建、退出，文件的创建、删除、打开、关闭，以及文件的读写等操作。整个代码结构清晰，对用户程序提供了基本的系统调用接口。

### 2.3 File Operating Syscalls 文件操作系统调用

以下是关于文件操作系统调用的分析：

1. **`syscall_create`：**
   - 实现了文件创建的系统调用。
   - 通过 `filesys_create` 函数创建一个新文件，传递的参数为文件名和初始大小。
2. **`syscall_remove`：**
   - 实现了文件删除的系统调用。
   - 通过 `filesys_remove` 函数删除指定文件。
3. **`syscall_open`：**
   - 实现了文件打开的系统调用。
   - 调用 `open_for_syscall` 函数打开指定文件，返回文件描述符。
4. **`syscall_file_size`：**
   - 实现了获取文件大小的系统调用。
   - 根据文件描述符获取对应的文件，然后调用 `file_length` 函数返回文件大小。
5. **`syscall_read`：**
   - 实现了文件读取的系统调用。
   - 如果文件描述符是 0（标准输入），则从输入设备读取字符；否则，从文件中读取数据。
6. **`syscall_write`：**
   - 实现了文件写入的系统调用。
   - 如果文件描述符是 1（标准输出），则将数据写入控制台；否则，将数据写入文件。
7. **`syscall_seek`：**
   - 实现了设置文件位置的系统调用。
   - 根据文件描述符获取对应的文件，并调用 `file_seek` 函数设置文件位置。
8. **`syscall_tell`：**
   - 实现了获取文件位置的系统调用。
   - 根据文件描述符获取对应的文件，并调用 `file_tell` 函数返回当前文件位置。
9. **`syscall_close`：**
   - 实现了文件关闭的系统调用。
   - 调用 `close_file` 函数关闭指定文件描述符的文件。

这些文件操作系统调用提供了对文件的基本操作，包括创建、删除、打开、关闭、读取和写入等。在实现过程中，对文件描述符和文件结构进行了有效的管理，并通过相应的文件系统函数完成底层文件操作。整体上，这些系统调用为用户程序提供了对文件的标准访问接口。

## 三、实验结果

以下是测试结果。实验代码通过了大部分测试用例。

![xzSs5.png](https://i0.imgs.ovh/2024/01/25/xzSs5.png)

## 四、User Programs实验总结

"user programs"实验通过实现用户程序加载和执行的相关功能，成功将用户程序与内核空间有效地分离，实现了用户程序的用户级执行。通过合理设计系统调用，如进程创建、等待、退出以及文件操作等，实现了用户程序对系统资源的合理访问。实验中，对进程的上下文切换、异常处理等进行了有效管理，确保了系统的稳定性和可靠性。同时，文件系统调用的实现为用户程序提供了对文件的基本操作接口。通过这一系列的实验，深入理解了操作系统内核与用户程序之间的交互机制，加深了对操作系统底层原理的理解。

# 实验总结

## 1.对专业知识基本概念、基本理论和典型方法的理解

在操作系统课程设计进行的过程中，我对相关专业知识取得了一定的理解，一些基本概念、基本理论和典型方法包括：

1. **进程和线程：** 理解进程和线程的概念，以及它们在操作系统中的作用和管理。这可能涉及到进程控制块（PCB）、上下文切换等方面的知识。
2. **系统调用：** 熟悉系统调用的概念和实现方式。系统调用是用户程序与操作系统之间进行通信的接口，包括文件操作、进程管理等。
3. **文件系统：** 了解文件系统的组织结构和基本操作。这包括文件描述符、文件读写、文件管理等方面的内容。
4. **内存管理：** 学习内存管理的原理，包括虚拟内存、分页、分段等概念。了解地址空间和物理内存的映射关系。
5. **同步和互斥：** 熟悉多线程环境下的同步和互斥机制，如锁、信号量等。了解如何避免死锁和保证资源安全访问。
6. **中断和异常处理：** 掌握中断和异常的概念，了解中断向量表、中断处理程序等。了解操作系统如何处理硬件中断和软件异常。
7. **设备驱动程序：** 了解设备驱动程序的设计和实现。包括设备的初始化、中断处理、数据传输等。
8. **用户程序执行：** 知道用户程序的加载和执行过程。理解系统调用的触发和用户态与内核态的切换。
9. **操作系统设计原则：** 学习操作系统设计的基本原则，如模块化、可扩展性、性能优化等。

## 2.**怎么建立模型。**

#### 步骤：

1. **需求分析：** 确定操作系统的功能和性能需求。这可能包括进程管理、文件系统、内存管理等。
2. **架构设计：** 设计操作系统的总体架构，包括模块之间的关系和交互。
3. **模块划分：** 将操作系统分解为不同的模块，每个模块负责特定的功能。常见的模块包括内核、文件系统、设备驱动程序等。
4. **接口定义：** 定义模块之间的接口和通信机制。这有助于确保模块可以有效地协同工作。
5. **数据结构设计：** 设计和选择适当的数据结构，以支持操作系统的功能。例如，进程控制块、文件描述符等。
6. **算法设计：** 设计用于实现操作系统功能的算法。例如，调度算法、文件分配算法等。
7. **实现和调试：** 编写和调试每个模块的代码。确保模块之间的协作正确并处理异常情况。
8. **性能优化：** 根据需求对操作系统进行性能优化，以提高响应速度、减少资源占用等。
9. **测试：** 对操作系统进行全面的测试，包括功能测试、性能测试和稳定性测试。

#### 注意事项：

- **安全性和稳定性：** 操作系统模型必须具备良好的安全性和稳定性，以防止恶意攻击和系统崩溃。
- **扩展性：** 考虑未来的扩展性，确保操作系统可以适应新的硬件和应用需求。

总的来说，建立模型的关键在于清晰的问题定义、有效的数据处理和适当的评估。模型的建立是一个迭代的过程，需要不断调整和优化。

## 3.  **如何利用基本原理解决复杂工程问题。**

操作系统中，利用基本原理解决复杂工程问题是一个关键而复杂的任务。以下是一些操作系统中如何应用基本原理解决复杂工程问题的方法：

### 1. **抽象和模块化设计：**

- **原理应用：** 使用基本原理如进程管理、内存管理和文件系统等，对系统进行抽象和模块化设计。这使得系统更易于理解、维护和扩展。
- **问题解决：** 当面临复杂问题时，将其分解为更小的、可管理的部分。每个部分可以由相应的模块或原理来解决，从而降低整体系统的复杂性。

### 2. **进程与线程管理：**

- **原理应用：** 利用进程和线程管理原理，实现多任务并发执行。这使得系统可以更有效地处理多个任务，提高系统资源利用率。
- **问题解决：** 针对复杂应用，可以将其分解为多个进程或线程，每个负责不同的任务。通过进程/线程间的通信和同步，协同完成整体目标。

### 3. **内存管理：**

- **原理应用：** 使用内存管理原理，将物理内存抽象为虚拟内存，实现对进程的内存隔离和保护。
- **问题解决：** 处理大型应用时，通过虚拟内存技术，系统可以更高效地使用有限的物理内存，并为每个进程提供足够的地址空间。

### 4. **文件系统设计：**

- **原理应用：** 利用文件系统原理，将数据组织为文件和目录，提供对数据的有序访问和管理。
- **问题解决：** 面对大量数据和多用户访问时，文件系统的良好设计可以提供高效的文件组织结构和访问方式，确保数据的完整性和一致性。

### 5. **设备管理：**

- **原理应用：** 利用设备管理原理，实现对硬件设备的有效控制和调度，提供标准的接口。
- **问题解决：** 在面对多样化的硬件设备时，设备管理原理可以提供一致的方式与设备进行交互，使得系统可以适应不同硬件配置。

### 6. **错误处理和容错设计：**

- **原理应用：** 使用错误处理和容错原理，提高系统的鲁棒性和可靠性。
- **问题解决：** 当系统面临故障或异常时，容错设计可以确保系统能够从错误中恢复，继续提供服务，减小系统崩溃的可能性。

总体而言，操作系统利用基本原理通过抽象、模块化和标准化的设计方法，解决复杂工程问题。这种基于原理的设计使得系统更具扩展性、可维护性和性能优越性。

## 4.*具有实验方案设计的能力*

在操作系统设计中，具有实验方案设计的能力意味着能够结合理论知识和实际需求，提出并实施创新性的实验方案。这包括对操作系统的各个模块和功能进行深入理解，能够分析和解决实际问题，并通过设计合理的实验验证新的概念、算法或优化策略。实验方案设计的能力还要求对系统性能、稳定性和安全性等方面进行全面考量，以确保设计的方案在实践中能够有效地应用和取得实质性的成果。

## 5.如何对环境和社会的可持续发展。

在追求环境和社会的可持续发展方面，关键在于实施综合性的策略，平衡经济、社会和环境之间的关系。首先，可持续发展需要建立绿色和环保的生产方式，采用清洁能源、降低资源浪费、减少污染排放，以确保经济增长的同时不对生态环境造成不可逆转的破坏。通过技术创新和绿色产业的发展，可以推动可持续经济的建设，实现资源的高效利用。

其次，社会可持续发展需要关注社会公正和包容性。这包括提高教育水平、促进社会公平、减少贫富差距，以及推动公共卫生和医疗服务的普及。通过建立社会保障体系和推动社会公益事业，可以实现社会资源的公平分配，为全体人民提供更好的生活条件。

综合而言，环境和社会的可持续发展需要在经济、社会和环境三个方面取得平衡。这要求政府、企业和社会各界通力合作，制定并执行全面的可持续发展战略，确保在满足当前需求的同时不损害未来的发展空间。
