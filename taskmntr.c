/* This is the only file you should update and submit. */

/* Fill in your Name and GNumber in the following two comment fields
 * Name: Aidan Grupac
 * GNumber: G01367405
 */

#include <sys/wait.h>
#include "taskmntr.h"
#include "parse.h"
#include "util.h"


//linked list node struct
typedef struct node{
    //the instruction itself
    Instruction instruction;
    //the status of the instruction's process
    int status;
    //the exit code of the instruction's process
    int exit_code;
    //the process id of the instruction's process
    int pid;
    //the command line of the instruction
    char *cmd;
    //process type - foreground or background
    int process_type;
    //tasknum
    int tasknum;
    //number of nodes in list (only used by head)
    int total_nodes;
    //pointer to next node
    struct node *next;
} Node;

//PROTOTYPES
int main();
void set_handlers();
void reset_handlers();
void ctrlc_handler(int);
void ctrlz_handler(int);
void sigchld_handler(int);
void block_sigchld();
void unblock_sigchld();
void create_node(Instruction, char *, Node *);
void copy_node(Node *, Node *);
void add_to_history(Node *, Node *);
void add_to_tasklist(Node *, Node *);
void assign_tasknum(Node *, Node *);
Node * find_task_by_tasknum(int, Node *);
Node * find_task_by_pid(pid_t, Node *);
void remove_task(int, Node *);
void parse_iofiles(char **, Node *);
void generate_process_args(char **, Node *);
void file_cleanup(int, int, Node *);
void exec_child_process(char **, Node *);
void choose_instruction(int, Node *, char **, Node *, Node *);
void inst_help();
void inst_quit();
void inst_history(char **, Node *, Node *);
void inst_list(Node *);
void inst_delete(char **, Node *);
void inst_exec(char **, Node *);
void inst_bg(char **, Node *);
void inst_pipe(char **, Node *);
void inst_kill(char **, Node *);
void inst_suspend(char **, Node *);
void inst_resume(char **, Node *);
void inst_command(Node *);


//GLOBALS
//dummy head node for history list
Node *history_head;
//dummy head node for task list
Node *tasklist_head;
//the current task - for access in signal handlers
Node *current_task;

//handler structs
struct sigaction ctrlc_new, ctrlc_old;
struct sigaction ctrlz_new, ctrlz_old;
struct sigaction sigchld_new, sigchld_old;


/* The entry of your task controller program */
int main(){
    /* Command line */
    char cmdline[MAXLINE];        
    char *cmd = NULL;

    /* Intial Prompt and Welcome */
    log_intro();
    log_help();

    //allocate dummy heads
    history_head = calloc(1, sizeof(Node));
    tasklist_head = calloc(1, sizeof(Node));

    //update signal handling
    memset(&ctrlc_new, 0, sizeof(ctrlc_new));
    memset(&ctrlz_new, 0, sizeof(ctrlz_new));
    memset(&sigchld_new, 0, sizeof(sigchld_new));
    set_handlers();
    
    /* Shell looping here to accept user command and execute */
    while(1){
        /* Argument list */
        char *argv[MAXARGS+1]; 

        //Instruction struct     
        Instruction inst;

        /* Print prompt */
        log_prompt();

        /* Read a line */
        // note: fgets will keep the ending '\n'
	    errno = 0;
        if(fgets(cmdline, MAXLINE, stdin) == NULL){
            if(errno == EINTR) continue;
            exit(-1);
        }

        /* ctrl-d will exit text processor */
        if(feof(stdin)) exit(0);

        /* Parse command line */
        /* empty cmd line will be ignored */
        if(strlen(cmdline) == 1) continue;  

        /* remove trailing '\n' */
        cmdline[strlen(cmdline) - 1] = '\0';  

        /* duplicate the command line */
        cmd = malloc(strlen(cmdline) + 1);
        snprintf(cmd, strlen(cmdline) + 1, "%s", cmdline);

        /* Bail if command is only whitespace */
        if(!is_whitespace(cmd)){
            /* initialize arg lists and instruction */
            initialize_command(&inst, argv); 
            /* call provided parse() */   
            parse(cmd, &inst, argv);            

            /* After parsing: your code to continue from here */
            /*================================================*/

            //create a node for the instruction
            Node *inst_node = calloc(1, sizeof(Node));
            create_node(inst, cmd, inst_node);

            //decide which builtin command to execute
            choose_instruction(1, inst_node, argv, history_head, tasklist_head);
            
        }  // end if(!is_whitespace(cmd))

    }  // end while(1)

    return 0;
}


//updates handling for SIGINT, SIGTSTP, and SIGCHLD to new behavior
void set_handlers(){

    ctrlc_new.sa_handler = ctrlc_handler;
    sigaction(SIGINT, &ctrlc_new, &ctrlc_old);

    ctrlz_new.sa_handler = ctrlz_handler;
    sigaction(SIGTSTP, &ctrlz_new, &ctrlz_old);

    sigchld_new.sa_handler = sigchld_handler;
    sigaction(SIGCHLD, &sigchld_new, &sigchld_old);
}


//resets handling for SIGINT, SIGTSTP, and SIGCHLD to default behavipr
void reset_handlers(){

    ctrlc_new.sa_handler = SIG_DFL;
    sigaction(SIGINT, &ctrlc_new, &ctrlc_old);

    ctrlz_new.sa_handler = SIG_DFL;
    sigaction(SIGTSTP, &ctrlz_new, &ctrlz_old);

    sigchld_new.sa_handler = SIG_DFL;
    sigaction(SIGCHLD, &sigchld_new, &sigchld_old);
}


//SIGINT (ctrl-c) handler
void ctrlc_handler(int sig){

    log_ctrl_c();
    if(current_task && current_task->status == LOG_STATE_RUNNING && current_task->process_type == LOG_FG){
        kill(current_task->pid, SIGINT);
    }
}


//SIGTSTP (ctrl-z) handler
void ctrlz_handler(int sig){

    log_ctrl_z();
    if(current_task && current_task->status == LOG_STATE_RUNNING && current_task->process_type == LOG_FG){
        kill(current_task->pid, SIGTSTP);
    }
}


//SIGCHLD handler
void sigchld_handler(int sig){

    int status = 0;
    while(1){
        pid_t pid = waitpid(-1, &status, WNOHANG | WCONTINUED | WUNTRACED);
        if(pid <= 0) return;

        current_task = find_task_by_pid(pid, tasklist_head);

        if(WIFEXITED(status)){
            current_task->status = LOG_STATE_FINISHED;
            current_task->exit_code = WEXITSTATUS(status);
            log_status_change(current_task->tasknum, pid, current_task->process_type, current_task->cmd, LOG_TERM);
            /* char msg[] = "\t\tCHILD TERMINATED\n";//DEBUG
            write(STDOUT_FILENO, msg, strlen(msg));//DEBUG */
        }
        else if(WIFSTOPPED(status)){
            current_task->status = LOG_STATE_SUSPENDED;
            log_status_change(current_task->tasknum, pid, current_task->process_type, current_task->cmd, LOG_SUSPEND);
            /* char msg[] = "\t\tCHILD SUSPENDED\n";//DEBUG
            write(STDOUT_FILENO, msg, strlen(msg));//DEBUG */
        }
        else if(WIFSIGNALED(status)){
            current_task->status = LOG_STATE_KILLED;
            current_task->exit_code = WEXITSTATUS(status);
            log_status_change(current_task->tasknum, pid, current_task->process_type, current_task->cmd, LOG_TERM_SIG);
            /* char msg[] = "\t\tCHILD KILLED\n";//DEBUG
            write(STDOUT_FILENO, msg, strlen(msg));//DEBUG */
        }
        else if(WIFCONTINUED(status)){
            current_task->status = LOG_STATE_RUNNING;
            log_status_change(current_task->tasknum, pid, current_task->process_type, current_task->cmd, LOG_RESUME);
            /* char msg[] = "\t\tCHILD RESUMED\n";//DEBUG
            write(STDOUT_FILENO, msg, strlen(msg));//DEBUG */
        }
        /* else{
            char msg[] = "\t\tERROR\n";//DEBUG
            write(STDOUT_FILENO, msg, strlen(msg));//DEBUG
        } */
    }
}


//SIGCHLD blocking
void block_sigchld(){

    sigset_t mask, prev_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_BLOCK, &mask, &prev_mask);
}


//SIGCHLD unblocking
void unblock_sigchld(){

    sigset_t mask, prev_mask;
    sigemptyset(&mask);
    sigaddset(&mask, SIGCHLD);
    sigprocmask(SIG_UNBLOCK, &mask, &prev_mask);
}


//initializes a node
void create_node(Instruction inst, char *cmd, Node *inst_node){

    inst_node->instruction = inst;
    inst_node->cmd = cmd;
}


//creates a deep copy of a node
void copy_node(Node *source, Node *dest){

    dest->instruction = source->instruction;
    dest->status = source->status;
    dest->exit_code = source->exit_code;
    dest->pid = source->pid;
    dest->cmd = calloc(1, strlen(source->cmd) + 1);
    strncpy(dest->cmd, source->cmd, strlen(source->cmd));
    dest->process_type = source->process_type;
    dest->tasknum = source->tasknum;
    dest->total_nodes = -1;
    dest->next = NULL;
}


//adds node to history list
void add_to_history(Node *inst_node, Node *history_head){

    //find node such that node->next is NULL
    Node *task = history_head;
    while(task->next != NULL){
        task = task->next;
    }

    //add new node to list and update list size counter
    task->next = inst_node;
    inst_node->next = NULL;
    history_head->total_nodes++;
}


//adds node to task list
void add_to_tasklist(Node *inst_node, Node *tasklist_head){

    //find node such that node->next is NULL or node->next->tasknum is greater than current
    Node *task = tasklist_head;
    while(1){
        //if end of list is reached, add to end
        if(task->next == NULL){
            task->next = inst_node;
            inst_node->next = NULL;
            break;
        }
        //if next node has greater tasknum than current, insert before it
        if(task->next->tasknum > inst_node->tasknum){
            inst_node->next = task->next;
            task->next = inst_node;
            break;
        }

        task = task->next;
    }

    //update list size counter
    tasklist_head->total_nodes++;
}


//determines the correct tasknum to be assigned
void assign_tasknum(Node *inst_node, Node *tasklist_head){

    int tasknum = 0;
    Node *task = tasklist_head;

    while(task != NULL){
        //check if end of list is reached
        if(!task->next){
            tasknum++;
            break;
        }
        //check if tasknum of next node is not in incrementing order
        if(task->next->tasknum != (tasknum + 1)){
            tasknum = task->tasknum + 1;
            break;
        }
        task = task->next;
        tasknum++;
    }

    inst_node->tasknum = tasknum;
}


//searches for task by tasknum
Node * find_task_by_tasknum(int tasknum, Node *tasklist_head){

    //search for tasknum
    Node *task = tasklist_head->next;
    while(task != NULL){
        if(task->tasknum == tasknum){
            return task;
        }
        task = task->next;
    }

    //return null if task not found
    return NULL;
}


//searches for task by pid
Node * find_task_by_pid(pid_t pid, Node *tasklist_head){

    //search for pid
    Node *task = tasklist_head->next;
    while(task != NULL){
        if(task->pid == pid){
            return task;
        }
        task = task->next;
    }

    //return null if task not found
    return NULL;
}


//removes a task node from tasklist
void remove_task(int tasknum, Node *tasklist_head){

    Node *prev = tasklist_head;
    while(prev->tasknum != (tasknum - 1)){
        prev = prev->next;
    }
    prev->next = prev->next->next;
    tasklist_head->total_nodes--;
}


//get filenames for redirection from argv
void parse_iofiles(char **argv, Node *task){

    int i = 0;
    int in_found = 0, out_found = 0;
    while(argv[i] != NULL){
        //if inward redirection is detected
        if(!in_found && !strcmp(argv[i], "<")){
            task->instruction.infile = calloc(1, strlen(argv[i + 1]));
            strncpy(task->instruction.infile, argv[i + 1], strlen(argv[i + 1]));
            in_found = 1;
        }
        //if outward redirection is detected
        else if(!out_found && !strcmp(argv[i], ">")){
            task->instruction.outfile = calloc(1, strlen(argv[i + 1]));
            strncpy(task->instruction.outfile, argv[i + 1], strlen(argv[i + 1]));
            out_found = 1;
        }
        //if both were found quit
        if(in_found && out_found) return;
        //otherwise continue search
        else i++;
    }
}


//creates arg vector for a process using task cmdline
void generate_process_args(char **process_args, Node *task){

    //create a new argument vector for the new process using the command line
    char *cmd_copy = calloc(1, strlen(task->cmd) + 1);
    strncpy(cmd_copy, task->cmd, strlen(task->cmd));

    
    //fill arg vector with contents of task cmd
    int i = 0;
    process_args[i] = strtok(cmd_copy, " ");
    while(process_args[i] != NULL){
        i++;
        process_args[i] = strtok(NULL, " ");
    }
}


//closes in and out fds and clears infile and outfile
void file_cleanup(int fd_in, int fd_out, Node *task){

    close(fd_in);
    close(fd_out);
    task->instruction.infile = NULL;
    task->instruction.outfile = NULL;
}


//executes a new process
void exec_child_process(char **argv, Node *task){
            
    //create a new argument vector for the new process using the command line
    char *process_args[MAXARGS];
    generate_process_args(process_args, task);

    //infile/outfile
    parse_iofiles(argv, task);

    //program filepaths
    char short_path[100] = "./";
    char long_path[100] = "/usr/bin/";
    strncat(short_path, process_args[0], strlen(process_args[0]));
    strncat(long_path, process_args[0], strlen(process_args[0]));

    //redirection
    int fd_in = 0, fd_out = 0;
    if(task->instruction.infile){
        log_redir(task->tasknum, LOG_REDIR_IN, task->instruction.infile);
        fd_in = open(task->instruction.infile, O_RDONLY);
        if(fd_in == -1){
            log_file_error(task->tasknum, task->instruction.infile);
            file_cleanup(fd_in, fd_out, task);
            exit(1);
        } 
        else dup2(fd_in, STDIN_FILENO);
    }
    if(task->instruction.outfile){
        log_redir(task->tasknum, LOG_REDIR_OUT, task->instruction.outfile);
        fd_out = open(task->instruction.outfile, O_WRONLY | O_CREAT, S_IRWXU);
        if(fd_out == -1){
            log_file_error(task->tasknum, task->instruction.outfile);
            file_cleanup(fd_in, fd_out, task);
            exit(1);
        } 
        else dup2(fd_out, STDOUT_FILENO);
    }

    //unblock signal
    unblock_sigchld();

    //child calls exec
    process_args[0] = short_path;
    if(execv(short_path, process_args) == -1){
        process_args[0] = long_path;
            if(execv(long_path, process_args) == -1){
                //if exec fails call log_exec_error and terminate
                log_exec_error(task->cmd);
                file_cleanup(fd_in, fd_out, task);
                exit(1);
            }
    }
    //if exec succeeds - file cleanup
    file_cleanup(fd_in, fd_out, task);
}


//decides which instruction to execute based on Instruction struct
void choose_instruction(int history, Node *inst_node, char **argv, Node *history_head, Node *tasklist_head){

    //history value determines if node should be added to history list

    //ensure that handlers are set and sigchld is unblocked before anything is executed
    unblock_sigchld();
    set_handlers();

    char *instr = inst_node->instruction.instruct;

    //help
    if(!strcmp(instr, "help")){
        inst_help();
        //add to history
        if(history) add_to_history(inst_node, history_head);
        return;
    }
    //quit
    else if(!strcmp(instr, "quit")){
        inst_quit();
        return;
    }
    //history
    else if(!strcmp(instr, "history")){
        inst_history(argv, history_head, tasklist_head);
        return;
    }
    //list
    else if(!strcmp(instr, "list")){
        inst_list(tasklist_head);
        //add to history
        if(history) add_to_history(inst_node, history_head);
        return;
    }
    //delete
    else if(!strcmp(instr, "delete")){
        inst_delete(argv, tasklist_head);
        //add to history
        if(history) add_to_history(inst_node, history_head);
        return;
    }
    //exec
    else if(!strcmp(instr, "exec")){
        inst_exec(argv, tasklist_head);
        //add to history
        if(history) add_to_history(inst_node, history_head);
        return;
    }
    //bg
    else if(!strcmp(instr, "bg")){
        inst_bg(argv, tasklist_head);
        //add to history
        if(history) add_to_history(inst_node, history_head);
        return;
    }
    //kill
    else if(!strcmp(instr, "kill")){
        inst_kill(argv, tasklist_head);
        //add to history
        if(history) add_to_history(inst_node, history_head);
        return;
    }
    //suspend
    else if(!strcmp(instr, "suspend")){
        inst_suspend(argv, tasklist_head);
        //add to history
        if(history) add_to_history(inst_node, history_head);
        return;
    }
    //resume
    else if(!strcmp(instr, "resume")){
        inst_resume(argv, tasklist_head);
        //add to history
        if(history) add_to_history(inst_node, history_head);
        return;
    }
    //pipe
    else if(!strcmp(instr, "pipe")){
        inst_pipe(argv, tasklist_head);
        //add to history
        if(history) add_to_history(inst_node, history_head);
        return;
    }
    //any other command
    else{
        //determine tasknum
        assign_tasknum(inst_node, tasklist_head);
        inst_command(inst_node);
        //add to history
        if(history) add_to_history(inst_node, history_head);
        //create separate node to add to task list
        Node *inst_node_copy = calloc(1, sizeof(Node));
        copy_node(inst_node, inst_node_copy);
        add_to_tasklist(inst_node_copy, tasklist_head);
        return;
    }
}


//help instruction
void inst_help(){

    log_help();
}


//quit instruction
void inst_quit(){

    log_quit();
    exit(0);
}


//history instruction
void inst_history(char **argv, Node *history_head, Node *tasklist_head){

    int index = 0;
    Node *task = history_head->next;

    //if no number is supplied
    if(argv[1] == NULL){
        log_history_info(history_head->total_nodes);
        //print all commands in history list
        while(task != NULL){
            log_history_commands(index, task->cmd);
            task = task->next;
            index++;
        }
    }
    //if number is supplied
    else{
        int index_to_find = 0;
        sscanf(argv[1], "%d", &index_to_find);
        //search for node in history list
        while(task != NULL){
            if(index == index_to_find){
                log_history_exec(task->cmd);

                //create a new argument vector using the command line of the found task
                char *cmd_copy = calloc(1, strlen(task->cmd) + 1);
                strncpy(cmd_copy, task->cmd, strlen(task->cmd));

                //fill arg vector with contents of task cmd
                int i = 0;
                char *process_args[MAXARGS + 1];
                process_args[i] = strtok(cmd_copy, " ");
                while(process_args[i] != NULL){
                    i++;
                    process_args[i] = strtok(NULL, " ");
                }

                //re execute
                choose_instruction(0, task, process_args, history_head, tasklist_head);
                return;
            }
            task = task->next;
            index++;
        }
        //if not found print error
        log_history_error(index_to_find);
    }
    
}


//list instruction
void inst_list(Node *tasklist_head){

    log_num_tasks(tasklist_head->total_nodes);

    Node *task = tasklist_head->next;
    while(task != NULL){
        log_task_info(task->tasknum, task->status, task->exit_code, task->pid, task->cmd);
        task = task->next;
    }

}


//exec instruction
void inst_exec(char **argv, Node *tasklist_head){

    //find task with given tasknum
    int tasknum = -1; 
    sscanf(argv[1], "%d", &tasknum);
    Node *task = find_task_by_tasknum(tasknum, tasklist_head);
    current_task = task;

    //if task was not found
    if(!task){
        log_task_num_error(tasknum);
        return;
    }

    //if task is busy do not exec
    if(task->status == LOG_STATE_RUNNING || task->status == LOG_STATE_SUSPENDED){
        log_status_error(tasknum, task->status);
        return;
    }

    task->process_type = LOG_FG;

    //block sigchld
    block_sigchld();

    //fork - parent
    if((task->pid = fork())){
        log_status_change(task->tasknum, task->pid, task->process_type, task->cmd, LOG_START);
        task->status = LOG_STATE_RUNNING;

        unblock_sigchld();

        int status = 0;
        if(waitpid(task->pid, &status, WUNTRACED) > 0){
            task->status = LOG_STATE_FINISHED;
            task->exit_code = WEXITSTATUS(status);
            log_status_change(task->tasknum, task->pid, task->process_type, task->cmd, LOG_TERM);
        }

    }
    //child
    else{
        //set group pid
        setpgid(0, 0);
        //reset handlers to default
        reset_handlers();
        //exec
        exec_child_process(argv, task);
    }
}


//bg instruction
void inst_bg(char **argv, Node *tasklist_head){

    //find task with given tasknum
    int tasknum = -1; 
    sscanf(argv[1], "%d", &tasknum);
    Node *task = find_task_by_tasknum(tasknum, tasklist_head);
    current_task = task;

    //if task was not found
    if(!task){
        log_task_num_error(tasknum);
        return;
    }

    //if task is busy do not exec
    if(task->status == LOG_STATE_RUNNING || task->status == LOG_STATE_SUSPENDED){
        log_status_error(tasknum, task->status);
        return;
    }
    
    task->process_type = LOG_BG;

    //block sigchld
    block_sigchld();

    //fork - parent
    if((task->pid = fork())){
        //parent calls log_status_change
        log_status_change(task->tasknum, task->pid, task->process_type, task->cmd, LOG_START);
        task->status = LOG_STATE_RUNNING;
        unblock_sigchld();
    }
    //child
    else{
        //set group pid
        setpgid(0, 0);
        //reset handlers to default
        reset_handlers();
        //exec
        exec_child_process(argv, task);
    }
}


//pipe instruction
void inst_pipe(char **argv, Node *tasklist_head){

    int tasknum1 = 0;
    int tasknum2 = 0;
    sscanf(argv[1], "%d", &tasknum1);
    sscanf(argv[2], "%d", &tasknum2);

    //if tasknums are equal abort
    if(tasknum1 == tasknum2){
        log_pipe_error(tasknum1);
        return;
    }

    //if pipe creation fails abort
    int pipe_fds[2] = {0};
    if(pipe(pipe_fds) == -1){
        log_file_error(tasknum1, LOG_FILE_PIPE);
        return;
    }

    //if pipe succeeds
    log_pipe(tasknum1, tasknum2);
    int fd_in = pipe_fds[1];
    int fd_out = pipe_fds[0];

    //find both tasks
    Node *task1 = find_task_by_tasknum(tasknum1, tasklist_head);
    Node *task2 = find_task_by_tasknum(tasknum2, tasklist_head);

    //if either task was not found abort
    if(!task1){
        log_task_num_error(tasknum1);
        return;
    }
    if(!task2){
        log_task_num_error(tasknum2);
        return;
    }

    //fork two children
    //first child task1 - background
    if((task1->pid = fork()) == 0){
        //piping
        close(fd_out);
        dup2(fd_in, STDOUT_FILENO);

        //set group pid
        setpgid(0, 0);
        //reset handlers
        reset_handlers();
        
        //create arg vector for child process
        char *process_args[MAXARGS];
        generate_process_args(process_args, task1);

        //program filepaths
        char short_path[100] = "./";
        char long_path[100] = "/usr/bin/";
        strncat(short_path, process_args[0], strlen(process_args[0]));
        strncat(long_path, process_args[0], strlen(process_args[0]));

        //unblock signal
        unblock_sigchld();
        //child calls exec
        process_args[0] = short_path;
        if(execv(short_path, process_args) == -1){
            process_args[0] = long_path;
            if(execv(long_path, process_args) == -1){
                //if exec fails call log_exec_error and terminate
                log_exec_error(task1->cmd);
                exit(1);
            }
        }
    }
    else{
        //second child task2 - foreground
        if((task2->pid = fork()) == 0){
            //piping
            close(fd_in);
            dup2(fd_out, STDIN_FILENO);

            //set group pid
            setpgid(0, 0);
            //reset handlers
            reset_handlers();

            //create a new argument vector for the new process using the command line
            char *process_args[MAXARGS];
            generate_process_args(process_args, task2);

            //program filepaths
            char short_path[100] = "./";
            char long_path[100] = "/usr/bin/";
            strncat(short_path, process_args[0], strlen(process_args[0]));
            strncat(long_path, process_args[0], strlen(process_args[0]));

            //unblock signal
            //unblock_sigchld();
            
            //wait for background process to finish
            //wait(NULL);

            //child calls exec
            process_args[0] = short_path;
            if(execv(short_path, process_args) == -1){
                process_args[0] = long_path;
                if(execv(long_path, process_args) == -1){
                    //if exec fails call log_exec_error and terminate
                    log_exec_error(task2->cmd);
                    exit(1);
                }
            }
        }
        //parent
        else{
            //unblock sigchld
            unblock_sigchld();
            //task 1 - background
            task1->status = LOG_STATE_RUNNING;
            task1->process_type = LOG_BG;
            log_status_change(task1->tasknum, task1->pid, task1->process_type, task1->cmd, LOG_START);
            
            //task2 - foreground
            task2->status = LOG_STATE_RUNNING;
            task2->process_type = LOG_FG;
            log_status_change(task2->tasknum, task2->pid, task2->process_type, task2->cmd, LOG_START);
            
            int status = 0;
            waitpid(task2->pid, &status, 0);
            if(WIFEXITED(status)){
                task2->status = LOG_STATE_FINISHED;
                task2->exit_code = WEXITSTATUS(status);
            }
            log_status_change(task2->tasknum, task2->pid, task2->process_type, task2->cmd, LOG_TERM);
            
        }
    }
}


//delete instruction
void inst_delete(char **argv, Node *tasklist_head){

    int tasknum = -1; 
    sscanf(argv[1], "%d", &tasknum);
    Node *task = find_task_by_tasknum(tasknum, tasklist_head);

    //if task was not found
    if(!task){
        log_task_num_error(tasknum);
        return;
    }
    
    //if task is busy do not remove
    if(task->status == LOG_STATE_RUNNING || task->status == LOG_STATE_SUSPENDED){
        log_status_error(tasknum, task->status);
        return;
    }
    
    //remove node from list
    remove_task(tasknum, tasklist_head);
    log_purge(tasknum);
}


//kill instruction
void inst_kill(char **argv, Node *tasklist_head){

    int tasknum = -1; 
    sscanf(argv[1], "%d", &tasknum);
    Node *task = find_task_by_tasknum(tasknum, tasklist_head);
    current_task = task;

    //if task was not found
    if(!task){
        log_task_num_error(tasknum);
        return;
    }

    //if task is idle do not signal
    if(task->status == LOG_STATE_READY || task->status == LOG_STATE_FINISHED || task->status == LOG_STATE_KILLED){
        log_status_error(tasknum, task->status);
        return;
    }
    
    //send SIGINT to task
    kill(task->pid, SIGINT);
    log_sig_sent(LOG_CMD_KILL, task->tasknum, task->pid);
}


//suspend instruction
void inst_suspend(char **argv, Node *tasklist_head){

    int tasknum = -1; 
    sscanf(argv[1], "%d", &tasknum);
    Node *task = find_task_by_tasknum(tasknum, tasklist_head);
    current_task = task;

    //if task was not found
    if(!task){
        log_task_num_error(tasknum);
        return;
    }

    //if task is idle do not signal
    if(task->status == LOG_STATE_READY || task->status == LOG_STATE_FINISHED || task->status == LOG_STATE_KILLED){
        log_status_error(tasknum, task->status);
        return;
    }
    
    //send SIGTSTP to task
    kill(task->pid, SIGTSTP);
    log_sig_sent(LOG_CMD_SUSPEND, task->tasknum, task->pid);
}


//resume instruction
void inst_resume(char **argv, Node *tasklist_head){

    int tasknum = -1; 
    sscanf(argv[1], "%d", &tasknum);
    Node *task = find_task_by_tasknum(tasknum, tasklist_head);
    current_task = task;

    //if task was not found
    if(!task){
        log_task_num_error(tasknum);
        return;
    }

    //if task is idle do not signal
    if(task->status == LOG_STATE_READY || task->status == LOG_STATE_FINISHED || task->status == LOG_STATE_KILLED){
        log_status_error(tasknum, task->status);
        return;
    }

    //send SIGCONT to task
    kill(task->pid, SIGCONT);
    log_sig_sent(LOG_CMD_RESUME, task->tasknum, task->pid);

    //only move task to foreground if it was suspended
    if(task->status != LOG_STATE_RUNNING){

        block_sigchld();
        task->process_type = LOG_FG;
        
        int status = 0;
        waitpid(task->pid, &status, 0);
        unblock_sigchld();
        
        if(WIFEXITED(status)){
            task->status = LOG_STATE_FINISHED;
            task->exit_code = WEXITSTATUS(status);
        }
        log_status_change(task->tasknum, task->pid, task->process_type, task->cmd, LOG_TERM);
    }
}


//command instruction
void inst_command(Node *inst_node){

    log_task_init(inst_node->tasknum, inst_node->cmd);
}