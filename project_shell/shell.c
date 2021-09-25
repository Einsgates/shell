/**
 * shell
 * CS 241 - Fall 2021 Jiayuan Hong
 */
#include "format.h"
#include "shell.h"
#include "vector.h"
#include "sstring.h"
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <dirent.h>
#include <getopt.h>
#include <signal.h>
#include <unistd.h>

#define BUF 1000
#define PATH 100
/***********************    STRUCTURE OF PROCESS    ***********************/
typedef struct process {
    char *command;
    pid_t pid;
} process;

/***************************    FUNCTIONS DEFINE    ***************************/

//Create and Destroy Process
process *create_process(const char *buf, pid_t pid);
void destroy_process(pid_t pid);
void destroy_process_list();
void kill_process_list();

//Catching Ctrl+C and background
void sig_int();
void sig_chld_backgrd();

//external command
int external_command(char *buf);

//Signal Commands
void kill_process(pid_t pid);
void stop_process(pid_t pid);
void cont_process(pid_t pid);

//Process Information
process_info *create_info(char *command, pid_t pid);
void destroy_info(process_info* this);
void ps_info();
void info_pfd(pid_t pid);
/**************************    STATIC VARIABLES    **************************/
static vector *history_list = NULL;
static vector *process_list = NULL;


/******************************    SHELL    ******************************/
int shell(int argc, char *argv[]) {
    signal(SIGINT, sig_int);
    signal(SIGCHLD, sig_chld_backgrd);

    history_list = string_vector_create();
    process_list = shallow_vector_create();
    int opt = 0, num = 1;
    char *ptr_h = NULL, *ptr_f = NULL;
    while ((opt = getopt(argc, argv, "h:f:")) != -1) {
        switch (opt) {
            case 'h':
                ptr_h = optarg;
                num += 2;
                break;
            case 'f':
                ptr_f = optarg;
                num += 2;
                break;
        }
    }
    if (argc != num) {
        print_usage();
        exit(1);
    }
    //load history
    FILE *history = NULL;
    char *path = NULL;
    if (ptr_h) {
        path = get_full_path(ptr_h);
        history = fopen(path, "r");
        if (!history) {
            print_history_file_error();
        } else {
            char *history_files  = NULL;
            size_t size = 0;
            ssize_t readbytes;
            while (true) {
                readbytes = getline(&history_files, &size, history);
                if (readbytes == -1) break;
                if (readbytes > 0 && history_files[readbytes - 1] == '\n') {
                    history_files[readbytes - 1] = '\0';
                    vector_push_back(history_list, history_files);
                }
            }
            free(history_files);
            fclose(history);
        }
    }
    //open file or stdin
    FILE *file;
    if (ptr_f) {
        file = fopen(ptr_f, "r");
        if (!file) {
            print_script_file_error();
            exit(1);
        }
    } else {
        file = stdin;
    }
    //shell loop
    char *buf = NULL;
    size_t size = 0;
    ssize_t readbytes = 0;
    while (true) {
        char *path = get_full_path("./");
        print_prompt(path, getpid());
        free(path);
        //command input
        readbytes = getline(&buf, &size, file);
        if (readbytes == -1) {
            kill_process_list();
            break;
        }
        if (readbytes > 0 && buf[readbytes - 1] == '\n') {
            buf[readbytes - 1] = '\0';
            if (file != stdin) {
                print_command(buf);
            }
        }
        //built-in command: ps & signals
        if (!strcmp(buf, "ps")) {
            ps_info();
        } else if (!strncmp(buf, "pfd", 3)) {
            pid_t p_pid;
            size_t p_num = sscanf(buf + 3, "%d", &p_pid);
            if (p_num != 1) {
                print_invalid_command(buf);
            } else {
                info_pfd(p_pid);
            }
        } else if (!strncmp(buf, "kill", 4)) {
            pid_t k_pid;
            size_t k_num = sscanf(buf + 4, "%d", &k_pid);
            if (k_num != 1) {
                print_invalid_command(buf);
            } else {
                kill_process(k_pid);
            }
        } else if (!strncmp(buf, "stop", 4)) {
            pid_t s_pid;
            size_t s_num = sscanf(buf + 4, "%d", &s_pid);
            if (s_num != 1) {
                print_invalid_command(buf);
            } else {
                stop_process(s_pid);
            }
        } else if (!strncmp(buf, "cont", 4)) {
            pid_t c_pid;
            size_t c_num = sscanf(buf + 4, "%d", &c_pid);
            if (c_num != 1) {
                print_invalid_command(buf);
            } else {
                cont_process(c_pid);
            }
        } else if (!strcmp(buf, "!history")) {
            for (size_t i = 0; i < vector_size(history_list); i++) {
                print_history_line(i, (char*)vector_get(history_list, i));
            }
        } else if (buf[0] == '#') {
            size_t cnt, count;
            count = sscanf(buf + 1, "%zu", &cnt);
            if (!count || cnt > vector_size(history_list) - 1) {
                print_invalid_index();
            } else {
                char *cmd = (char *)vector_get(history_list, cnt);
                print_command(cmd);
                vector_push_back(history_list, cmd);
                external_command(cmd);
            }
        } else if (buf[0] == '!') {
            for (size_t i = vector_size(history_list) - 1; i>= 0; i--) {
                char *cmd = (char *)vector_get(history_list, i);
                if (buf[1] == '\0' || !strncmp(buf + 1, cmd, strlen(buf + 1))) {
                    print_command(cmd);
                    vector_push_back(history_list, cmd);
                    external_command(cmd);
                    break;
                }
                if (i == 0) print_no_history_match();
            }
        } else if (!strcmp(buf, "exit")) {
            kill_process_list();
            break;
        } else {
            vector_push_back(history_list, buf);
            int sign = 0;
            sstring *buf_str = cstr_to_sstring(buf);
            vector *command = sstring_split(buf_str, ' ');
            for (size_t i = 0; i < vector_size(command); i++) {
                char *operator = (char *)vector_get(command, i);
                if (!strcmp(operator, "&&")) {
                    char *token1 = strtok(buf, "&");
                    token1[strlen(token1) - 1] = '\0';
                    char *token2 = strtok(NULL, "");
                    token2 += 2;
                    if (!external_command(token1)) {
                        external_command(token2);
                    }
                    sign = 1;
                } else if (!strcmp(operator, "||")) {
                    char *token1 = strtok(buf, "|");
                    token1[strlen(token1) - 1] = '\0';
                    char *token2 = strtok(NULL, "");
                    token2 += 2;
                    if (external_command(token1)) {
                        external_command(token2);
                    }
                    sign = 1;
                } else if (operator[strlen(operator) - 1] == ';') {
                    char *token1 = strtok(buf, ";");
                    char *token2 = strtok(NULL, "");
                    token2 += 1;
                    external_command(token1);
                    external_command(token2);
                    sign = 1;
                } else if (!strcmp(operator, ">")) {
                    sign = 1;
                    char *token1 = strtok(buf, ">");
                    token1[strlen(token1) - 1] = '\0';
                    char *token2 = strtok(NULL, "");
                    token2 += 1;
                    char *redir_path = get_full_path(token2);
                    FILE *r_file = fopen(redir_path, "w");
                    if (!r_file) {
                        print_redirection_file_error();
                    } else {
                        fflush(stdout);
                        int f1 = fileno(r_file);
                        int f2 = f1;
                        dup2(f1, 1);
                        fclose(r_file);
                        external_command(token1);
                        dup2(1, f2);
                        free(redir_path);
                    }
                } else if (!strcmp(operator, ">>")) {
                    sign = 1;
                    char *token1 = strtok(buf, ">");
                    token1[strlen(token1) - 1] = '\0';
                    char *token2 = strtok(NULL, "");
                    token2 += 1;
                    char *redir_path = get_full_path(token2);
                    FILE *r_file = fopen(redir_path, "a");
                    if (!r_file) {
                        print_redirection_file_error();
                    } else {
                        fflush(stdout);
                        int f1 = fileno(r_file);
                        dup2(f1, 1);
                        fclose(r_file);
                        free(redir_path);
                        external_command(token1);
                    }
                }
            }
            vector_destroy(command);
            sstring_destroy(buf_str);
            if (!sign) {
                external_command(buf);
            }
        }
    }
    free(buf);
    if (ptr_f) fclose(file);
    if (ptr_h) {
        FILE* f = fopen(path, "w");
        VECTOR_FOR_EACH(history_list, line, {
          fprintf(f, "%s\n", (char *)line);
        });
        fclose(f);
        free(path);
    }
    vector_destroy(history_list);
    return 0;
}

/******************************   FUNCTION IMPLEMENTATION   ******************************/
process *create_process(const char* buf, pid_t pid) {
    process *new = malloc(sizeof(process));
    new->command = malloc(sizeof(char) * (strlen(buf) + 1));
    strcpy(new->command, buf);
    new->pid = pid;
    return new;
}

void destroy_process(pid_t pid) {
    for (size_t i = 0; i < vector_size(process_list); i++) {
        process *this = (process *)vector_get(process_list, i);
        if (this->pid == pid) {
            free(this->command);
            free(this);
            vector_erase(process_list, i);
            break;
        }
    }
}

void destroy_process_list() {
    for (size_t i = 0; i < vector_size(process_list); i++) {
        process *this = (process *)vector_get(process_list, i);
        free(this->command);
        free(this);
    }
    vector_destroy(process_list);
}

void kill_process_list() {
    for (size_t i = 0; i < vector_size(process_list); i++) {
        process *killing = (process *)vector_get(process_list, i);
        kill(killing->pid, SIGKILL);
    }
    destroy_process_list();
}

void sig_int() {
    for (size_t i = 0; i < vector_size(process_list); i++) {
        process *this = (process *)vector_get(process_list, i);
        if (this->pid != getpgid(this->pid)) {
            kill(this->pid, SIGKILL);
            destroy_process(this->pid);
        }
    }
}

void sig_chld_backgrd() {
    pid_t pid;
    while ((pid = waitpid(-1, 0, WNOHANG)) > 0) {
        destroy_process(pid);
    }
}

int external_command(char *buf) {
    if (!strncmp(buf, "cd", 2)) {
        int next = chdir(buf + 3);
        if (next < 0) {
            print_no_directory(buf + 3);
            return 1;
        } else {
            return 0;
        }
    } else {
        fflush(stdout);
        pid_t pid = fork();
        if (pid < 0) {
            print_fork_failed();
            exit(1);
        } else if (pid > 0) {
            process *this = create_process(buf, pid);
            vector_push_back(process_list, this);
            if (buf[strlen(buf) - 1] == '&') {
                if (setpgid(pid, pid) == -1) {
                    print_setpgid_failed();
                    exit(1);
                }
            } else {
                if (setpgid(pid, getpid()) == -1) {
                    print_setpgid_failed();
                    exit(1);
                }
                int status;
                pid_t ppid = waitpid(pid, &status, 0);
                if (ppid != -1) {
                    destroy_process(ppid);
                    if (WIFEXITED(status) && WEXITSTATUS(status)) {
                        return 1;
                    }
                } else {
                    print_wait_failed();
                    exit(1);
                }
            }
        }
        else {
            if (buf[strlen(buf) - 1] == '&') {
                buf[strlen(buf) - 1] ='\0';
            }
            vector *command_list = sstring_split(cstr_to_sstring(buf), ' ');
            char *command[vector_size(command_list) + 1];
            for (size_t i = 0; i < vector_size(command_list); i++) {
                command[i] = (char *)vector_get(command_list, i);
            }
            if (!strcmp(command[vector_size(command_list) - 1],"")) {
                command[vector_size(command_list) - 1] = NULL;
            } else {
                command[vector_size(command_list)] = NULL;
            }
            print_command_executed(getpid());
            execvp(command[0], command);
            print_exec_failed(command[0]);
            exit(1);
        }
    }
    return 0;
}

void kill_process(pid_t pid) {
    for (size_t i = 0; i < vector_size(process_list); i++) {
        process *killing = (process*)vector_get(process_list, i);
        if (killing->pid == pid) {
            kill(killing->pid, SIGKILL);
            print_killed_process(killing->pid, killing->command);
            destroy_process(killing->pid);
            return;
        }
    }
    print_no_process_found(pid);
}

void stop_process(pid_t pid) {
    for (size_t i = 0; i < vector_size(process_list); i++) {
        process *stopping = (process*)vector_get(process_list, i);
        if (stopping->pid == pid) {
            kill(stopping->pid, SIGTSTP);
            print_stopped_process(stopping->pid, stopping->command);
            //destroy_process(stopping->pid);
            return;
        }
    }
    print_no_process_found(pid);
}

void cont_process(pid_t pid) {
    for (size_t i = 0; i < vector_size(process_list); i++) {
        process *continuing = (process*)vector_get(process_list, i);
        if (continuing->pid == pid) {
            kill(continuing->pid, SIGCONT);
            return;
        }
    }
    print_no_process_found(pid);
}

process_info *create_info(char *command, pid_t pid) {//order
    process_info *this = malloc(sizeof(process_info));
    this->command = malloc(sizeof(process_info));
    strcpy(this->command, command);
    this->pid = pid;
    char path[PATH], buf[BUF];
    char *ptr;
    snprintf(path, PATH, "/proc/%d/status", pid);
    FILE *file = fopen(path, "r");
    if (!file) {
        print_script_file_error();
        exit(1);
    }
    while (fgets(buf, BUF, file)) {
        if(!strncmp(buf, "State:", 6)) {
        ptr = buf + 7;
        while(isspace(*ptr)) ++ptr;
        this->state = *ptr;
      } else if (!strncmp(buf, "Threads:", 8)) {
        char *ptr_thread;
        ptr = buf + 9;
        while(isspace(*ptr)) ++ptr;
        this->nthreads = strtol(ptr, &ptr_thread, 10);
      } else if (!strncmp(buf, "VmSize:", 7)) {
        char *ptr_vms;
        ptr = buf + 8;
        while(isspace(*ptr)) ++ptr;
        this->vsize = strtol(ptr, &ptr_vms, 10);
      }
  }
    fclose(file);
    snprintf(path, PATH, "/proc/%d/stat", pid);
    FILE *sta_file = fopen(path, "r");
    if (!sta_file) {
        print_script_file_error();
        exit(1);
    }
    fgets(buf, BUF, sta_file);
    fclose(sta_file);
    ptr = strtok(buf, " ");
    int index = 0;
    char *cpu;
    unsigned long utime, stime;
    unsigned long long starttime;
    while (ptr) {
        if (index == 13) {
            utime = strtol(ptr, &cpu, 10);
        } else if (index == 14) {
            stime = strtol(ptr, &cpu, 10);
        } else if (index == 21) {
            starttime = strtol(ptr, &cpu, 10);
        }
        ptr = strtok(NULL, " ");
        index++;
    }
    char buf_cpu[100];
    unsigned long total_secs = (utime + stime) / sysconf(_SC_CLK_TCK);
    if (!execution_time_to_string(buf_cpu, 100, total_secs/60, total_secs%60)) {
        exit(1);
    }
    this->time_str = malloc(sizeof(char) * (strlen(buf_cpu) + 1));
    strcpy(this->time_str, buf_cpu);
    FILE *stat = fopen("/proc/stat", "r");
    if (!stat) {
        print_script_file_error();
        exit(1);
    }
    unsigned long btime;//unsigned long long
    while(fgets(buf, 100, stat)) {
      if(!strncmp(buf, "btime", 5)) {//system_time
        ptr = buf + 6;
        while(isspace(*ptr)) ++ptr;
        btime = strtol(ptr, &cpu, 10);
      }
  }
    fclose(stat);
    char buf_start[100];
    time_t total_secs_start = starttime/sysconf(_SC_CLK_TCK) + btime;
    struct tm *tm_info = localtime(&total_secs_start);
    if (!time_struct_to_string(buf_start, 100, tm_info)) exit(1);
    this->start_str = malloc(sizeof(char)*(strlen(buf_start)+1));
    strcpy(this->start_str, buf_start);
    return this;
}

void destroy_info(process_info* this) {
    free(this->start_str);
    free(this->time_str);
    free(this->command);
    free(this);
}

void ps_info() {
    print_process_info_header();
    for (size_t i = 0; i < vector_size(process_list); i++) {
        process *ps = (process *)vector_get(process_list, i);
        process_info *this = create_info(ps->command, ps->pid);
        print_process_info(this);
        destroy_info(this);
    }
    process_info *p_shell = create_info("./shell", getpid());
    print_process_info(p_shell);
    destroy_info(p_shell);
}

void info_pfd(pid_t pid) {
    pid_t pid_shell = getpid();
    process *this = create_process("./shell", pid_shell);
    vector_push_back(process_list, this);
    for (size_t i = 0; i <vector_size(process_list); i++) {
        if (this->pid == pid) {
        char path[PATH];
        snprintf(path, PATH, "/proc/%d/fdinfo", pid);
        DIR *fdinfo = opendir(path);
        if (!fdinfo) {
            print_script_file_error();
            exit(1);
        }
        print_process_fd_info_header();
        struct dirent *dent;
        while ((dent = readdir(fdinfo))) {
            size_t fdinfo_num, fd_num;
            fdinfo_num = sscanf(dent->d_name, "%zu", &fd_num);
            if (fdinfo_num == 1) {
                snprintf(path, PATH, "/proc/%d/fdinfo/%zu", pid, fd_num);
                FILE *fd = fopen(path, "r");
                if (!fd) {
                    print_script_file_error();
                    exit(1);
                }
                char buf[BUF];
                char *ptr, *cpu;
                size_t pos;
                char* pos_str = "pos:";
                while (fgets(buf, 100, fd)) {
                    if (!strncmp(buf, pos_str, strlen(pos_str))) {
                        ptr = buf + strlen(pos_str);
                        while (isspace(*ptr)) ++ptr;
                        pos = strtol(ptr, &cpu, 10);
                    }
                }
                fclose(fd);
                char final_path[100];
                ssize_t index = 0;
                snprintf(path, PATH, "proc/%d/fd?%zu", pid, fd_num);
                if ((index = readlink(path, final_path, 99)) < 0) exit(1);
                else final_path[index] = 0;
                print_process_fd_info(fd_num, pos, final_path);
            }
        }
        closedir(fdinfo);
        destroy_process(pid_shell);
        return;
        }
    }
    destroy_process(pid_shell);
    print_no_process_found(pid);
}