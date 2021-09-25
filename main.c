#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#define LSH_TOK_BUFSIZE 64
#define LSH_TOK_DELIM " \t\r\n\a"
/**
 * loop in the shell and interpreting commands, contains 3 steps:
 * read command: lsh_read_line()
 * split line: lsh_spilt_line()
 * execute commands: lsh_execute_line()
 */
void lsh_loop();

/**
 * read line using getline until EOF
 */
char *lsh_read_line();

/**
 * parse line into a list of arguments, using whitespace as delimeters
 */
char **lsh_split_line(char *line);

/**
 * This will either launch a builtin, process
 */
int lsh_execute(char **args);

/**
 * This start a process using fork-exec-wait pattern
 */
int lsh_launch(char **args);

/**
 * This function will go to the input directory
 */
int lsh_cd(char **args);

/**
 * This will give user help and hints, usage of ant function
 */
int lsh_help(char **args);

/**
 * When successfully exited
 */
int lsh_exit(char **args);


/**
 * builtin commands: cd help exit
 */
char *builtin_str[] = {"cd", "help", "exit"};

/**
 * obtain the number of builtin functions
 */
int lsh_num_builtins();
/**
 * builtin commands to functions:
 * lsh_cd
 * lsh_help
 * lsh_exit
 */
int (*builtin_func[]) (char**) = {&lsh_cd, &lsh_help, &lsh_exit};

int main(int argc, char **argv) {
    lsh_loop();
    return EXIT_SUCCESS;
}

void lsh_loop() {
    char *line;
    char **args;
    int status;

    do {
        printf("$ ");
        line = lsh_read_line();
        args = lsh_split_line(line);
        status = lsh_execute(args);
        free(line);
        free(args);
    } while (status);
}

char* lsh_read_line() {
    char *line = NULL;
    ssize_t bufsize = 0;

    if (getline(&line, &bufsize, stdin) == -1) {
        if (feof(stdin)) {
            exit(EXIT_SUCCESS);
        } else {
            perror("readline");
            exit(EXIT_FAILURE);
        }
    }
    return line;
}

char **lsh_split_line(char *line) {
    int bufsize = LSH_TOK_BUFSIZE;
    int position = 0;
    char **tokens = malloc(sizeof(char*) * bufsize);
    char *token;

    if (!tokens) {
        fprintf(stderr, "lsh: allocation error\n");
        exit(EXIT_FAILURE);
    }

    token = strtok(line, LSH_TOK_DELIM);
    while (token != NULL) {
        tokens[position] = token;
        position++;

        if (position >= bufsize) {
            bufsize += LSH_TOK_BUFSIZE;
            tokens = realloc(tokens, bufsize * sizeof(char*));
            if (!tokens) {
                fprintf(stderr, "lsh: allocation error\n");
                exit(EXIT_FAILURE);
            }
        }
        token = strtok(NULL, LSH_TOK_DELIM);
    }
    tokens[position] = NULL;
    return tokens;
}

int lsh_execute(char **args) {
    if (args[0] == NULL) return 1;
    for (size_t i = 0; i < lsh_num_builtins(); i++) {
        if (!strcmp(args[0], builtin_str[i])) {
            return (*builtin_func[i])(args);
        }
    }
    return lsh_launch(args);
}

int lsh_num_builtins() {
    return sizeof(builtin_str) / sizeof(builtin_str[0]);
}

int lsh_launch(char **args) {
    pid_t pid, wpid;
    int status;
    pid = fork();
    if (pid < 0) {
        perror("lsh");
    } else if (pid == 0) {
        if (execvp(args[0], args) == -1) {
            perror("lsh");
        }
    } else {
        do {
            //Parent Process
            wpid = waitpid(pid, &status, WUNTRACED);
        } while (!WIFEXITED(status) && !WIFSIGNALED(status));
    }
    return 1;
}

int lsh_cd(char **args) {
    if (args[1] == NULL) {
        fprintf(stderr, "lsh: expected argument to \"cd\"\n");
    } else {
        if (chdir(args[1]) != 0) {
            perror("lsh");
        }
    }
    return 1;
}

int lsh_help(char **args) {
    for (size_t i = 0; i < lsh_num_builtins(); i++) {
        printf("   %s\n", builtin_str[i]);
    }
    printf("Use Linux Man Page!\n");
    return 1;
}

int lsh_exit(char **args) {
    return 0;
}
