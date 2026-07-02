//Remember to make sure that your tracer and tracee programs in a different directory.
//In my case, i have my tracee program in the Tracee_prog directory and my tracer program in the Tracer_prog directory.
//Also the tracer program requires sudo/root privileges since it uses ptrace.



#include <stdio.h>
#include <sys/ptrace.h> //The library responsible for manipulating the tracee.
#include <unistd.h> //For getpid, close, read, write etc.
#include <stdlib.h>
#include <sys/wait.h> //For waitpid and sleep
#include <sys/types.h>
#include <sys/user.h> //For user_regs_struct
#include <string.h>

int main(){

    char line[128];
    int status;
    struct user_regs_struct regs; //this is resposible for seeing the rip, rsp, rbp etc.
    pid_t pid; //process id

    FILE* cmd = popen("pgrep bleh", "r"); //pgrep shows the pid of the process, here you have to replace bleh with your tracee's elf name

    if(cmd == NULL) perror("CMD error");

    if(fgets(line, sizeof(line), cmd) != NULL){
        pid = atoi(line); //ascii to integer, very useful here.
        printf("The process id is: %d\n", pid);
    }

    pclose(cmd); //make sure to close the file pointer.

    if(ptrace(PTRACE_ATTACH, (pid_t)pid, NULL, NULL) == -1){ //ptrace_attach makes the tracer program attach to the tracee, here we put NULL in the address field as well as in the register pointer field.
        perror("ptrace");
        exit(EXIT_FAILURE);
    }

    pid_t w = waitpid((pid_t)pid, &status, __WALL); //status is just an integer pointer used to store the exit status and info for a child process, whereas __WALL means to simply wait untill all the child processes complete.

    if (w == -1)
    {
        perror("waitpid");
        exit(EXIT_FAILURE);
    }

    if (WIFSTOPPED(status)) //WIFSTOPPED: wait if stopped. status is passed because it will show whether the program freezed or no.
    {
        int sig = WSTOPSIG(status); //WSTOPSIG: wait stop signal, outputs a signal value after stopping the program.

        printf("Waitpid reported a stop! Signal value: %d\n", sig);
        printf("program stopped succesfully!\n");

        ptrace(PTRACE_GETREGS, pid, NULL, &regs); //ptrace_getregs is used for getting the register pointers of the tracee process, here null is used in the address field and &regs is a blank pointer which will now be containing all the register pointer's info.

        printf("0x%llx\n", regs.rip); //regs.rip for specifically seeing the instruction pointer of the tracee program.

        //Now here we are trying to derail the execution of the tracee program by making it take a detour to the detourFunc().

        char line2[128];

        FILE* cmd2 = popen("cd ..;cd Tracee_prog/; objdump -d bleh | grep targetFunc", "r"); //a cmd command to exactly find out the offset address of the targetFunc.

        if (cmd2 == NULL) perror("CMD error");

        unsigned long offset_addr = 0;

        if (fgets(line2, 17, cmd2) != NULL)
        {
            offset_addr = strtoul(line2, NULL, 16); //conversion to unsigned long.
            printf("%lx\n", offset_addr);
            printf("%p\n", (void *)offset_addr); //void is used to see if 0x is coming before the hex.
        }

        pclose(cmd2); //make sure to close the file pointer.

        char line3[32];
        char command[128];

        snprintf(command, sizeof(command), "cd ..; cd ..; cd ..; cat proc/%d/maps", pid); //integrating an integer into a string so that we can use it on the terminal.

        FILE *cmd3 = popen(command, "r");

        if(cmd3 == NULL) perror("CMD error");

        unsigned long base_addr = 0;

        if (fgets(line3, 13, cmd3) != NULL)
        {
            base_addr = strtoul(line3, NULL, 16); //conversion
            printf("%lx\n", base_addr);
            printf("%p\n", (void *)base_addr);
        }
        pclose(cmd3);

        char loadstr[] = "0xf30f1e00000015e9"; //Flags have been hardcoded since functions remain constant, you change these accordingly to your function's registers.(Can be seen by running: [objdump -d {your exe name}] on your terminal).
        char *endptr; //makes sure that the end of a string is not silced off.
        long data;

        unsigned long addr = (base_addr + offset_addr); //the real address of the function is the base address which gets randomized every time by aslr due to the elf file being compiled as a pie file(position independent executable).
        data = ptrace(PTRACE_PEEKTEXT, pid, (void *)addr, NULL); //ptrace_peektext is used to look at the flags at the mentioned address in the address field, here we are leaving the register pointer field null since we are not mapping/feeding it any data.

        if(data == -1) perror("Ptrace failed!");

        printf("%ld\n%lx\n", data, data);

        data = strtoul(loadstr, &endptr, 16); //converstion, here we used the E9 JMP module thus allowing us to jump from an addres to another by finding the difference between the targetFunc's address and the detourFunc's address and also leaving the last 3 bytes of the data pointer the same as the jmp module requires 5 free bytes.
        //In the end we converted the desired data pointer into litlle endian formal with the most significant byte at the last.
        //Hence we get loadstr as: 0xf30f1e00000015e9, where f30f1e represents the last 3 bytes and 15e9 represent the address difference and jmp respectively.

        printf("%ld\n%lx\n", data, data);

        ptrace(PTRACE_POKETEXT, pid, (void*)addr, (void *)data); //poketext is used to map a data pointer to the provided address thus instructing the tracee to detour and execute the detourFunc.

        getchar(); //This was used just to freeze until needed.
    }
    
    ptrace(PTRACE_CONT, pid, NULL, NULL); //unfreezes the tracee.

    ptrace(PTRACE_DETACH, pid, NULL, NULL); //detaches from the tracee.
    return 0;
}