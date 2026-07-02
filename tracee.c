#include <stdio.h>
#include <unistd.h> //used for sleep

void targetFunc(){
    printf("Hello From The Original Function\n");
    return;
}

void detourFunc(){
    printf("[ALERT]: PATCHER SUCCESSFUL!, EXECUTION HIJACKED!\n");
    return;
}

int main()
{
    while(1){
        targetFunc();
        sleep(3); //3 is in seconds, you can change this accordingly to your needs.
    }
    return 0;
}