/*************************************************************************
 *  --------->    File Name: spawn.c
 *  --------->    Author: chengfeiZH
 *  --------->    Mail: chengfeizh@gmail.com
 *  --------->    Time: 2015年07月28日 星期二 10时52分13秒
 ************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>

void spawn()
{
    pid_t pid = fork();
    if (pid == 0) {
        printf("child process!\n");
        execl("/bin/ls", "ls", "-al", "/home/zhangchengfei/Desktop/", (char *)0);
    } else if (pid < 0) {
        perror("fork");
    } else {
        printf("parent process\n");
    }
}


int main()
{
    spawn();
    spawn();
    return 0;   
}
