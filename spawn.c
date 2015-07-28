/*************************************************************************
 *  --------->    File Name: spawn.c
 *  --------->    Author: chengfeiZH
 *  --------->    Mail: chengfeizh@gmail.com
 *  --------->    Time: 2015年07月28日 星期二 10时52分13秒
 ************************************************************************/

#include <stdio.h>
#include <sys/types.h>
#include <unistd.h>
#include <assert.h>
#include <string.h>

typedef struct config
{
    char path[64];
    char name[64];
    char mem[16];
} Config;

/*
 * prog : mini-os启动文件路径
 * name : domain名字
 * mem : domain内存大小
 */
void spawn(const Config conf)
{
    pid_t pid = fork();
    if (pid == 0) {
        printf("child process!\n");
        char confPath[1028];
        strcpy(confPath, conf.path);
        strcat(confPath, "temp.conf");
        printf("path: %s\n", confPath);
        FILE *stream = fopen(confPath, "w");
        assert(stream);
        char content[1024] = {0};
        strcat(content, "kernel = \"mini-os.gz\"\r\n");
        strcat(content, "name = \"");
        strcat(content, conf.name);
        strcat(content, "\"\r\nmemory = ");
        strcat(content, conf.mem);
        strcat(content, "\r\non_crash = \"destroy\"\r\n");
        printf("%s\n", content); 
        assert(fwrite(content, sizeof(content), 1, stream));
        fclose(stream);
        
    } else if (pid < 0) {
        perror("fork");
    } else {
        printf("parent process\n");
    }
}
#define x 3
int main()
{
    Config conf;
    strcpy(conf.path, "/home/zhangchengfei/");
    strcpy(conf.name, "mini-os001");
    strcpy(conf.mem, "32");
    spawn(conf);
    return 0;   
}
