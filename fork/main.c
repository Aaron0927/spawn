#include <stdio.h>
#include <xenstore.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>
#include <sched.h>
#include <xenstore.h>
#include <mini-os/lib.h>
#include <mini-os/xmalloc.h>
#include <xen/grant_table.h>
#include <mini-os/gntmap.h>

unsigned int domid;
// 获取domID 
unsigned int get_domid(struct xs_handle *xs) 
{
    char *buf;
    unsigned int len, domid;
    buf = xs_read(xs, XBT_NULL, "domid", &len);
    domid = atoi(buf);
    printf("---> domid : %d\n", domid);
    return domid;
}

// 查询xenstore判断自己是父DomU还是子DomU
int read_xenstore(char *key) //check_state() 
{
    struct xs_handle *xs;
    char *path;
    int rcv_data;

    /* Get a connection to the daemon */
    xs = xs_daemon_open();
    if ( xs == NULL ) 
    {
        perror("---> xs_deamon_open:");
    }
    printf("---> xs_deamon_open OK!\n");

    domid = get_domid(xs);
    
    /* Get the local domain path */
    path = xs_get_domain_path(xs, domid);
    if ( path == NULL ) 
    {
        perror("---> get_domain_path:");
    }
    printf("---> get_domain_path OK! path = %s\n", path);
    

    /* Make space for our node on the path */
    path = realloc(path, strlen(path) + strlen("/console/") + strlen(key) + 1);
    if ( path == NULL ) 
    {
        perror("---> realloc_path:");
    }
    strcat(path, "/console/");
    strcat(path, key);

    printf("---> realloc_path OK! path = %s\n", path);

    rcv_data =  xenbus_read_integer(path);
    printf("---> reading OK! data = %d\n\n\n", rcv_data);
    
    free(path);
    xs_daemon_close(xs); 
    return rcv_data;
}

// 将int转成char *
void itoa(char *str, int num) {
    int base = 10000;
    while (num / base == 0) {
        base = base / 10;
    }
    
    int i = 0;
    while (base > 0) {
        str[i++] = '0' + num / base;
        num = num % base;    
        base = base / 10;
    }
    str[i] = '\0'; 
}

// 将配置参数写到xenstore
void write_xenstore(char *key, int value) {
    struct xs_handle *xs;
    char *path;
    char *msg;

    /* Get a connection to the daemon */
    xs = xs_daemon_open();
    if ( xs == NULL ) 
    {
        perror("---> xs_deamon_open:");
    }
    printf("---> xs_deamon_open OK!\n");

    
    /* Get the local domain path */
    path = xs_get_domain_path(xs, domid);
    if ( path == NULL ) 
    {
        perror("---> get_domain_path:");
    }
    printf("---> get_domain_path OK! path = %s\n", path);
    

    /* Make space for our node on the path */
    path = realloc(path, strlen(path) + strlen("/console/") + strlen(key) + 1);
    if ( path == NULL ) 
    {
        perror("---> realloc_path:");
    }
    strcat(path, "/console/");
    strcat(path, key);

    printf("---> realloc_path OK! path = %s\n", path);
    char str_value[10];
    itoa(str_value, value);

    msg = xenbus_write(0, path, str_value);
    if (msg) {
        printf("-------------------->%s\n", msg);
        free(msg);
    } else {
        printf("---> writing OK! data = %s\n\n\n", str_value);
    }

    free(path);
    xs_daemon_close(xs); 
}

void dofork(int function) {
    write_xenstore("child_do_function", function);
}


void fun1() {
    printf("child do function 1\n");
}

void fun2() {
    printf("child do function 2\n");
}

void fun3() {
    printf("child do function 3\n");
}

int main()
{
    sleep(1);
    int is_parent = read_xenstore("is_parent");
    char  shared_page[1024];
    void *receive_page;
    unsigned long offset;
    unsigned long offset_end;
    if (is_parent == 1) {
        goto parent;
    } else {
        goto child;
    }

parent:
    strcpy(shared_page, "zhangchengfei");
    printf("---> I am parent DomU!\n");
    printf("machine address : %p\n", virt_to_mfn(shared_page));
    printf("virtual address : %p\n", (shared_page));
    offset = ((unsigned long)shared_page & 0x0000000000000fff);
    printf("%lu\n", offset);
    offset_end = offset + strlen("zhangchengfei");

    // 开始授权
    grant_ref_t grant = gnttab_grant_access(domid + 1, virt_to_mfn(shared_page), 0);

    // 更新xenstore配置
    write_xenstore("offset", offset);
    write_xenstore("offset_end", offset_end);
    write_xenstore("done_fork", 1);  // 1表示已经做了fork
    write_xenstore("refs", grant);
    write_xenstore("pdomid", domid);

    dofork(1);

    int i = 0;
    while (1) {
        sleep(1);
        i++;
        if (i < 2) {
        printf("shared page on %d\n", grant);
        }
    }
    gnttab_end_access(grant);
    return 0;
child:
    printf("---> I am child DomU!\n");
    struct gntmap *map = (struct gntmap *)malloc(sizeof(struct gntmap));
    offset = read_xenstore("offset");
    offset_end = read_xenstore("offset_end");
    sleep(1);
    uint32_t refs =  read_xenstore("refs");
    uint32_t pdomid =  read_xenstore("pdomid");
    uint32_t child_do_function=  read_xenstore("child_do_function");
    printf("-------------------------------> %d\n", pdomid);
    gntmap_init(map);
    char buf[4096];
    receive_page = gntmap_map_grant_refs(map, 1, &pdomid, 0, &refs, 0);
        
    memcpy(buf, receive_page , sizeof(char) * 4096);
        
    printf("---->  %p\n", virt_to_mfn(receive_page));

    printf("rcv_data: ");
    for (int i = offset; i < offset_end; i++) {
        printf("%c", buf[i]);
    }
    printf("\n");
    switch (child_do_function) {
        case 1: fun1(); break;
        case 2: fun2(); break;
        case 3: fun3(); break;
    }
    gntmap_fini(map);
    return 0;
}
