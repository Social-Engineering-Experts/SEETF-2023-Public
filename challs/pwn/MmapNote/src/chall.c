//gcc ./chall.c -o chall -lseccomp -no-pie -s 
#define _GNU_SOURCE 1

#include <sys/mman.h>
#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <assert.h>
#include <unistd.h>
#include <stdio.h>
#include <seccomp.h>
#include <stdio.h>
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
// use seccomp to allow only read, open, mmap, exit syscall

void filter(){
    scmp_filter_ctx ctx;
    ctx = seccomp_init(SCMP_ACT_KILL);

    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(open), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(openat), 0) == 0);    
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(write), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(mmap), 0) == 0);
    assert(seccomp_rule_add(ctx, SCMP_ACT_ALLOW, SCMP_SYS(exit_group), 0) == 0);
    assert(seccomp_load(ctx) == 0);
}

void * note[100];
int size[100];
int count = 0;

int gadget(){
    //add asm code 
    __asm__(
        // pop rdi, ret
        "pop %rdi\n\t"
        "ret\n\t"
        "pop %rax\n\t"
        "ret\n\t"
        "pop %rsi\n\t"
        "ret\n\t"
        "pop %rdx\n\t"
        "ret\n\t"
        "pop %r10\n\t"
        "ret\n\t"
        "pop %r8\n\t"
        "ret\n\t"
        "pop %r9\n\t"
        "ret\n\t"
        "pop %rsp\n\t"
        "ret\n\t"
        "pop %rbp\n\t"
        "ret\n\t"
        "pop %rbx\n\t"
        "ret\n\t"
        "pop %rcx\n\t"
        "ret\n\t"
        "syscall\n\t"
        "ret\n\t"
    );
    return 1;
}


int init(){
    // required for ctf challenge
    setbuf(stdout, 0);
    setbuf(stdin, 0);
    setbuf(stderr,0);
    return 1;
}

int createNote(){
    if(count < 100){
        void * addr = 0;
        addr = mmap(NULL, 0x1000, PROT_WRITE|PROT_READ, MAP_PRIVATE|MAP_ANON, 0, 0);
        note[count] = addr;
        printf("Note created id %d\n",count);
        printf("Addr of note %d is 0x%llx\n", count, (unsigned long long)addr);
        ++count;
        return 1;
    }else{
        printf("Note full, cant create anymore!!!!!!!\n");
        return 0;
    }
    
}

int writeNote(){
    unsigned int idx = 0;
    printf("idx = ");
    scanf("%d", &idx);
    if(idx >= count){
        puts("invalid idx");
        return 0;
    }
    printf("size to write = ");
    scanf("%d", &size[idx]);
    if(size[idx] > 0x1000){
        puts("too much");
        return 0;
    }
    read(0, note[idx], size[idx]);
    return 1;
}

int readNote(){
    unsigned int idx = 0;
    printf("idx = ");
    scanf("%d", &idx);
    if(idx >= count){
        puts("invalid idx");
        return 0;
    }
    write(1, note[idx], size[idx]);
    return 1;
}

void menu(){
    puts("1. create note");
    puts("2. write");
    puts("3. read");
    puts("4. exit");
    printf("> ");
    return;
}

int check = 1;

int main(){
    init();
    puts("Welcome to the SEETF note sandbox!");
    puts("======================================");
    puts("======================================");
    char buf[16];
    while (check)
    {
        menu();
        read(0, buf, 1600);
        switch (atol(buf))
        {
        case 1: 
            createNote();
            break;
        case 2:
            writeNote();
            break;
        case 3:
            readNote();
            break;
        case 4:
            check = 0;
            break;
        }
    }
    filter();
    puts("Bye!");
}