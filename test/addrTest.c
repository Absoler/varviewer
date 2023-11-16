#include <stdlib.h>
int g1, g2;

struct S{
    short f1;
    int f2;
}s1;

struct Big{
    int f3;
    struct S fs1;
    struct S *ps2;
};

int a, b;
int arr[100];

int inner(struct S *sin, int *p){
    *p = g2 + 1;
    if(sin->f1){
        g1 = 1;
        g2 = 2;
    }else{
        g1 = 3;
        g2 = 4;
    }
    int res = *p + sin->f2;
    return res + g2;
}

void outer(struct S *s, int *p){
    s->f1 = 1;
    int sum = g1 + inner(s, p);
    if(sum<100){
        arr[sum] += 1;
    }
    g2 = sum;
}

struct Big *big ;

int main(){
    struct S* s2 = (struct S*)malloc(sizeof(struct S));
    outer(&s1, &a);
    const int const_1 = 1;
    s2->f2 = 2;
    outer(s2, &b);

    struct T{
        int f1;
        short f2;
        int f3;
    };
    struct T t = (struct T){const_1,1,1};
    t.f1 = g1;
    g2 = t.f1 + s1.f2;

    big = (struct Big*)malloc(sizeof(struct Big));
    big->ps2 = (struct S*)malloc(sizeof(struct S));
    big->fs1 = (struct S){1, 1};
    big->ps2->f1 = 0;
    g1 = big->fs1.f1 + g1 + big->ps2->f1;
}