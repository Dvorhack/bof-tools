#include <stdlib.h>
#include <stdio.h>

void vuln(){
    char buffer[10];
    gets(buffer);
}

int main(){
    vuln();
}