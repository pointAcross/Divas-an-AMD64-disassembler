#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
int main(int argv, char **argc){
    FILE *fp;
    uint8_t *buffer;
    size_t size; 
    int i,count;
    if(fp = fopen(argc[1],"rb")){\
        fseek(fp,0,SEEK_END);
        size = ftell(fp);
        fseek(fp,0,SEEK_SET);
        printf("%d bytes\n",size);
        buffer = malloc(size);
        fread(buffer,1,size,fp);
        for(i = 0; i<size;i+=2){
            printf("%02x%02x ",buffer[i+1],buffer[i]);
            count++;
            if(count%8 == 0){
                printf("\n");
            }
        }
    }
    else{
        printf("Error\n");
    }

}

