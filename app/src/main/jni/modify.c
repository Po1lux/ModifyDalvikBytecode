//
// Created by seanchen on 2019-12-03.
//
#include <unistd.h> //getpid
#include <stdio.h>  //sprintf
#include <android/log.h>
#include <string.h> //strstr
#include <stdlib.h> //strtoul
#include "cn_pollux_modifydalvikbytecode_MainActivity.h"

#define TAG "cs"
#define LOGD(...) __android_log_print(ANDROID_LOG_DEBUG,TAG,__VA_ARGS__)

int findMagic(void* searchStartPage){
    char magic[10];
//    memcpy(magic,"dex\n035",8);
    memcpy(magic,"oat\n",5);
    if(memcmp(searchStartPage,magic,5)){
        return 0;
    }else{
        return 1;
    }
}

JNIEXPORT jint JNICALL Java_cn_pollux_modifydalvikbytecode_MainActivity_modifyBytecode
        (JNIEnv *env, jclass clazz) {
    /**
     * 寻找dex的地址
     */
    int pid = getpid();
    void *start;
    void *end;
    char fileName[32];
    sprintf(fileName, "/proc/%d/maps", pid);
    LOGD("%s", fileName);
    FILE *fp = fopen(fileName, "r");
    if (fp != NULL) {
        char line[1024];
        while (fgets(line, sizeof(line), fp) != NULL) {
            //data/dalvik-cache/arm/data@app@cn.pollux.modifydalvikbytecode-2@base.apk@classes.dex
            //data/dalvik-cache/data@app@cn.pollux.modifydalvikbytecode-2.apk@classes.dex
            if (strstr(line, "@cn.pollux.modifydalvikbytecode") !=
                NULL) {
                if (strstr(line, "classes.dex") != NULL) {
                    LOGD("line:%s",line);
                    char *s = strchr(line, '-');
                    s += 1;//跳过'-'，不然被strtoul当做负号
                    start = (void *)strtoul(line, NULL, 16);
                    end = (void *)strtoul(s, NULL, 16);
                    LOGD("dex start address:%x",(unsigned int)start);
                    LOGD("dex end address:%x", (unsigned int)end);
                    break;
                }
            }
        }
        fclose(fp);
    } else {
        LOGD("open %s failed", fileName);
    }

    long pageSize = sysconf(_SC_PAGE_SIZE);    //获取系统页面大小
    unsigned int startAddr = (unsigned int)start;
    unsigned int endAddr = (unsigned int)end;
    unsigned int searchStartPage = startAddr;
    unsigned int searchStartPos = 0;

    while(!findMagic((void*)(searchStartPage+40))) {
        searchStartPage += pageSize;
    }
    searchStartPos = searchStartPage+40;
    LOGD("searchStartPage = %x", searchStartPage);
    LOGD("searchStartPos = %x", searchStartPos);
//    char* con = (char*)malloc(20);
//    memcpy(con,(void*)searchStartPos,19);
//    LOGD("magic:%s",con);
    return 1;
}