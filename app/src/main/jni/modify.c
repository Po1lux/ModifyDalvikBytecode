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

/**
 * 找到DEX的文件魔术"dex\n035"
 * @param searchStartPage
 * @return
 */
int findMagic(void* searchStartPage){
    char magic[10];
    memcpy(magic,"dex\n035",8);
    if(memcmp(searchStartPage,magic,5)){
        return 0;
    }else{
        return 1;
    }
}
/**
 * leb128格式数据转成int格式数据
 * @param addr
 * @param count
 * @return
 */
int readUleb128(int *addr, int count){
    int *address;
    int result;
    signed int bytes;
    signed int value_1;
    signed int value_2;
    signed int value_3;

    address = addr;
    result = *(char *)addr;
    bytes = 1;
    if ( (unsigned int)result > 0x7F )//判断最高bit 0x7f = 0111 1111
    {
        value_1 = *((char *)address + 1);//取下一个8bit
        //第一个字节与第二个字节去除最高位，拼成一个2字节数值
        result = result & 0x7F | ((value_1 & 0x7F) << 7);
        bytes = 2;
        if ( value_1 > 127 )//如果第二个字节最高位为1，即后面还有数值
        {
            value_2 = *((char *)address + 2);//取第三个字节
            result |= (value_2 & 0x7F) << 14;//移位，拼成3字节数值
            bytes = 3;
            if ( value_2 > 127 )//如果第三个字节最高位为1，接着取下面的数值
            {
                value_3 = *((char *)address + 3);
                bytes = 4;
                result |= (value_3 & 0x7F) << 21;
                if ( value_3 > 127 )//如果第四个字节最高位为1，接着取下面的数值
                {
                    bytes = 5;
                    result |= *((char *)address + 4) << 28;
                }//结束判断，此时可以取得最大值为：
                // 1111111 1111111 1111111 1111111 1111111 = 7ffffffffh，基本满足需要
            }
        }
    }
    *(int *)count = bytes;//将leb128数值的字节数返回给count指针
    return result;//返回转换成的int数值
}

int getStrIdx(int searchStartPos,char *str,int size){
    int index;
    int string_ids;
    int string_data_off;
    int *stringAddr;
    int string_num_mutf8;

    if(*(int *)(searchStartPos + 56))//string_ids_size
    {
        index = 0;
        string_ids = searchStartPos + *(int *)(searchStartPos+60);
        while(1) {
            string_data_off = *(int *)string_ids;
            string_ids +=4;
            stringAddr = (int *)(searchStartPos + string_data_off);
            string_num_mutf8 = 0;
            if( readUleb128(stringAddr,(int)&string_num_mutf8) == size
                && !strncmp((char *)stringAddr + string_num_mutf8,str,size)){
                LOGD("(int)&string_num_mutf8:%d",(int)&string_num_mutf8);
                LOGD("(int)&string_num_mutf8:%d",string_num_mutf8);
                break;
            }
            ++index;
            if(*(int *)(searchStartPos+56) <= index ) {
                index = -1;
                break;
            }
        }
    }else {
        index = -1;
    }
    return index;
}


JNIEXPORT jint JNICALL Java_cn_pollux_modifydalvikbytecode_MainActivity_modifyBytecode
        (JNIEnv *env, jclass clazz) {

    //寻找dex的地址
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
            if (strstr(line, "@cn.pollux.modifydalvikbytecode") !=NULL) {
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

    //从开始地址搜索，去掉40h的odex头
    while(!findMagic((void*)(searchStartPage+40))) {
        searchStartPage += pageSize;
    }
    searchStartPos = searchStartPage+40;
    LOGD("searchStartPage = %x", searchStartPage);
    LOGD("searchStartPos = %x", searchStartPos);

    int classStrIdx = 0;
    classStrIdx = getStrIdx(searchStartPos,"Lcn/pollux/modifydalvikbytecode/Add;",strlen("Lcn/pollux/modifydalvikbytecode/Add;"));
    LOGD("classStrIdx:%x",classStrIdx);
    return 1;
}