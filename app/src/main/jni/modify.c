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
int findMagic(void *searchStartPage) {
    char magic[10];
    memcpy(magic, "dex\n035", 8);
    if (memcmp(searchStartPage, magic, 5)) {
        return 0;
    } else {
        return 1;
    }
}

/**
 * leb128格式数据转成int格式数据
 * @param addr
 * @param count
 * @return
 */
int readUleb128(int *addr, int count) {
    int *address;
    int result;
    signed int bytes;
    signed int value_1;
    signed int value_2;
    signed int value_3;

    address = addr;
    result = *(char *) addr;
    bytes = 1;
    if ((unsigned int) result > 0x7F)//判断最高bit 0x7f = 0111 1111
    {
        value_1 = *((char *) address + 1);//取下一个8bit
        //第一个字节与第二个字节去除最高位，拼成一个2字节数值
        result = result & 0x7F | ((value_1 & 0x7F) << 7);
        bytes = 2;
        if (value_1 > 127)//如果第二个字节最高位为1，即后面还有数值
        {
            value_2 = *((char *) address + 2);//取第三个字节
            result |= (value_2 & 0x7F) << 14;//移位，拼成3字节数值
            bytes = 3;
            if (value_2 > 127)//如果第三个字节最高位为1，接着取下面的数值
            {
                value_3 = *((char *) address + 3);
                bytes = 4;
                result |= (value_3 & 0x7F) << 21;
                if (value_3 > 127)//如果第四个字节最高位为1，接着取下面的数值
                {
                    bytes = 5;
                    result |= *((char *) address + 4) << 28;
                }//结束判断，此时可以取得最大值为：
                // 1111111 1111111 1111111 1111111 1111111 = 7ffffffffh，基本满足需要
            }
        }
    }
    *(int *) count = bytes;//将leb128数值的字节数返回给count指针
    return result;//返回转换成的int数值
}

/*
struct string_ids_item{
		uint string_data_off;
}
string_data_off->struct uleb128 utf16_size+string data[]
 */
int getStrIdx(int dexPos, char *str, int size) {
    int index;
    int string_ids_item;
    int string_data_off;
    int *stringAddr;
    int string_num_mutf8;

    if (*(int *) (dexPos + 56))//string_ids_size
    {
        index = 0;
        string_ids_item = dexPos + *(int *) (dexPos + 60);
        while (1) {
            string_data_off = *(int *) string_ids_item;
            string_ids_item += 4;
            stringAddr = (int *) (dexPos + string_data_off);
            string_num_mutf8 = 0;

            //string_data_off指向的内容前面是一个uleb128格式的数据，表示字符串的长度，之后才是字符串
            if (readUleb128(stringAddr, (int) &string_num_mutf8) == size
                && !strncmp((char *) stringAddr + string_num_mutf8, str, size)) {
                break;
            }
            ++index;
            if (*(int *) (dexPos + 56) <= index) {
                index = -1;
                break;
            }
        }
    } else {
        index = -1;
    }
    return index;
}
/*
struct type_ids_item{
		uint descriptor_idx;
}
 */
//descriptor_id对应string_ids_item的下标
int getTypeIdx(int dexPos, int strIdx) {
    int type_ids_item_size;
    int type_ids_item_addr;
    int typeid_to_stringid;
    signed int index = 0;

    type_ids_item_size = *(int *) (dexPos + 64);
    if (!type_ids_item_size)
        return -1;
    type_ids_item_addr = dexPos + *(int *) (dexPos + 68);
    while (index < type_ids_item_size) {
        typeid_to_stringid = *((int *) type_ids_item_addr + index);
        if (strIdx == typeid_to_stringid) {
            return index;
        }
        index += 1;
    }
    return index;
}

/*
struct method_ids_item{
		ushort class_idx;
		ushort proto_idx;
		uint name_idx;
}
 */
int getMethodIdx(int dexPos, int classTypeIdx, int methodStrIdx) {
    int method_ids_item_size;
    int method_ids_item_addr;
    signed int index = 0;

    method_ids_item_size = *(int *) (dexPos + 88);
    if (method_ids_item_size) {
        method_ids_item_addr = dexPos + *(int *) (dexPos + 92);
        while (index < method_ids_item_size) {
            if (*(short *) method_ids_item_addr == classTypeIdx
                && *(int *) (method_ids_item_addr + 4) == methodStrIdx) {
                return index;
            } else {
                index++;
                method_ids_item_addr += 8;
            }
        }
        return -1;
    } else {//method_ids_item_size为空
        return -1;
    }

}

/*
struct class_def_item
{
	uint class_idx;     	//-->type_ids
	uint access_flags;
	uint superclass_idx;	//-->type_ids
	uint interface_off;     //-->type_list
	uint source_file_idx;	//-->string_ids
	uint annotations_off;	//-->annotation_directory_item
	uint class_data_off;	//-->class_data_item
	uint static_value_off;	//-->encoded_array_item
}

 */
int getClassDefItem(int dexPos, int classTypeIdx) {
    int classDefsSize;

    int classDefsOff;
    int result;
    int classIdx;
    int count;

    classDefsSize = *(int *)(dexPos + 96);
    LOGD("size:%d",classDefsSize);
    classDefsOff = *(int *)(dexPos + 100);
    result = 0;
    if (classDefsSize)
    {
        classIdx = dexPos + classDefsOff;
        result = classIdx;
        if ( *(int *)classIdx != classTypeIdx)
        {
            count = 0;
            while (1)
            {
                ++count;
                if (count == classDefsSize)
                    break;
                result += 32;
                if ( *(int *)(result) == classTypeIdx)

                    return result-dexPos;
            }
            result = 0;
        }
    }
//    while (index < class_def_item_size) {
//        class_def_item_addr = (int *)class_def_item_addr + 8 * index;
//        classIdx = *((int *) class_def_item_addr);
//        if (classIdx == classTypeIdx) {
//
//        }
//    }
    return result;

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
            if (strstr(line, "@cn.pollux.modifydalvikbytecode") != NULL) {
                if (strstr(line, "classes.dex") != NULL) {
                    LOGD("line:%s", line);
                    char *s = strchr(line, '-');
                    s += 1;//跳过'-'，不然被strtoul当做负号
                    start = (void *) strtoul(line, NULL, 16);
                    end = (void *) strtoul(s, NULL, 16);
                    LOGD("dex start address:%x", (unsigned int) start);
                    LOGD("dex end address:%x", (unsigned int) end);
                    break;
                }
            }
        }
        fclose(fp);
    } else {
        LOGD("open %s failed", fileName);
    }

    long pageSize = sysconf(_SC_PAGE_SIZE);    //获取系统页面大小
    unsigned int startAddr = (unsigned int) start;
    unsigned int endAddr = (unsigned int) end;
    unsigned int searchStartPage = startAddr;
    unsigned int dexPos = 0;

    //从开始地址搜索，去掉40h的odex头
    while (!findMagic((void *) (searchStartPage + 40))) {
        searchStartPage += pageSize;
    }
    dexPos = searchStartPage + 40;
    LOGD("dexPos = %x", dexPos);

    int classStrIdx = 0;
    classStrIdx = getStrIdx(dexPos, "Lcn/pollux/modifydalvikbytecode/Add;",
                            strlen("Lcn/pollux/modifydalvikbytecode/Add;"));
    LOGD("classStrIdx:%x", classStrIdx);

    int methodStrIdx = 0;
    methodStrIdx = getStrIdx(dexPos, "add", strlen("add"));
    LOGD("methodStrIdx:%x", methodStrIdx);

    int classTypeIdx = 0;
    classTypeIdx = getTypeIdx(dexPos, classStrIdx);
    LOGD("classTypeIdx:%x", classTypeIdx);

    int methodIdx = 0;
    methodIdx = getMethodIdx(dexPos, classTypeIdx, methodStrIdx);
    LOGD("methodIdx:%x", methodIdx);

    int classDataItemAddr = 0;
    classDataItemAddr = getClassDefItem(dexPos, classTypeIdx);
    LOGD("classDataItemAddr:%x", classDataItemAddr);//952f8144

    return 1;
}