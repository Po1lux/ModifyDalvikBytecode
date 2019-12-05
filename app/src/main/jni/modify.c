//
// Created by seanchen on 2019-12-03.
//
#include <unistd.h> //getpid
#include <stdio.h>  //sprintf
#include <android/log.h>
#include <string.h> //strstr
#include <stdlib.h> //strtoul
#include <sys/mman.h> //mprotect
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
    result = *addr & 0xff;
    bytes = 1;
    if ((unsigned int) result > 0x7F)//判断最高bit 0x7f = 0111 1111
    {
        value_1 = (*address >> 8) & 0xff;//取下一个8bit
        //第一个字节与第二个字节去除最高位，拼成一个2字节数值
        result = result & 0x7F | (value_1 & 0x7F) << 7;
        bytes = 2;
        if (value_1 > 0x7F)//如果第二个字节最高位为1，即后面还有数值
        {
            value_2 = (*address >> 16) & 0xff;//取第三个字节
            result |= (value_2 & 0x7F) << 14;//移位，拼成3字节数值
            bytes = 3;
            if (value_2 > 0x7F)//如果第三个字节最高位为1，接着取下面的数值
            {
                value_3 = (*address >> 24) & 0xff;
                bytes = 4;
                result |= (value_3 & 0x7F) << 21;
                if (value_3 > 0x7F)//如果第四个字节最高位为1，接着取下面的数值
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

int *skipUleb128(int num, int *address) {
    int read_count;
    int *read_address;
    int i = 0;

    read_count = num;
    read_address = address;
//    for (; read_count; read_address = (int *) ((char *) read_address + i)) {
//        readUleb128(read_address, (int) &i);
//        --read_count;
//    }
    while (read_count) {
        readUleb128(read_address, (int) &i);
        read_address = (int *) ((char *) read_address + i);
        read_count--;
    }
    return read_address;
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
    int class_def_item_size;
    int class_def_item_addr;
    int classIdx;
    int index = 0;

    class_def_item_size = *(int *) (dexPos + 96);
    class_def_item_addr = dexPos + *(int *) (dexPos + 100);
    while (index < class_def_item_size) {
        classIdx = *((int *) class_def_item_addr);
        if (classIdx == classTypeIdx) {
            return class_def_item_addr;
        }
        class_def_item_addr = (int *) class_def_item_addr + 8;
        index++;
    }
    return -1;
}

/*
struct class_data_item
{
	uleb128 static_fields_size;
	uleb128 instance_fields_size;
	uleb128 direct_methods_size;
	uleb128 virtual_methods_size;
	encoded_field  static_fields[static_fields_size];
	encoded_field  instance_fields[instance_fields_size];
	encoded_method direct_methods[direct_methods_size];
	encoded_method virtual_methods[virtual_methods_size];
}
struct encoded_field
{
	uleb128 filed_idx_diff;
	uleb128 access_flags;
}
struct encoded_method
{
	uleb128 method_idx_diff;
	uleb128 access_flags;
	uleb128 code_off;
}
 */
int getCodeItem(int dexPos, int classDefItemAddr, int methodIdx) {
    int static_fields_size;
    int instance_fields_size;
    int direct_methods_size;
    int virtual_methods_size;
    int uleb128Bytes = 0;
    int *class_data_item_addr;
    int *tclass_data_item_addr;
    int *instance_fields_addr;
    int *direct_methods_addr;

    class_data_item_addr = (int *) (dexPos + *((int *) classDefItemAddr + 6));

    tclass_data_item_addr = class_data_item_addr;
    static_fields_size = readUleb128(tclass_data_item_addr, (int) &uleb128Bytes);
    LOGD("static_fields_size:%d", static_fields_size);


    tclass_data_item_addr = (int *) ((char *) tclass_data_item_addr + uleb128Bytes);
    instance_fields_size = readUleb128(tclass_data_item_addr, (int) &uleb128Bytes);
    LOGD("instance_fields_size:%d", instance_fields_size);


    tclass_data_item_addr = (int *) ((char *) tclass_data_item_addr + uleb128Bytes);
    direct_methods_size = readUleb128(tclass_data_item_addr, (int) &uleb128Bytes);
    LOGD("direct_methods_size:%d", direct_methods_size);


    tclass_data_item_addr = (int *) ((char *) tclass_data_item_addr + uleb128Bytes);
    virtual_methods_size = readUleb128(tclass_data_item_addr, (int) &uleb128Bytes);
    LOGD("virtual_methods_size:%d", virtual_methods_size);


    tclass_data_item_addr = (int *) ((char *) tclass_data_item_addr + uleb128Bytes);

    instance_fields_addr = skipUleb128(2 * static_fields_size, tclass_data_item_addr);
    direct_methods_addr = skipUleb128(2 * instance_fields_size, instance_fields_addr);
    LOGD("direct_methods_off:%p", (int *) ((char *) direct_methods_addr - dexPos));

    int *pointAddr = direct_methods_addr;
    int method_idx_diff;
    int access_flags;
    int code_off;
    int devnull;
    //第一个方法的method_idx_diff就是其方法的methodIdx，其后的method_idx_diff是前一个的关于第一个方法的method_idx_diff就是其方法的methodIdx的差值
    int first_method_idx_diff = readUleb128(direct_methods_addr, (int) &devnull);
    int flag = direct_methods_size;
    methodIdx = methodIdx - first_method_idx_diff;

    while (direct_methods_size) {
        LOGD("method_idx_diff_off:%p", (int *) ((char *) pointAddr - dexPos));
        //第一个method_idx_diff做特殊处理
        method_idx_diff = readUleb128(pointAddr, (int) &uleb128Bytes);
        if (flag == direct_methods_size) {
            method_idx_diff = method_idx_diff - first_method_idx_diff;
        }
        pointAddr = (int *) ((char *) pointAddr + uleb128Bytes);//指向access_flags
        LOGD("access_flags_off:%p", (int *) ((char *) pointAddr - dexPos));
        if (methodIdx == method_idx_diff) {
            access_flags = readUleb128(pointAddr, (int) &uleb128Bytes);
            pointAddr = (int *) ((char *) pointAddr + uleb128Bytes);//指向code_item
            LOGD("code_off_off:%p", (int *) ((char *) pointAddr - dexPos));
            code_off = readUleb128(pointAddr, (int) &uleb128Bytes);
            LOGD("code_off:%x", code_off);
            return code_off + dexPos;
        }
        direct_methods_size--;
        pointAddr = skipUleb128(2, pointAddr);
    }

    while (virtual_methods_size) {
        LOGD("method_idx_diff_off:%p", (int *) ((char *) pointAddr - dexPos));
        //第一个method_idx_diff做特殊处理
        method_idx_diff = readUleb128(pointAddr, (int) &uleb128Bytes);
        if (flag == direct_methods_size) {
            method_idx_diff = method_idx_diff - first_method_idx_diff;
        }
        pointAddr = (int *) ((char *) pointAddr + uleb128Bytes);//指向access_flags
        LOGD("access_flags_off:%p", (int *) ((char *) pointAddr - dexPos));
        if (methodIdx == method_idx_diff) {
            access_flags = readUleb128(pointAddr, (int) &uleb128Bytes);
            pointAddr = (int *) ((char *) pointAddr + uleb128Bytes);//指向code_item
            LOGD("code_off_off:%p", (int *) ((char *) pointAddr - dexPos));
            code_off = readUleb128(pointAddr, (int) &uleb128Bytes);
            LOGD("code_off:%x", code_off);
            return code_off + dexPos;
        }
        direct_methods_size--;
        pointAddr = skipUleb128(2, pointAddr);
    }
}

int byte2int(void *addr, int size) {
    int result=0;
    uint16_t byte = 0;
    uint8_t* map = (uint8_t*)calloc(size,'\x00');
    memcpy(map,addr,4);
    for(int i=0;i<size;i++){
        byte = map[i];
        result |= byte<<(8*i);
    }
    free(map);
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

    int classDefItemAddr = 0;
    classDefItemAddr = getClassDefItem(dexPos, classTypeIdx);
    LOGD("classDefItemAddr:%x", classDefItemAddr);

    int codeItemAddr = 0;
    codeItemAddr = getCodeItem(dexPos, classDefItemAddr, methodIdx);
    LOGD("codeItemAddr:%x", codeItemAddr);

/*
struct code_item
{
    ushort registers_size;
    ushort ins_size;
    ushort outs_size;
    ushort tries_size;
    uint debug_info_off;
    uint insns_size;//指令个数
    ushort insns [ insns_size ];
    ushort paddding; // optional
    try_item tries [ tyies_size ]; // optional
    encoded_catch_handler_list handlers; // optional
}
 */
    int *insns_size_addr = (int *) (codeItemAddr + 12);
    int insns_size = byte2int(insns_size_addr,4)*2;
    LOGD("insns_size:%d",insns_size);


    char *code_insns_address;
    code_insns_address = (char *) (codeItemAddr + 16);
    char *code = (char*)calloc(insns_size,'\x00');
    memcpy(code,code_insns_address,insns_size);
    for(int i= 0;i<insns_size;i++){
        LOGD("insns:%02x",code[i]);
    }

    void *codeinsns_page_address =
            (void *) (codeItemAddr + 16 - (codeItemAddr + 16) % (unsigned int) pageSize);
    mprotect(codeinsns_page_address, pageSize, PROT_READ | PROT_WRITE);
    char inject[] = {0x92, 0x00, 0x01, 0x02, 0x0f, 0x00};
    memcpy(code_insns_address, inject, 6);
    return 1;
}