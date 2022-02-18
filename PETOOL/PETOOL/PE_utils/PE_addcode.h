//
// Created by MS08-067 on 2020/8/4.
//

#ifndef PE_PRACTICE_PE_ADDCODE_H
#define PE_PRACTICE_PE_ADDCODE_H

#endif //PE_PRACTICE_PE_ADDCODE_H

#include "stdio.h"
#include "windows.h"
#include "stdlib.h"

#define SHELLCODELENGTH 0X12
#define MESSAGEBOXADDR 0x77D5050B
static BYTE shellCode[] = {0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00, 0x6A, 0x00,
                    0xE8, 0x00, 0x00, 0x00, 0x00,
                    0xE9, 0x00, 0x00, 0x00, 0x00};