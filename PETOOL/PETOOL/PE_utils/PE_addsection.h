//
// Created by MS08-067 on 2020/8/4.
//

#ifndef PE_PRACTICE_PE_ADDSECTION_H
#define PE_PRACTICE_PE_ADDSECTION_H

#endif //PE_PRACTICE_PE_ADDSECTION_H

#include "PE_tools.h"


static BYTE SECION_HEAD_DATA[] = {0x2E, 0x73, 0x68, 0x65, 0x6C, 0x6C, 0x00, 0x00, 0x8C, 0xA6, 0x00, 0x00, 0x00, 0x10, 0x00,
                           0x00, 0x00, 0xA8, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                           0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x20, 0x00, 0x00, 0x60};


VOID AddSection(DWORD size_of_new_section);