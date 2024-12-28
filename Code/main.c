#include "POC.h"

__attribute__((section(".text")))

ULONG_PTR mainCRTStartup(void)
{
    setup();
    //Code only to stop the program like a getchar function
    HANDLE p_std_out = ((PPEB)NtCurrentPeb())->ProcessParameters->StandardInput;
    CHAR unrequired[16];
    IO_STATUS_BLOCK status;
    PNtReadFile p_nt_read_file = get_procedure_address_nt("NtReadFile\0");
    (void)p_nt_read_file(p_std_out, nullptr, nullptr, nullptr, &status, &unrequired[0], 32, nullptr, nullptr);
    return 0x0;
}