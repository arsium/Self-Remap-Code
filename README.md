# Self-Remap Code

The idea comes from this amazing [repository](https://github.com/changeofpace/Self-Remapping-Code).


## Summary

This program is able to remap itself to prevent debugging or dumping. This program has been tested in 64-bit. It could work in 32-bit but not tested or intended.

## Features

* PEB used to retrieve base image address
* Custom GetModule address
* Custom GetProcAddress
* No imports
* Minimal executable
* Custom memcpy
* Syscall used : NtCreateSection, NtMapViewOfSection, NtUnmapViewOfSection, NtClose
* Custom headers

> [!NOTE]
>
> The program must be compiled with section aligned to a block of  memory (64kb) or system granularity instead of page alignment (4kb).

## Improvements

* Indirect syscalls
* Name of function obfuscation
* Return address spoofing
* ...

## Scheme

![Mapper](https://github.com/arsium/Self-Remap-Code/blob/main/Mapper.png?raw=true)
