#ifndef ELF_FILES_H
#define ELF_FILES_H

bool is_correct_elf(FILE* elf_fd);
unsigned long get_entry_point(FILE* elf_fd, pid_t child);
unsigned long get_base_address(pid_t child);
void print_proc_maps(pid_t child);

#endif