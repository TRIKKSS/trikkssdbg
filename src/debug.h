#ifndef MAIN_H
#define MAIN_H

#include <stdbool.h>
#include <stdint.h>

typedef struct bp bp;
struct bp {
	// save our breakpoint
	// I use chained list because we dont know the number of bp
	int id;
	long int instruction_before; // saved instruction
	long int address; // bp address
	char* description; // optional description of our bp
	bp* next_node; // address of the next node
};

// main debugger loop
void debugger_cli(pid_t child);
bool place_breakpoint(pid_t child, long int address, char* description);
void remove_breakpoint(pid_t child, int id);
void print_all_registers(pid_t process);
long get_register(pid_t process, char* reg_name);
int is_reg_available(char *regs_name);
bool bp_already_exist(long int addr);
void print_all_bp();
void delete_breakpoint(int id);
int add_breakpoint(
	bp** breakpoint,
	int id,
	long int instruction,
	long int address,
	char* description
);
bp* is_user_breakpoint(long rip);
uint8_t* read_memory(pid_t child, long int addr, int size);
// void check_for_malloc_errors(void* ptr);

#endif