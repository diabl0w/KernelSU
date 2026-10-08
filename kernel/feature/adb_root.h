#ifndef __KSU_H_ADB_ROOT
#define __KSU_H_ADB_ROOT
#include <asm/ptrace.h>
#include <linux/jump_label.h>

extern struct static_key_false ksu_adb_root;

long ksu_adb_root_handle_execve(struct pt_regs *regs);
long ksu_adb_root_handle_execveat(struct pt_regs *regs);

void ksu_adb_root_init(void);

void ksu_adb_root_exit(void);

#endif
