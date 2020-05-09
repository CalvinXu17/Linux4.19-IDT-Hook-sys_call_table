#include <linux/init.h>
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/types.h>
#include <linux/unistd.h>
#include <linux/sched.h>
#include <linux/kallsyms.h>
#include <asm/cacheflush.h>
#include <asm/page.h>
#include <asm/current.h>
	
unsigned long *syscall_table; // 系统调用表地址

struct 
{
	unsigned short size;
	unsigned int addr; // 高32位为idt表地址
}__attribute__((packed)) idtr; // idtr是48位6字节寄存器

struct
{
	unsigned short offset_low;
	unsigned short selector;
	unsigned char reserved;
	unsigned char flag;
	unsigned short offset_high;
}__attribute__((packed)) idt; // idt表 8字节

void get_addr_idt(void)
{
	asm("sidt %0":"=m"(idtr)); //通过idtr获取IDT表的地址
	printk(KERN_ALERT "idt table adr: 0x%x\n", idtr.addr);
}

unsigned long* find_sys_call_table(void)
{
	unsigned int sys_call_off;
	char *p;
	int i;
	unsigned int ret=0;
 
	//将0x80中断处理程序的地址存放到idt中
	memcpy(&idt, idtr.addr+8*0x80, sizeof(idt));//IDT表每项占8个字节，所以sizeof(idt)=8
	sys_call_off = ((idt.offset_high<<16) | idt.offset_low); // 将offset_high和offset_low拼接成32位
 
	p = sys_call_off;
	unsigned int calladr=0;
	for(i=0; i<300; i++)
	{
		// movl	%esp, %eax; call do_int80_syscall_32的机器码
		if(p[i]=='\x89' && p[i+1]=='\xe0' && p[i+2]=='\xe8')
		{
			calladr = (unsigned int)(p+i) + 2; // p+i为mov指令的地址，再加2为call指令地址
			break;
		}
	}
	unsigned int offset = *(unsigned int *)(calladr+1); // call向的地址的偏移
	unsigned int dist_adr = calladr + 5 + offset; // 实际地址=call指令地址+5+偏移
	printk(KERN_ALERT "calladr: 0x%x, offset: 0x%x, jmp to: 0x%x\n", calladr, offset, dist_adr);
	
	
	p = dist_adr;
	for(i=0; i<300; i++)
	{
		
		// push dword ptr [ebx+14h];mov eax, dword ptr [D467B200h+eax*4]
		if(p[i]=='\xff' && p[i+1]=='\x73' && p[i+2]=='\x14' && p[i+3]=='\x8b')
		{
			ret = *(unsigned int*)(p+i+6); 
			// push dword ptr [ebx+14h]指令地址+6的值为sys_call_table地址
			printk(KERN_ALERT "sys_call_table: 0x%x\n", ret);
			break;
		}
	}
	
	return (unsigned long*)ret;
}
 
unsigned int oldadr;
void myfunc(void)
{
	printk(KERN_ALERT "hook uname\n");
	return;
}

static int lkm_init(void)
{
	get_addr_idt(); // 获取idt表地址
	
	syscall_table = find_sys_call_table();
	if (syscall_table)
	{
		write_cr0(read_cr0() & (~0x10000)); // 关闭内核写保护
		oldadr = (unsigned int)syscall_table[__NR_uname]; // 保存真实地址
		syscall_table[__NR_uname] = myfunc; // 修改地址
		write_cr0(read_cr0() | 0x10000); // 恢复写保护
		printk(KERN_ALERT "hook success\n");
	} else {
		printk(KERN_ALERT "hook failed\n");
	}
	return 0;
}
 
static void lkm_exit(void)
{
	if (syscall_table) {
		write_cr0(read_cr0() & (~0x10000));	
		syscall_table[__NR_uname] = oldadr; // 恢复原地址
		write_cr0(read_cr0() | 0x10000);
		printk(KERN_ALERT "resume syscall table, module removed\n");
	}
	printk(KERN_ALERT "Good Bye Kernel!\n");
}

MODULE_LICENSE("GPL");
MODULE_AUTHOR("calvin");
MODULE_DESCRIPTION("hook idt");
module_init(lkm_init);
module_exit(lkm_exit);
