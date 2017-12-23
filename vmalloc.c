/*
 *  linux/mm/vmalloc.c
 *
 *  Copyright (C) 1993  Linus Torvalds
 *  Support of BIGMEM added by Gerhard Wichert, Siemens AG, July 1999
 *  SMP-safe vmalloc/vfree/ioremap, Tigran Aivazian <tigran@veritas.com>, May 2000
 */

#include <linux/config.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>
#include <linux/highmem.h>
#include <linux/smp_lock.h>

#include <asm/uaccess.h>
#include <asm/pgalloc.h>

rwlock_t vmlist_lock = RW_LOCK_UNLOCKED;
struct vm_struct * vmlist;

static inline void free_area_pte(pmd_t * pmd, unsigned long address, unsigned long size) //释放页表中的表项pte分配所有页框
{
	pte_t * pte;
	unsigned long end;

	if (pmd_none(*pmd))
		return;
	if (pmd_bad(*pmd)) {
		pmd_ERROR(*pmd);
		pmd_clear(pmd);
		return;
	}
	pte = pte_offset(pmd, address);
	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;
	do {
		pte_t page;
		page = ptep_get_and_clear(pte);
		address += PAGE_SIZE;
		pte++;
		if (pte_none(page))
			continue;
		if (pte_present(page)) {
			struct page *ptpage = pte_page(page);
			if (VALID_PAGE(ptpage) && (!PageReserved(ptpage)))
				__free_page(ptpage);
			continue;
		}
		printk(KERN_CRIT "Whee.. Swapped out page in kernel page table\n");
	} while (address < end);
}

static inline void free_area_pmd(pgd_t * dir, unsigned long address, unsigned long size)  //释放页中间目录（pmd映射）
{
	pmd_t * pmd;
	unsigned long end;

	if (pgd_none(*dir))
		return;
	if (pgd_bad(*dir)) {
		pgd_ERROR(*dir);
		pgd_clear(dir);
		return;
	}
	pmd = pmd_offset(dir, address);
	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	do {
		free_area_pte(pmd, address, end - address);
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address < end);
}

void vmfree_area_pages(unsigned long address, unsigned long size)  //断开vm所在线性地址所对应的映射关系
{
	pgd_t * dir;
	unsigned long end = address + size;

	dir = pgd_offset_k(address);
	flush_cache_all();
	do {
		free_area_pmd(dir, address, end - address);
		address = (address + PGDIR_SIZE) & PGDIR_MASK;
		dir++;
	} while (address && (address < end));
	flush_tlb_all();
}

static inline int alloc_area_pte (pte_t * pte, unsigned long address,  //为页表中的表项pte分配所有页框（页表页建立映射）
			unsigned long size, int gfp_mask, pgprot_t prot)
{
	unsigned long end;

	address &= ~PMD_MASK;
	end = address + size;
	if (end > PMD_SIZE)
		end = PMD_SIZE;
	do {
		struct page * page;
		spin_unlock(&init_mm.page_table_lock);
		page = alloc_page(gfp_mask);
		spin_lock(&init_mm.page_table_lock);
		if (!pte_none(*pte))
			printk(KERN_ERR "alloc_area_pte: page already exists\n");
		if (!page)
			return -ENOMEM;
		set_pte(pte, mk_pte(page, prot));
		address += PAGE_SIZE;
		pte++;
	} while (address < end);
	return 0;
}

static inline int alloc_area_pmd(pmd_t * pmd, unsigned long address, unsigned long size, int gfp_mask, pgprot_t prot)  //创建页中间目录映射
{
	unsigned long end;

	address &= ~PGDIR_MASK;
	end = address + size;
	if (end > PGDIR_SIZE)
		end = PGDIR_SIZE;
	do {
		pte_t * pte = pte_alloc(&init_mm, pmd, address);
		if (!pte)
			return -ENOMEM;
		if (alloc_area_pte(pte, address, end - address, gfp_mask, prot))
			return -ENOMEM;
		address = (address + PMD_SIZE) & PMD_MASK;
		pmd++;
	} while (address < end);
	return 0;
}

inline int vmalloc_area_pages (unsigned long address, unsigned long size,  //为申请到的虚拟空间更改页目录、页表
                               int gfp_mask, pgprot_t prot)
{
	pgd_t * dir;
	unsigned long end = address + size;
	int ret;

	dir = pgd_offset_k(address);
	spin_lock(&init_mm.page_table_lock);
	do {
		pmd_t *pmd;
		
		pmd = pmd_alloc(&init_mm, dir, address);
		ret = -ENOMEM;
		if (!pmd)
			break;

		ret = -ENOMEM;
		if (alloc_area_pmd(pmd, address, end - address, gfp_mask, prot))
			break;

		address = (address + PGDIR_SIZE) & PGDIR_MASK;
		dir++;

		ret = 0;
	} while (address && (address < end));
	spin_unlock(&init_mm.page_table_lock);
	flush_cache_all();
	return ret;
}

struct vm_struct * get_vm_area(unsigned long size, unsigned long flags)//在vmalloc地址空间中找到一个适当的区域.
{
	unsigned long addr;
	struct vm_struct **p, *tmp, *area;

	area = (struct vm_struct *) kmalloc(sizeof(*area), GFP_KERNEL); //为vm_struct结构分配内核空间
	if (!area)
		return NULL;
	size += PAGE_SIZE;
	addr = VMALLOC_START;   //从high_memory+8MB开始寻找
	write_lock(&vmlist_lock);
	for (p = &vmlist; (tmp = *p) ; p = &tmp->next) {  //遍历vmlist链表
		if ((size + addr) < addr)
			goto out;
		if (size + addr <= (unsigned long) tmp->addr)    //发现两个链表项所表示的虚拟内存块之间大小能放下申请的虚拟内存快
			break;
		addr = tmp->size + (unsigned long) tmp->addr;
		if (addr > VMALLOC_END-size)
			goto out;
	}
	/*将相应起始地址，块大小，flag标志等信息填入刚申请得到的vm_struct结构中*/
	area->flags = flags;
	area->addr = (void *)addr;
	area->size = size;
	area->next = *p;
	*p = area;
	write_unlock(&vmlist_lock);
	return area;     //返回vm_strcut结构体指针

out:   //给出的addr,size过大造成上溢
	write_unlock(&vmlist_lock);  //将前面对vmlist写操作而加的锁解锁
	kfree(area);    //将已经分配的vm_list结构所用储存空间释放
	return NULL;
}

void vfree(void * addr)   //函数将一个现存的子区域从vmalloc地址空间删除
{
	struct vm_struct **p, *tmp;

	if (!addr)
		return;
	if ((PAGE_SIZE-1) & (unsigned long) addr) {   //所释放的空间必须以页对齐，否则当作地址错误返回
		printk(KERN_ERR "Trying to vfree() bad address (%p)\n", addr);
		return;
	}
	write_lock(&vmlist_lock);
	for (p = &vmlist ; (tmp = *p) ; p = &tmp->next) {
		if (tmp->addr == addr) {      //找到表示该虚拟快的vm_struct结构
			*p = tmp->next;    //将这个vm_struct从vmlist中删除
			vmfree_area_pages(VMALLOC_VMADDR(tmp->addr), tmp->size); //清除与释放虚拟空间有关的页目录项，页表项
			write_unlock(&vmlist_lock);
			kfree(tmp);   //释放vm_struct结构占用的内核态空间
			return;
		}
	}
	write_unlock(&vmlist_lock);
	printk(KERN_ERR "Trying to vfree() nonexistent vm area (%p)\n", addr);
}

void * __vmalloc (unsigned long size, int gfp_mask, pgprot_t prot)
{
	void * addr;
	struct vm_struct *area;

	size = PAGE_ALIGN(size);//对size进行了页面对齐设置
	if (!size || (size >> PAGE_SHIFT) > num_physpages) {  //检测size的合法性  
		BUG();
		return NULL;
	}
	/*在高端内存区分配一个vm_struct并初始化*/
	area = get_vm_area(size, VM_ALLOC);
	if (!area)
		return NULL;
	addr = area->addr;
	 /*为area分配管理page的数组，并通过伙伴系统分配物理页面*/
	if (vmalloc_area_pages(VMALLOC_VMADDR(addr), size, gfp_mask, prot)) {   //分配一个管理page结构的数组，并通过伙伴系统，分配物理页面并填充该数组
		vfree(addr);
		return NULL;
	}
	return addr;
}

long vread(char *buf, char *addr, unsigned long count)  //读调换页面
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			*buf = '\0';
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*buf = *addr;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}

long vwrite(char *buf, char *addr, unsigned long count)  //写调换页面
{
	struct vm_struct *tmp;
	char *vaddr, *buf_start = buf;
	unsigned long n;

	/* Don't allow overflow */
	if ((unsigned long) addr + count < count)
		count = -(unsigned long) addr;

	read_lock(&vmlist_lock);
	for (tmp = vmlist; tmp; tmp = tmp->next) {
		vaddr = (char *) tmp->addr;
		if (addr >= vaddr + tmp->size - PAGE_SIZE)
			continue;
		while (addr < vaddr) {
			if (count == 0)
				goto finished;
			buf++;
			addr++;
			count--;
		}
		n = vaddr + tmp->size - PAGE_SIZE - addr;
		do {
			if (count == 0)
				goto finished;
			*addr = *buf;
			buf++;
			addr++;
			count--;
		} while (--n > 0);
	}
finished:
	read_unlock(&vmlist_lock);
	return buf - buf_start;
}
