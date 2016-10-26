/*
 * (C) Copyright 2015 Intel Corporation
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 *
 * This program is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; version 2
 * of the License.
 */

#include "isgx.h"
#include <linux/highmem.h>
#include <linux/shmem_fs.h>

void isgx_dbg(struct isgx_enclave *enclave, const char *format, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, format);
	vaf.fmt = format;
	vaf.va = &args;

	pr_debug_ratelimited("isgx: [%d:0x%p] %pV",
			     pid_nr(enclave->tgid_ctx->tgid),
			     (void *) enclave->base, &vaf);
}

void isgx_info(struct isgx_enclave *enclave, const char *format, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, format);
	vaf.fmt = format;
	vaf.va = &args;

	pr_info_ratelimited("isgx: [%d:0x%p] %pV",
			    pid_nr(enclave->tgid_ctx->tgid),
			    (void *) enclave->base, &vaf);
}

void isgx_warn(struct isgx_enclave *enclave, const char *format, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, format);
	vaf.fmt = format;
	vaf.va = &args;

	pr_warn("isgx: [%d:0x%p] %pV",
	        pid_nr(enclave->tgid_ctx->tgid),
	        (void *) enclave->base, &vaf);
}

void isgx_err(struct isgx_enclave *enclave, const char *format, ...)
{
	struct va_format vaf;
	va_list args;

	va_start(args, format);
	vaf.fmt = format;
	vaf.va = &args;

	pr_err("isgx: [%d:0x%p] %pV",
	       pid_nr(enclave->tgid_ctx->tgid),
	       (void *) enclave->base, &vaf);
}

void *isgx_get_epc_page(struct isgx_epc_page *entry)
{
#ifdef CONFIG_X86_32
	return kmap_atomic_pfn(PFN_DOWN(entry->pa));
#else
	return isgx_epc_mem + (entry->pa - isgx_epc_base);
#endif
}

void isgx_put_epc_page(void *epc_page_vaddr)
{
#ifdef CONFIG_X86_32
	kunmap_atomic(epc_page_vaddr);
#else
#endif
}

struct page *isgx_get_backing_page(struct isgx_enclave* enclave,
				   struct isgx_enclave_page* entry,
				   bool write)
{
	struct page *user_page;
	unsigned long backing_addr;
	int ret;

	backing_addr = enclave->backing + entry->addr - enclave->base;

#if LINUX_VERSION_CODE >= KERNEL_VERSION(4,6,4)
	ret = get_user_pages_remote(
#else
	ret = get_user_pages(
#endif
			     enclave->owner,
			     enclave->mm,
			     backing_addr,
			     1, /* nr_pages */
			     write, /* write */
			     0, /* force */
			     &user_page,
			     NULL);
	if (ret < 0) {
		isgx_dbg(enclave,
			 "get_user_pages() for the backing 0x%lx "\
			 "returned %d\n",
			 entry->addr, ret);
		return ERR_PTR(ret);
	}

	return user_page;
}

void isgx_put_backing_page(struct page *backing_page, bool write)
{
	if (write)
		set_page_dirty(backing_page);

	put_page(backing_page);
}

void isgx_insert_pte(struct isgx_enclave *enclave,
		     struct isgx_enclave_page *enclave_page,
		     struct isgx_epc_page *epc_page,
		     struct vm_area_struct *vma)
{
	int ret;
#ifdef CONFIG_X86_32
	void *ioremap_vaddr = ioremap_cache(epc_page->pa, PAGE_SIZE);
	BUG_ON(!ioremap_vaddr);
#endif
	ret = vm_insert_pfn(vma, enclave_page->addr, PFN_DOWN(epc_page->pa));
#ifdef CONFIG_X86_32
	iounmap(ioremap_vaddr);
#endif
	if (ret) {
		isgx_err(enclave, "vm_insert_pfn() returned %d\n", ret);
		BUG();
	}
}

int isgx_eremove(struct isgx_epc_page *epc_page)
{
	void *epc;
	int ret;

	epc = isgx_get_epc_page(epc_page);
	ret = __eremove(epc);
	isgx_put_epc_page(epc);

	if (ret)
		pr_debug_ratelimited("EREMOVE returned %d\n", ret);

	return ret;
}

static int isgx_test_and_clear_young_cb(pte_t *ptep, pgtable_t token,
				unsigned long addr, void *data)
{
	int ret = pte_young(*ptep);

	if (ret) {
		pte_t pte = pte_mkold(*ptep);
		set_pte_at((struct mm_struct *) data, addr, ptep, pte);
	}

	return ret;
}

/**
 * isgx_test_and_clear_young() - is the enclave page recently accessed?
 * @page:	enclave page to be tested for recent access
 *
 * Checks the Access (A) bit from the PTE corresponding to the
 * enclave page and clears it. Returns 1 if the page has been
 * recently accessed and 0 if not.
 */
int isgx_test_and_clear_young(struct isgx_enclave_page *page)
{
	struct vm_area_struct *vma = isgx_find_vma(page->enclave, page->addr);

	if (!vma)
		return 0;

	return apply_to_page_range(vma->vm_mm, page->addr, PAGE_SIZE,
				   isgx_test_and_clear_young_cb, vma->vm_mm);
}

/**
 * isgx_find_vma() - find VMA for the enclave address
 * @enclave:	the enclave to be searched
 * @addr:	the linear address to query
 *
 * Finds VMA for the given address of the enclave. Returns the VMA if
 * there is one containing the given address.
 */
struct vm_area_struct *isgx_find_vma(struct isgx_enclave *enclave,
			       unsigned long addr)
{
	struct vm_area_struct *vma = find_vma(enclave->mm, addr);
	if (!vma)
		isgx_dbg(enclave, "cannot find VMA at 0x%lx\n", addr);
	return vma;
}

/**
 * isgx_pin_mm - pin the mm_struct of an enclave
 *
 * @encl:	an enclave
 *
 * Locks down mmap_sem of an enclave if it still has VMAs and was not suspended.
 * Returns true if this the case.
 */
bool isgx_pin_mm(struct isgx_enclave *encl)
{
	if (encl->flags & ISGX_ENCLAVE_SUSPEND)
		return false;

	if (!atomic_read(&encl->vma_cnt))
		return false;

	atomic_inc(&encl->mm->mm_count);
	down_read(&encl->mm->mmap_sem);

	if (!atomic_read(&encl->vma_cnt)) {
		isgx_unpin_mm(encl);
		return false;
	}

	return true;
}

/**
 * isgx_unpin_mm - unpin the mm_struct of an enclave
 *
 * @encl:	an enclave
 *
 * Unlocks the mmap_sem.
 */
void isgx_unpin_mm(struct isgx_enclave *encl)
{
	up_read(&encl->mm->mmap_sem);
	mmdrop(encl->mm);
}

/**
 * isgx_invalidate - Invalidate the enclave
 *
 * @enclave:	an enclave
 *
 * Zap PTEs for all TCS pages 
 */
void isgx_invalidate(struct isgx_enclave *enclave)
{
	struct vm_area_struct *vma;
	struct isgx_enclave_page *entry;
	struct rb_node *rb;

	if (!atomic_read(&enclave->vma_cnt))
		return;

	rb = rb_first(&enclave->enclave_rb);
	while (rb) {
		entry = container_of(rb, struct isgx_enclave_page, node);
		rb = rb_next(rb);
		if (entry->epc_page && (entry->flags & ISGX_ENCLAVE_PAGE_TCS)) {
			vma = find_vma(enclave->mm, enclave->base);
			if (vma) {
				BUG_ON(vma->vm_private_data != NULL && vma->vm_private_data != enclave);
				BUG_ON(vma->vm_ops != &isgx_vm_ops);

				zap_vma_ptes(vma, entry->addr, PAGE_SIZE);
			}
		}
	}
}

/**
 * isgx_find_enclave() - find enclave given a virtual address
 * @mm:		the address space where we query the enclave
 * @addr:	the virtual address to query
 * @vma:	VMA if an enclave is found or NULL if not
 *
 * Finds an enclave given a virtual address and a address space where to seek it
 * from. The return value is zero on success. Otherwise, it is either positive
 * for SGX specific errors or negative for the system errors.
 */
int isgx_find_enclave(struct mm_struct *mm, unsigned long addr,
		      struct vm_area_struct **vma)
{
	struct isgx_enclave *enclave;

	*vma = find_vma(mm, addr);

	if (!(*vma) || (*vma)->vm_ops != &isgx_vm_ops || addr < (*vma)->vm_start)
		return -EINVAL;

	/* Is ECREATE already done? */
	enclave = (*vma)->vm_private_data;
	if (!enclave)
		return -ENOENT;

	if (enclave->flags & ISGX_ENCLAVE_SUSPEND) {
		isgx_info(enclave,  "suspend ID has been changed");
		return ISGX_POWER_LOST_ENCLAVE;
	}

	return 0;
}

/**
 * isgx_enclave_find_page() - find an enclave page
 * @encl:	the enclave to query
 * @addr:	the virtual address to query
 */
struct isgx_enclave_page *isgx_enclave_find_page(struct isgx_enclave *enclave,
						 unsigned long enclave_la)
{
	struct rb_node *node = enclave->enclave_rb.rb_node;

	while (node) {
		struct isgx_enclave_page *data =
			container_of(node, struct isgx_enclave_page, node);

		if (data->addr > enclave_la)
			node = node->rb_left;
		else if (data->addr < enclave_la)
			node = node->rb_right;
		else
			return data;
	}

	return NULL;
}

void isgx_enclave_release(struct kref *ref)
{
	struct rb_node *rb1, *rb2;
	struct isgx_enclave_page *entry;
	struct isgx_enclave *enclave =
		container_of(ref, struct isgx_enclave, refcount);

	if (enclave->tgid_ctx) {
		mutex_lock(&enclave->tgid_ctx->lock);
		if (!list_empty(&enclave->enclave_list))
			list_del(&enclave->enclave_list);
		mutex_unlock(&enclave->tgid_ctx->lock);
	}
		
	rb1 = rb_first(&enclave->enclave_rb);
	while (rb1) {
		entry = container_of(rb1, struct isgx_enclave_page, node);
		rb2 = rb_next(rb1);
		rb_erase(rb1, &enclave->enclave_rb);
		if (entry->epc_page) {
			list_del(&entry->epc_list);
			isgx_free_epc_page(entry->epc_page, enclave,
					   ISGX_FREE_EREMOVE);
		}

		isgx_free_va_slot(entry->va_page, entry->va_offset);

		kfree(entry);
		rb1 = rb2;
	}

	if (enclave->secs_page.epc_page)
		isgx_free_epc_page(enclave->secs_page.epc_page, NULL,
				   ISGX_FREE_EREMOVE);

	isgx_free_va_slot(enclave->secs_page.va_page, enclave->secs_page.va_offset);

	enclave->secs_page.epc_page = NULL;

	if (enclave->tgid_ctx)
		kref_put(&enclave->tgid_ctx->refcount, release_tgid_ctx);
	kfree(enclave);
}
