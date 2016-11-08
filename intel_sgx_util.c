/*
 * This file is provided under a dual BSD/GPLv2 license.  When using or
 * redistributing this file, you may do so under either license.
 *
 * GPL LICENSE SUMMARY
 *
 * Copyright(c) 2016 Intel Corporation.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of version 2 of the GNU General Public License as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * General Public License for more details.
 *
 * Contact Information:
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Intel Finland Oy - BIC 0357606-4 - Westendinkatu 7, 02160 Espoo
 *
 * BSD LICENSE
 *
 * Copyright(c) 2016 Intel Corporation.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 *   * Redistributions of source code must retain the above copyright
 *     notice, this list of conditions and the following disclaimer.
 *   * Redistributions in binary form must reproduce the above copyright
 *     notice, this list of conditions and the following disclaimer in
 *     the documentation and/or other materials provided with the
 *     distribution.
 *   * Neither the name of Intel Corporation nor the names of its
 *     contributors may be used to endorse or promote products derived
 *     from this software without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS
 * "AS IS" AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT
 * LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR
 * A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT
 * OWNER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT
 * LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Authors:
 *
 * Jarkko Sakkinen <jarkko.sakkinen@linux.intel.com>
 * Suresh Siddha <suresh.b.siddha@intel.com>
 * Serge Ayoun <serge.ayoun@intel.com>
 * Shay Katz-zamir <shay.katz-zamir@intel.com>
 */

#include "intel_sgx.h"
#include <linux/highmem.h>
#include <linux/shmem_fs.h>

void *sgx_get_epc_page(struct sgx_epc_page *entry)
{
#ifdef CONFIG_X86_32
	return kmap_atomic_pfn(PFN_DOWN(entry->pa));
#else
	return sgx_epc_mem + (entry->pa - sgx_epc_base);
#endif
}

void sgx_put_epc_page(void *epc_page_vaddr)
{
#ifdef CONFIG_X86_32
	kunmap_atomic(epc_page_vaddr);
#else
#endif
}

struct page *sgx_get_backing(struct sgx_encl *encl,
			     struct sgx_encl_page *entry)
{
	struct page *backing;
	struct inode *inode;
	struct address_space *mapping;
	gfp_t gfpmask;
	pgoff_t index;

	inode = encl->backing->f_path.dentry->d_inode;
	mapping = inode->i_mapping;
	gfpmask = mapping_gfp_mask(mapping);

	index = (entry->addr - encl->base) >> PAGE_SHIFT;
	backing = shmem_read_mapping_page_gfp(mapping, index, gfpmask);

	return backing;
}

void sgx_put_backing(struct page *backing_page, bool write)
{
	if (write)
		set_page_dirty(backing_page);

	put_page(backing_page);
}

struct vm_area_struct *sgx_find_vma(struct sgx_encl *encl, unsigned long addr)
{
	struct vm_area_struct *vma;

	vma = find_vma(encl->mm, addr);
	if (vma && encl == vma->vm_private_data)
		return vma;

	sgx_dbg(encl, "cannot find VMA at 0x%lx\n", addr);
	return NULL;
}

void sgx_zap_tcs_ptes(struct sgx_encl *encl, struct vm_area_struct *vma)
{
	struct sgx_encl_page *entry;
	struct rb_node *rb;

	rb = rb_first(&encl->encl_rb);
	while (rb) {
		entry = container_of(rb, struct sgx_encl_page, node);
		rb = rb_next(rb);
		if (entry->epc_page && (entry->flags & SGX_ENCL_PAGE_TCS) &&
		    entry->addr >= vma->vm_start &&
		    entry->addr < vma->vm_end)
			zap_vma_ptes(vma, entry->addr, PAGE_SIZE);
	}
}

bool sgx_pin_mm(struct sgx_encl *encl)
{
	if (encl->flags & SGX_ENCL_SUSPEND)
		return false;

	mutex_lock(&encl->lock);
	if (encl->vma_cnt) {
		atomic_inc(&encl->mm->mm_count);
	} else {
		mutex_unlock(&encl->lock);
		return false;
	}
	mutex_unlock(&encl->lock);

	down_read(&encl->mm->mmap_sem);

	if (!encl->vma_cnt) {
		sgx_unpin_mm(encl);
		return false;
	}

	return true;
}

void sgx_unpin_mm(struct sgx_encl *encl)
{
	up_read(&encl->mm->mmap_sem);
	mmdrop(encl->mm);
}

void sgx_invalidate(struct sgx_encl *encl)
{
	struct vm_area_struct *vma;
	unsigned long addr;

	for (addr = encl->base; addr < (encl->base + encl->size);
	     addr = vma->vm_end) {
		vma = sgx_find_vma(encl, addr);
		if (vma)
			sgx_zap_tcs_ptes(encl, vma);
	}

	encl->vma_cnt = 0;
}

int sgx_find_encl(struct mm_struct *mm, unsigned long addr,
		  struct vm_area_struct **vma)
{
	struct sgx_encl *encl;

	*vma = find_vma(mm, addr);

	if (!(*vma) || (*vma)->vm_ops != &sgx_vm_ops ||
	    addr < (*vma)->vm_start)
		return -EINVAL;

	encl = (*vma)->vm_private_data;
	if (!encl) {
		pr_debug("%s: VMA is memory mapped but no enclave created at 0x%p\n",
			 __func__, (void *)addr);
		return -ENOENT;
	}

	if (encl->flags & SGX_ENCL_SUSPEND) {
		sgx_dbg(encl,  "%s: suspend ID has been changed\n", __func__);
		return SGX_POWER_LOST_ENCLAVE;
	}

	return 0;
}

struct sgx_encl_page *sgx_encl_find_page(struct sgx_encl *encl,
					 unsigned long addr)
{
	struct rb_node *node = encl->encl_rb.rb_node;

	while (node) {
		struct sgx_encl_page *data =
			container_of(node, struct sgx_encl_page, node);

		if (data->addr > addr)
			node = node->rb_left;
		else if (data->addr < addr)
			node = node->rb_right;
		else
			return data;
	}

	return NULL;
}

void sgx_encl_release(struct kref *ref)
{
	struct rb_node *rb1, *rb2;
	struct sgx_encl_page *entry;
	struct sgx_va_page *va_page;
	struct sgx_encl *encl =
		container_of(ref, struct sgx_encl, refcount);

	if (encl->tgid_ctx) {
		mutex_lock(&encl->tgid_ctx->lock);
		if (!list_empty(&encl->encl_list))
			list_del(&encl->encl_list);
		mutex_unlock(&encl->tgid_ctx->lock);
	}

	rb1 = rb_first(&encl->encl_rb);
	while (rb1) {
		entry = container_of(rb1, struct sgx_encl_page, node);
		rb2 = rb_next(rb1);
		rb_erase(rb1, &encl->encl_rb);
		if (entry->epc_page) {
			list_del(&entry->load_list);
			sgx_free_page(entry->epc_page, encl, 0);
		}
		kfree(entry);
		rb1 = rb2;
	}

	while (!list_empty(&encl->va_pages)) {
		va_page = list_first_entry(&encl->va_pages,
					   struct sgx_va_page, list);
		list_del(&va_page->list);
		sgx_free_page(va_page->epc_page, encl, 0);
		kfree(va_page);
	}

	if (encl->secs_page.epc_page)
		sgx_free_page(encl->secs_page.epc_page, encl, 0);

	encl->secs_page.epc_page = NULL;

	if (encl->tgid_ctx)
		kref_put(&encl->tgid_ctx->refcount, sgx_tgid_ctx_release);

	if (encl->backing)
		fput(encl->backing);

	kfree(encl);
}
