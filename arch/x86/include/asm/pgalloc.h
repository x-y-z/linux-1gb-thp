/* SPDX-License-Identifier: GPL-2.0 */
#ifndef _ASM_X86_PGALLOC_H
#define _ASM_X86_PGALLOC_H

#include <linux/threads.h>
#include <linux/mm.h>		/* for struct page */
#include <linux/pagemap.h>

#define __HAVE_ARCH_PTE_ALLOC_ONE
#include <asm-generic/pgalloc.h>	/* for pte_{alloc,free}_one */

static inline int  __paravirt_pgd_alloc(struct mm_struct *mm) { return 0; }

#ifdef CONFIG_PARAVIRT_XXL
#include <asm/paravirt.h>
#else
#define paravirt_pgd_alloc(mm)	__paravirt_pgd_alloc(mm)
static inline void paravirt_pgd_free(struct mm_struct *mm, pgd_t *pgd) {}
static inline void paravirt_alloc_pte(struct mm_struct *mm, unsigned long pfn)	{}
static inline void paravirt_alloc_pmd(struct mm_struct *mm, unsigned long pfn)	{}
static inline void paravirt_alloc_pmd_clone(unsigned long pfn, unsigned long clonepfn,
					    unsigned long start, unsigned long count) {}
static inline void paravirt_alloc_pud(struct mm_struct *mm, unsigned long pfn)	{}
static inline void paravirt_alloc_p4d(struct mm_struct *mm, unsigned long pfn)	{}
static inline void paravirt_release_pte(unsigned long pfn) {}
static inline void paravirt_release_pmd(unsigned long pfn) {}
static inline void paravirt_release_pud(unsigned long pfn) {}
static inline void paravirt_release_p4d(unsigned long pfn) {}
#endif

/*
 * Flags to use when allocating a user page table page.
 */
extern gfp_t __userpte_alloc_gfp;

#ifdef CONFIG_PAGE_TABLE_ISOLATION
/*
 * Instead of one PGD, we acquire two PGDs.  Being order-1, it is
 * both 8k in size and 8k-aligned.  That lets us just flip bit 12
 * in a pointer to swap between the two 4k halves.
 */
#define PGD_ALLOCATION_ORDER 1
#else
#define PGD_ALLOCATION_ORDER 0
#endif

/*
 * Allocate and free page tables.
 */
extern pgd_t *pgd_alloc(struct mm_struct *);
extern void pgd_free(struct mm_struct *mm, pgd_t *pgd);

extern pgtable_t pte_alloc_one(struct mm_struct *);
extern pgtable_t pte_alloc_order(struct mm_struct *, unsigned long, int);

static inline void pte_free_order(struct mm_struct *mm, struct page *pte,
		int order)
{
	int i;

	for (i = 0; i < (1<<order); i++) {
		pgtable_pte_page_dtor(&pte[i]);
		__free_page(&pte[i]);
	}
}

extern void ___pte_free_tlb(struct mmu_gather *tlb, struct page *pte);

static inline void __pte_free_tlb(struct mmu_gather *tlb, struct page *pte,
				  unsigned long address)
{
	___pte_free_tlb(tlb, pte);
}

static inline void pmd_populate_kernel(struct mm_struct *mm,
				       pmd_t *pmd, pte_t *pte)
{
	paravirt_alloc_pte(mm, __pa(pte) >> PAGE_SHIFT);
	set_pmd(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
}

static inline void pmd_populate_kernel_safe(struct mm_struct *mm,
				       pmd_t *pmd, pte_t *pte)
{
	paravirt_alloc_pte(mm, __pa(pte) >> PAGE_SHIFT);
	set_pmd_safe(pmd, __pmd(__pa(pte) | _PAGE_TABLE));
}

static inline void pmd_populate(struct mm_struct *mm, pmd_t *pmd,
				struct page *pte)
{
	unsigned long pfn = page_to_pfn(pte);

	paravirt_alloc_pte(mm, pfn);
	set_pmd(pmd, __pmd(((pteval_t)pfn << PAGE_SHIFT) | _PAGE_TABLE));
}

#define pmd_pgtable(pmd) pmd_page(pmd)

static inline void pud_populate_with_pgtable(struct mm_struct *mm, pud_t *pud,
				struct page *pte)
{
	unsigned long pfn = page_to_pfn(pte);

	paravirt_alloc_pmd(mm, pfn);
	set_pud(pud, __pud(((pteval_t)pfn << PAGE_SHIFT) | _PAGE_TABLE));
}

#define pud_pgtable(pud) pud_page(pud)

#if CONFIG_PGTABLE_LEVELS > 2
static inline pmd_t *pmd_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	struct page *page;
	gfp_t gfp = GFP_KERNEL_ACCOUNT | __GFP_ZERO;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;
	page = alloc_pages(gfp, 0);
	if (!page)
		return NULL;
	if (!pgtable_pmd_page_ctor(page)) {
		__free_pages(page, 0);
		return NULL;
	}
	return (pmd_t *)page_address(page);
}

static inline void pmd_free(struct mm_struct *mm, pmd_t *pmd)
{
	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
	pgtable_pmd_page_dtor(virt_to_page(pmd));
	free_page((unsigned long)pmd);
}

static inline pmd_t *pmd_alloc_one_page_with_ptes(struct mm_struct *mm, unsigned long addr)
{
	pgtable_t pte_pgtables;
	pmd_t *pmd;
	spinlock_t *pmd_ptl;
	int i;

	pte_pgtables = pte_alloc_order(mm, addr,
		HPAGE_PUD_ORDER - HPAGE_PMD_ORDER);
	if (!pte_pgtables)
		return NULL;

	pmd = pmd_alloc_one(mm, addr);
	if (unlikely(!pmd)) {
		pte_free_order(mm, pte_pgtables,
			HPAGE_PUD_ORDER - HPAGE_PMD_ORDER);
		return NULL;
	}
	pmd_ptl = pmd_lock(mm, pmd);

	for (i = 0; i < (1<<(HPAGE_PUD_ORDER - HPAGE_PMD_ORDER)); i++)
		pgtable_trans_huge_deposit(mm, pmd, pte_pgtables + i);

	spin_unlock(pmd_ptl);

	return pmd;
}

static inline void pmd_free_page_with_ptes(struct mm_struct *mm, pmd_t *pmd)
{
	spinlock_t *pmd_ptl;
	int i;

	BUG_ON((unsigned long)pmd & (PAGE_SIZE-1));
	pmd_ptl = pmd_lock(mm, pmd);

	for (i = 0; i < (1<<(HPAGE_PUD_ORDER - HPAGE_PMD_ORDER)); i++) {
		pgtable_t pte_pgtable;

		pte_pgtable = pgtable_trans_huge_withdraw(mm, pmd);
		pte_free(mm, pte_pgtable);
	}

	spin_unlock(pmd_ptl);
	pmd_free(mm, pmd);
}
extern void ___pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd);

static inline void __pmd_free_tlb(struct mmu_gather *tlb, pmd_t *pmd,
				  unsigned long address)
{
	___pmd_free_tlb(tlb, pmd);
}

#ifdef CONFIG_X86_PAE
extern void pud_populate(struct mm_struct *mm, pud_t *pudp, pmd_t *pmd);
#else	/* !CONFIG_X86_PAE */
static inline void pud_populate(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	paravirt_alloc_pmd(mm, __pa(pmd) >> PAGE_SHIFT);
	set_pud(pud, __pud(_PAGE_TABLE | __pa(pmd)));
}

static inline void pud_populate_safe(struct mm_struct *mm, pud_t *pud, pmd_t *pmd)
{
	paravirt_alloc_pmd(mm, __pa(pmd) >> PAGE_SHIFT);
	set_pud_safe(pud, __pud(_PAGE_TABLE | __pa(pmd)));
}
#endif	/* CONFIG_X86_PAE */

#if CONFIG_PGTABLE_LEVELS > 3
static inline void p4d_populate(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
	paravirt_alloc_pud(mm, __pa(pud) >> PAGE_SHIFT);
	set_p4d(p4d, __p4d(_PAGE_TABLE | __pa(pud)));
}

static inline void p4d_populate_safe(struct mm_struct *mm, p4d_t *p4d, pud_t *pud)
{
	paravirt_alloc_pud(mm, __pa(pud) >> PAGE_SHIFT);
	set_p4d_safe(p4d, __p4d(_PAGE_TABLE | __pa(pud)));
}

static inline pud_t *pud_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	gfp_t gfp = GFP_KERNEL_ACCOUNT;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;
	return (pud_t *)get_zeroed_page(gfp);
}

static inline void pud_free(struct mm_struct *mm, pud_t *pud)
{
	BUG_ON((unsigned long)pud & (PAGE_SIZE-1));
	free_page((unsigned long)pud);
}

extern void ___pud_free_tlb(struct mmu_gather *tlb, pud_t *pud);

static inline void __pud_free_tlb(struct mmu_gather *tlb, pud_t *pud,
				  unsigned long address)
{
	___pud_free_tlb(tlb, pud);
}

#if CONFIG_PGTABLE_LEVELS > 4
static inline void pgd_populate(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
{
	if (!pgtable_l5_enabled())
		return;
	paravirt_alloc_p4d(mm, __pa(p4d) >> PAGE_SHIFT);
	set_pgd(pgd, __pgd(_PAGE_TABLE | __pa(p4d)));
}

static inline void pgd_populate_safe(struct mm_struct *mm, pgd_t *pgd, p4d_t *p4d)
{
	if (!pgtable_l5_enabled())
		return;
	paravirt_alloc_p4d(mm, __pa(p4d) >> PAGE_SHIFT);
	set_pgd_safe(pgd, __pgd(_PAGE_TABLE | __pa(p4d)));
}

static inline p4d_t *p4d_alloc_one(struct mm_struct *mm, unsigned long addr)
{
	gfp_t gfp = GFP_KERNEL_ACCOUNT;

	if (mm == &init_mm)
		gfp &= ~__GFP_ACCOUNT;
	return (p4d_t *)get_zeroed_page(gfp);
}

static inline void p4d_free(struct mm_struct *mm, p4d_t *p4d)
{
	if (!pgtable_l5_enabled())
		return;

	BUG_ON((unsigned long)p4d & (PAGE_SIZE-1));
	free_page((unsigned long)p4d);
}

extern void ___p4d_free_tlb(struct mmu_gather *tlb, p4d_t *p4d);

static inline void __p4d_free_tlb(struct mmu_gather *tlb, p4d_t *p4d,
				  unsigned long address)
{
	if (pgtable_l5_enabled())
		___p4d_free_tlb(tlb, p4d);
}

#endif	/* CONFIG_PGTABLE_LEVELS > 4 */
#endif	/* CONFIG_PGTABLE_LEVELS > 3 */
#endif	/* CONFIG_PGTABLE_LEVELS > 2 */

#endif /* _ASM_X86_PGALLOC_H */
