#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include "numa.h"
#include <unistd.h>
#include <errno.h>
#include <inttypes.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <malloc.h>
#include <stdbool.h>
#include <time.h>

#define PAGE_4KB (4096UL)
#define PAGE_2MB (512UL*PAGE_4KB)
#define PAGE_1GB (512UL*PAGE_2MB)

#define PRESENT_MASK (1UL<<63)
#define SWAPPED_MASK (1UL<<62)
#define PAGE_TYPE_MASK (1UL<<61)
#define PFN_MASK     ((1UL<<55)-1)

#define KPF_THP      (1UL<<22)
#define KPF_PUD_THP      (1UL<<27)

#define SPLIT_DEBUGFS "/sys/kernel/debug/split_huge_pages_in_range_pid"
#define SMAP_PATH "/proc/self/smaps"
#define THP_FS_PATH "/mnt/thp_fs"
#define INPUT_MAX 80

static int write_file(const char *path, const char *buf, size_t buflen)
{
	int fd;
	ssize_t numwritten;

	fd = open(path, O_WRONLY);
	if (fd == -1)
		return 0;

	numwritten = write(fd, buf, buflen - 1);
	close(fd);
	if (numwritten < 1)
		return 0;

	return (unsigned int) numwritten;
}

static void write_debugfs(int pid, uint64_t vaddr_start, uint64_t vaddr_end, int order)
{
	char input[INPUT_MAX];
	int ret;

	ret = snprintf(input, INPUT_MAX, "%d,%lx,%lx,%d", pid, vaddr_start,
			vaddr_end, order);
	if (ret >= INPUT_MAX) {
		printf("%s: Debugfs input is too long\n", __func__);
		exit(EXIT_FAILURE);
	}

	if (!write_file(SPLIT_DEBUGFS, input, ret + 1)) {
		perror(SPLIT_DEBUGFS);
		exit(EXIT_FAILURE);
	}
}

#define MAX_LINE_LENGTH 500

static bool check_for_pattern(FILE *fp, char *pattern, char *buf)
{
	while (fgets(buf, MAX_LINE_LENGTH, fp) != NULL) {
		if (!strncmp(buf, pattern, strlen(pattern)))
			return true;
	}
	return false;
}

static uint64_t check_huge(void *addr)
{
	uint64_t thp = 0;
	int ret;
	FILE *fp;
	char buffer[MAX_LINE_LENGTH];
	char addr_pattern[MAX_LINE_LENGTH];

	ret = snprintf(addr_pattern, MAX_LINE_LENGTH, "%08lx-",
		       (unsigned long) addr);
	if (ret >= MAX_LINE_LENGTH) {
		printf("%s: Pattern is too long\n", __func__);
		exit(EXIT_FAILURE);
	}


	fp = fopen(SMAP_PATH, "r");
	if (!fp) {
		printf("%s: Failed to open file %s\n", __func__, SMAP_PATH);
		exit(EXIT_FAILURE);
	}
	if (!check_for_pattern(fp, addr_pattern, buffer))
		goto err_out;

	/*
	 * Fetch the AnonHugePages: in the same block and check the number of
	 * hugepages.
	 */
	if (!check_for_pattern(fp, "AnonHugePages:", buffer))
		goto err_out;

	sscanf(buffer, "AnonHugePages:%10ld kB", &thp);

err_out:
	fclose(fp);
	return thp;
}

void split_pmd_thp()
{
	char *one_page;
	size_t len = 4 * PAGE_2MB;
	uint64_t thp_size;

	one_page = memalign(PAGE_1GB, len);

	madvise(one_page, len, MADV_HUGEPAGE);

	memset(one_page, 1, len);

	thp_size = check_huge(one_page);
	if (!thp_size) {
		printf("No THP is allocatd");
		exit(EXIT_FAILURE);
	}

	/* split all possible huge pages */
	write_debugfs(getpid(), (uint64_t)one_page, (uint64_t)one_page + len, 0);

	*one_page = 0;

	thp_size = check_huge(one_page);
	if (thp_size) {
		printf("Still %ld kB AnonHugePages not split\n", thp_size);
		exit(EXIT_FAILURE);
	}

	printf("Split huge pages successful\n");
	free(one_page);
}

void create_pagecache_thp_and_fd(size_t fd_size, int *fd, char **addr)
{
	const char testfile[] = THP_FS_PATH "/test";
	size_t i;
	int dummy;

	srand(time(NULL));

	*fd = open(testfile, O_CREAT | O_RDWR, 0664);

	for (i = 0; i < fd_size; i++) {
		unsigned char byte = rand();
		write(*fd, &byte, sizeof(byte));
	}
	close(*fd);
	sync();
	*fd = open("/proc/sys/vm/drop_caches", O_WRONLY);
	if (*fd == -1) {
		perror("open drop_caches");
		exit(EXIT_FAILURE);
	}
	if (write(*fd, "3", 1) != 1) {
		perror("write to drop_caches");
		exit(EXIT_FAILURE);
	}
	close(*fd);

	*fd = open(testfile, O_RDWR);

	*addr = mmap(NULL, fd_size, PROT_READ|PROT_WRITE, MAP_SHARED, *fd, 0);
	if (*addr == (void*)-1) {
		perror("cannot mmap");
		exit(1);
	}
	madvise(*addr, fd_size, MADV_HUGEPAGE);

	for (size_t i = 0; i < fd_size; i++) {
		dummy += *(*addr + i);
	}
}

void split_thp_in_pagecache_to_order(int order)
{
	int fd;
	char *addr;
	size_t fd_size = 2 * PAGE_2MB, i;

	create_pagecache_thp_and_fd(fd_size, &fd, &addr);

	printf("split %ld kB pagecache page to order %d ... ", fd_size >> 10, order);
	write_debugfs(getpid(), (uint64_t)addr, (uint64_t)addr + fd_size, order);

	for (i = 0; i < fd_size; i++) {
		*(addr + i) = (char)i;
	}

	close(fd);
	printf("done\n");
}

void truncate_thp_in_pagecache_to_order(int order)
{
	int fd;
	char *addr;
	size_t fd_size = 2 * PAGE_2MB, i;

	create_pagecache_thp_and_fd(fd_size, &fd, &addr);

	printf("truncate %ld kB pagecache page to size %lu kB ... ", fd_size >> 10, 4UL << order);
	ftruncate(fd, PAGE_4KB << order);

	for (i = 0; i < (PAGE_4KB << order); i++) {
		*(addr + i) = (char)i;
	}

	close(fd);
	printf("done\n");
}

int main(int argc, char** argv)
{
	int i;

	if (geteuid() != 0) {
		printf("Please run the benchmark as root\n");
		exit(EXIT_FAILURE);
	}

	split_pmd_thp();

	for (i = 8; i >= 0; i--)
		if (i != 1)
			split_thp_in_pagecache_to_order(i);

	for (i = 8; i >= 0; i--)
		if (i != 1)
			truncate_thp_in_pagecache_to_order(i);

	return 0;
}
