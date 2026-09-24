/* minimal devmem: devmem ADDR [VALUE]  (32-bit) */
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/mman.h>
#include <unistd.h>
int main(int c, char **v) {
	if (c < 2) { fprintf(stderr, "usage: %s addr [value]\n", v[0]); return 2; }
	unsigned long a = strtoul(v[1], 0, 0), pg = a & ~0xfffUL;
	int fd = open("/dev/mem", O_RDWR | O_SYNC);
	if (fd < 0) { perror("open /dev/mem"); return 1; }
	volatile uint32_t *m = mmap(0, 0x1000, PROT_READ | PROT_WRITE, MAP_SHARED, fd, pg);
	if (m == MAP_FAILED) { perror("mmap"); return 1; }
	volatile uint32_t *r = (volatile uint32_t *)((char *)m + (a - pg));
	if (c > 2) *r = (uint32_t)strtoul(v[2], 0, 0);
	printf("0x%08x\n", *r);
	return 0;
}
