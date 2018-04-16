#include <asm/unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "bit_map.h"
#include "xdedup_args.h"

#ifndef __NR_xdedup
#error xdedup system call not defined
#endif

int main(int argc, char **argv)
{
	int rc;
	int opt;
	struct xdedup_args args;
	args.b = 0;
	//args.n = 0, args.p = 0, args.d = 0;

	while((opt = getopt(argc, argv, "pnd")) != -1)
	{
		switch(opt)
		{
			case 'p':
			    args.b = p | args.b;
			    break;
			case 'n':
                            args.b = n | args.b;
			    break;
			case 'd':
                            args.b = d | args.b;
			    break;
			default:
			    printf("Please give proper flags\n");
			    break;
		}
	}
        
	args.param = argv;
	args.count = argc;
	args.index = optind;

	//void *dummy = (void *) argv[1];

  	//rc = syscall(__NR_xdedup, dummy);
	//rc = syscall(__NR_xdedup,"infile1.txt", "infile2.txt");
	//rc = syscall(__NR_xdedup, "infile1.txt", "destination_file.txt", "infile2.txt");
	
	rc = syscall(__NR_xdedup, (void *) &args);
	if (rc == 0)
		printf("syscall returned %d\n", rc);
	else
		printf("syscall returned %d (errno=%d)\n", rc, errno);

	exit(rc);
}
