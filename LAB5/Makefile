

compile: arpreq.c arpreq.c arping.c
	gcc arprep.c -o arprep.elf -lnet
	gcc arpreq.c -o arpreq.elf -lnet
	gcc arping.c -Wall -Wno-unused-variable -o arping.elf -lnet -lpcap 
	
strip: arprep.elf arpreq.elf	
	for i in 'arprep.elf' 'arpreq.elf' 'arping.elf'; \
	do	\
		if test -f $$i; then strip "$$i"; fi; \
	done

clean:
	rm -rf arp*.elf