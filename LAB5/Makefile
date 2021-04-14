
compile: reply request arping
	
reply: arprep.c
	gcc arprep.c -o arprep.elf -lnet
	
request: arpreq.c
	gcc arpreq.c -o arpreq.elf -lnet
	
arping: arping.c
	gcc arping.c -Wall -Wno-unused-variable -o arping.elf -lnet -lpcap 
	
strip: arprep.elf arpreq.elf arping.elf	
	for i in 'arprep.elf' 'arpreq.elf' 'arping.elf'; \
	do	\
		if test -f $$i; then strip "$$i"; fi; \
	done

clean:
	rm -rf arp*.elf