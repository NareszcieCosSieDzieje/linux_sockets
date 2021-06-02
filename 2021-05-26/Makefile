SRC_FILE=src

compile: zadanie_04_server zadanie_04_client prepare move

prepare:
	mkdir -p src

zadanie_04_server: zadanie_04_tcp_server.c
	gcc -w zadanie_04_tcp_server.c -o zadanie_04_tcp_server.elf

zadanie_04_client: zadanie_04_tcp_client.c
	gcc -w zadanie_04_tcp_client.c -o zadanie_04_tcp_client.elf

move:
	mv *.elf src/

strip: src
	for i in ./src/*.elf ; \
	do	\
		if test -f "$$i"; then strip "$$i"; fi; \
	done

clean:
	rm -rf *.elf

clean_src:
	rm -rfd ./src