SRC_FILE=src

compile: zadanie_05_server zadanie_05_client prepare move

prepare:
	mkdir -p src

zadanie_05_server: zadanie_05_server.c
	gcc -w zadanie_05_server.c -o zadanie_05_server.elf -lsctp

zadanie_05_client: zadanie_05_client.c
	gcc -w zadanie_05_client.c -o zadanie_05_client.elf -lsctp

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