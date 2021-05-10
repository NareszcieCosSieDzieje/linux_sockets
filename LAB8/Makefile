SRC_FILE=src

compile: zadanie3 zadanie4 prepare move

prepare:
	mkdir -p src

zadanie3: zadanie_03.c
	gcc -Wall zadanie_03.c -o zadanie_03.elf

zadanie4: zadanie_04.c
	gcc -Wall zadanie_04.c -o zadanie_04.elf

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