SRC_FILE=src

compile: prepare zadanie_04 move

compile_all: prepare arpget ifsetup irsend setgw zadanie_04 move

prepare:
	mkdir -p src
	
arpget: arpget.c
	gcc arpget.c -o arpget.elf -Wall
	
ifsetup: ifsetup.c
	gcc ifsetup.c -o ifsetup.elf -Wall
	
irsend: irsend.c
	gcc irsend.c -o irsend.elf -Wall 
	
setgw: setgw.c
	gcc setgw.c -o setgw.elf -Wall

zadanie_04: zadanie_04.c
	gcc zadanie_04.c -o zadanie_04.elf -Wall

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

