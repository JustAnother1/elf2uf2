TARGET  = elf2uf2
OBJECTS = elf2uf2.o
LIBS    = 


$(TARGET): $(OBJECTS)
	gcc -ggdb $^ $(LIBS) -o $@

elf2uf2.o: elf2uf2.c
	gcc -ggdb --pedantic -Wall -c $< -o $@

all: $(TARGET)
	size elf2uf2

clean:
	rm -f $(OBJECTS) $(TARGET)
