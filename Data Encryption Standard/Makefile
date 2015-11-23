# For more makefile info: http://www.cs.colby.edu/maxwell/courses/tutorials/maketutor/

CC=gcc
CFLAGS=
DEPS = DES.h
OBJ = DES.o 

%.o: %.c $(DEPS)
	$(CC) -c -o $@ $< $(CFLAGS)

DES: $(OBJ)
	gcc -o $@ $^ $(CFLAGS)
