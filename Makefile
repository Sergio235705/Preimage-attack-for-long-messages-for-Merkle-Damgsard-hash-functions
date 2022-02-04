CC=gcc
CFLAGS= -c -g -Wall -O -std=c99 -Wextra -O0

LDFLAGS=-lm

EXE = ex1_q1_test ex1_q2_test ex1_q3_test ex1_q4_test ex2_q1_test ex2_q2_test
OBJ = second_preim_48.o

all : $(EXE)

%.o : %.c xoshiro256starstar.h
	$(CC) $(CFLGAS)  -o $@ -c $<

ex1_q1_test : $(OBJ) ex1_q1_test.o
	$(CC) -o $@ $^ $(LDFLAGS)

ex1_q2_test : $(OBJ) ex1_q2_test.o
	$(CC) -o $@ $^ $(LDFLAGS)

ex1_q3_test : $(OBJ) ex1_q3_test.o
	$(CC) -o $@ $^ $(LDFLAGS)

ex1_q4_test : $(OBJ) ex1_q4_test.o
	$(CC) -o $@ $^ $(LDFLAGS)

ex2_q1_test : $(OBJ) ex2_q1_test.o
	$(CC) -o $@ $^ $(LDFLAGS) -O3 -march=native 

ex2_q2_test : $(OBJ) ex2_q2_test.o
	$(CC) -o $@ $^ $(LDFLAGS) -O3 -march=native 

clean:
	rm -f *.o $(EXE)

mrproper: clean
	rm -f $(EXE) vgcore.*
