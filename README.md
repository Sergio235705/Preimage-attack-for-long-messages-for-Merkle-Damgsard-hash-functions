# Crypto-Tp2

The goal of this TP is to implement a generic second preimage attack for long messages
for Merkle-Damg˚ard hash functions, in the specific case where the compression function
used within the hash function follows a Davies-Meyer construction.

Here are the files of the practical work sessions of the 22/10 and 29/10 .

## Authors
Sergio Giardina and Lucas Hanouz



## Run the tests

There is a Makefile for it. For each question requiring test, there is  a different test :

* `make ex1_q1_test` for question 1 of exercice 1
* `make ex1_q2_test` for question 2 of exercice 1
* `make ex1_q3_test` for question 3 of exercice 1
* `make ex1_q4_test` for question 4 of exercice 1
* `make ex2_q1_test` for question 1 of exercice 2
* `make ex2_q2_test` for question 2 of exercice 2 (attack)


Then run the exec (same name).

Oh, and there is `make clean` and `make mrproper` to clean the executable files if you want, it's free.

## Clean and execution
example for ex2_q2_test: 
* make clean
* make mrproper 
* make ex2_q2_test
* ./ex2_q2_test



## File organization 

Tests in `exX_qY_test.c` files, all the sources in `second_preim_48.c` and `xoshiro256starstar.h` is the header.
