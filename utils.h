#ifndef UTILS_H
#define UTILS_H

#include<LiDIA/bigmod.h>

const char SEP[2]="#";

// TYPE DEFINITION
typedef unsigned long ULONG;

// CONSTANTS
const int MAX=1024;
const int MAX2=2048;
const unsigned int MAXCHAR=256;
const int MAX_BSIZE=24;					// maximum blocksize

const char header[]=
"=========================================================\n"
"AZTECC - an implementation of elliptic curve cryptosystem\n"
"Version 1.0.0 - Copyright (c) 1999-2000 by Tedi Heriyanto\n"
"This is a freeware edition. Use it at your own risk.\n"
"=========================================================\n"
"\n"
"The elliptic curve used in this program has the following equation :\n"
"                y^2 mod p = x^3 + a*x + b mod p\n"
"where : \n"
"x and y are elliptic curve point coordinates\n"
"p is a large prime number (160-bit or 192-bit).\n"
"a and b are elliptic curve equation coefficients\n";

// Public Key Field Number
// username in 1st field
// hash_dp in 2nd field, etc.
const int USER=0;
const int HASH_D=1;
const int A4=2;
const int A6=3;
const int XP=4;
const int YP=5;
const int XDP=6;
const int YDP=7;
const int Q=8;

void banner();
char* getfield(const char *filename, const char* username, int fieldnum);
void str2bigint(char* s, const int blocksize, bigint& x);
void get_ecparm(bigmod& aa4, bigmod&aa6, bigmod& axp, bigmod& ayp, bigint& aq);
void get_passphrase(bigint& d, int blocksize, const char* username);
void find_point();
void test_point();
void gen_pubkey(const char* pkfilename, int blocksize);
long fsize(const char* fname);
void bigint_to_fixed_string(bigint x, char* str, int blocksize);
void fixed_string_to_bigint(const char* str, bigint& x, int blocksize);
void wipe_file(char* victimfile);
bool is_number(const char* str);
#endif
