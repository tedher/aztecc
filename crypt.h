#ifndef CRYPT_H
#define CRYPT_H

extern long blocksize;

void encrypt_file(char* pkfile,char* username, char* fsrcname);
void decrypt_file(const char* pkfile, const char* fsrcname);

#endif
