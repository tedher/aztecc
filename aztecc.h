#ifndef AZTEC_H
#define AZTEC_H

const char PKFILENAME[]="pubkey.pk";
const char manual[]=
	"Usage : aztecc [COMMANDS]\n\n"
	"COMMANDS :\n"
 	"-e, --encrypt <plaintext>    encrypt plaintext file, needs -u\n"
	"-d, --decrypt <ciphertext>   decrypt ciphertext file\n"
  	"-g, --genkey                 generate public key file, needs -k\n"
	"-f, --find                   find an elliptic curve point\n"
	"-t, --test                   test an elliptic curve point\n"
	"-k [160|192]                 keysize\n"
	"-u                           username\n" 
   "-w, --wipe    <filename>     wipe file\n"
	"-h, --help                   this help\n"
   "-v, --version                version info\n\n"
	"Notes : Valid keysize is 160 or 192.\n"
	"        If pkfile is not supplied, default to pubkey.pk\n\n"
	"Examples : \n"
	"aztecc -e t100.txt -u tdh\n\t"
	"encrypt plaintext file (t100.txt) for user 'tdh'\n"
   "aztecc -d t100.txt.tef\n\t"
	"decrypt ciphertext file (t100.txt.tef)\n"
	"aztecc -w t100.txt.tef\n\t"
	"wipe file t100.txt.tef\n\n"
	"Report bugs to <tedi-h@usa.net>\n";
#endif
