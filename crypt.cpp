/////////////////////////////////////////////////////
// crypt.cpp
//
// This file contains encryption/decryption functions
//
// Version : $1.0.0.$February 15, 2000
//
// AUTHOR : TH <tedi-h@usa.net>
// For copying/modifying/distributing see license.txt
/////////////////////////////////////////////////////

#include"md5.h"
#include"ecc.h"
#include"utils.h"
#include"crypt.h"
#include<LiDIA/bigint.h>
#include<LiDIA/bigmod.h>

// global variables
long blocksize=20;
point P,dp;
bigint k,q;
bigmod a4, a6,xp,yp;

// FUNCTION : initialization of elliptic curve
// AUTHOR : TH <tedi-h@usa.net>, Feb 2000
void init_ec(const char* pkfile, const char* username)
{
  	FILE* fpk;
	char* suser; 
	char* sa4; 
	char* sa6; 
	char* sq; 
	char* sxp; 
	char* syp; 
	
	if(!(fpk=fopen(pkfile,"r")))
	{
		banner();
		cerr<<"\nAZTECC ERROR : File ["<<pkfile<<"] cannot be opened!\n";
		exit(1);	
	}

	suser=getfield(pkfile,username,1);
	if (suser==NULL)
	{
		banner();
		cerr<<"\nAZTECC ERROR : Username not in public key.\n"<<endl;
		exit(2);
	}

	//--- init ecc parameters ---
	sq=getfield(pkfile,username,Q);

	if (sq == NULL)
  	{	
		banner();
		cerr<<"\nAZTECC ERROR : User's public key not available.\n";
   	exit(3);
  	}

	// set modulus
	string_to_bigint(sq,q);
	bigmod::set_modulus(q);

	if (q.bit_length() == 160)
		blocksize = 20;
  	else if (q.bit_length() == 192)
    	blocksize = 24;
	else
	{
		banner();
    	cerr<<"\nAZTECC ERROR : ";
		cerr<<"\nKey file corrupt: bit length of characteristic not "
			    "160 or 192-bit\n";
    	exit(3);
  	}

	sa4=getfield(pkfile,username,A4);
	string_to_bigmod(sa4,a4);

	sa6=getfield(pkfile,username,A6);
	string_to_bigmod(sa6,a6);

	point::init_curve(a4,a6);

	sxp=getfield(pkfile,username,XP);
	string_to_bigmod(sxp,xp);

	syp=getfield(pkfile,username,YP);
	string_to_bigmod(syp,yp);

	P.set_point(xp,yp);

	if(!P.on_curve())
	{
		banner();
		cerr<<"\nAZTECC ERROR : Point is not on the curve. \n";
		exit(4);
	}
	fclose(fpk);
}


// FUNCTION :
// Encrypt a block of text (20 or 24 chars/block)
//
// Input :
//	text      -> a block of text to be encrypted
//  xkdp      -> x-coordinate of x.d.P
//  fp        -> file pointer to output file
//
// Output : the encrypted text in filename
//
// AUTHOR : TH <tedi-h@usa.net>, 28 Jan 2000
void encrypt_block(unsigned char* text, bigint xkdp, FILE* fp)
{
	unsigned long h;

	for(int i=0;i<blocksize;i+=4)
	{
		h = xkdp.least_significant_digit();
		h ^= ( (unsigned long) text[i] 
			   | (unsigned long) text[i+1] << 8 
		 	 	| (unsigned long) text[i+2] << 16 
				| (unsigned long) text[i+3] << 24);
		
		fprintf(fp,"%c%c%c%c",char(h & 0x000000FF),
						char((h>>8) & 0x000000FF),
						char((h>>16) & 0x000000FF),
						char(h>>24));
		
		xkdp >>= 32;
	}
}


/////////////////////////////////////////////////////////
// FUNCTION :
// Decrypt a block of text (20 or 24 chars/block)
//
// Input :
//	text      -> text to be decrypted
//  xdkp      -> x-coordinate of d.kP
//
// AUTHOR : TH <tedi-h@usa.net>, 28 Jan 2000

void decrypt_block(unsigned char* text, bigint xdkp)
{
	unsigned long h;

	for(int i=0;i<blocksize;i+=4)
	{
		h = xdkp.least_significant_digit();
		h ^= ((unsigned long) text[i] 
			   |(unsigned long) text[i+1] << 8 
				|(unsigned long) text[i+2] << 16 
				|(unsigned long) text[i+3] << 24);

		text[i]   = char(h & 0x000000FF);
      text[i+1] = char((h>>8) & 0x000000FF);
      text[i+2] = char((h>>16) & 0x000000FF);
      text[i+3] = char(h>>24);

		xdkp >>= 32;
	}
}


/////////////////////////////////////////////////////////
// FUNCTION : encrypt a file
// Input :
//  pkfile    -> public key file
//	username  -> encrypt file using this user public key
//  fsrcname  -> file to be encrypted 
//
// AUTHOR : TH <tedi-h@usa.net>, 29 Jan 2000

void encrypt_file(char* pkfile,char* username, char* fsrcname)
{
	banner();

	// open Public Key File
	FILE* fpk;
	if(!(fpk=fopen(pkfile,"r")))
	{
		cerr<<"\nAZTECC ERROR : File ["<<pkfile<<"] cannot be opened.\n";
		exit(1);
	}

	// init elliptic curve
	init_ec(pkfile, username);

	// open input file
	FILE* fin;
	if(!(fin=fopen(fsrcname,"rb")))
	{
		cerr<<"\nAZTECC ERROR : File ["<<fsrcname<<"] cannot be opened.\n";
		exit(2);
	}

	// open output file
	FILE* fout;
	char* fdstname=new char[MAX];
	strncpy(fdstname,fsrcname,strlen(fsrcname)+1);
	strncat(fdstname,".tef",4);
	if(!(fout=fopen(fdstname,"wb")))
	{
		cerr<<"\nAZTECC ERROR : File ["<<fdstname<<"] cannot be opened.\n";
		exit(3);
	}
	
	// write username, filename and filesize to ciphertext
	fprintf(fout,"%s ",username);
	fprintf(fout,"%s ",fsrcname);
	long filesize=fsize(fsrcname);
	fprintf(fout,"%ld",filesize);
	fputc('\n',fout);

	bigmod xdp,ydp;
	
	// get d.P(other user public key) from pubkey file
	char* sxdp; 
	sxdp=getfield(pkfile,username,XDP);
	string_to_bigmod(sxdp,xdp);

	char* sydp; 
	sydp=getfield(pkfile,username,YDP);
	string_to_bigmod(sydp,ydp);

	dp.set_point(xdp,ydp);

	if(!dp.on_curve())
	{
		cerr<<"\nAZTECC ERROR : File ["<<pkfile<<"] may be corrupt.\n";
		exit(4);
	}

	bool has_to_pad=false;
	point H;
	bigint xkp,ykp,xkdp;
	
	cout<<"\nEncrypting file : ["<<fsrcname<<"] "<<endl;
	cout<<"The result will be stored in : ["<<fdstname<<"] "<<endl;
	cout<<"\nProcessing : "<<flush;

  	int blocks_already_done = 0;
	int i;

	// encrypt file
	while(blocks_already_done * blocksize < (int) filesize)
	{
		char buffer[MAX_BSIZE];
		char str1[MAXCHAR], str2[MAXCHAR];

		k=randomize(q);

		// multiply k.P 
		mul_point(H,k,P);							// H = k.P
		
		if(!H.on_curve())
		{
			cerr<<"\nAZTECC ERROR : File ["<<fsrcname<<"] may be corrupt.\n";
			exit(5);
		}

		get_x(xkp,H);									// xkp = X(k.P)
		get_y(ykp,H);									// ykp = Y(k.P)
				
		// store x(kP) to ciphertext
		bigint_to_fixed_string(xkp, str1,blocksize);
		for (i=0; i < blocksize; i++)
		  fputc(str1[i], fout);
		
		// store y(kP) to ciphertext
		bigint_to_fixed_string(ykp, str2,blocksize);
		for (i=0; i < blocksize; i++)
		  fputc(str2[i], fout);
		
		mul_point(H,k,dp);						// k.dP -> k * public_key

		get_x(xkdp,H);         

		// process a block of plaintext, 20/24 chars
		for(i=0;i<blocksize;i++)
		{
			if(!has_to_pad)
			{
				buffer[i]=fgetc(fin);
				if(feof(fin))
					has_to_pad=true;
      }
			else // need padding
				buffer[i]='@';
		} //for

    	blocks_already_done ++;

		encrypt_block((unsigned char*)buffer,xkdp,fout);
      cout<<"."<<flush;
	}//while !feof

	cout<<"\n\nDone encrypting =>"<<fsrcname<<"<="<<endl;
   cout<<"Encrypted file ["<<fdstname<<"]"<<endl;
	fclose(fin);
	fclose(fpk);
	fclose(fout);

	//cleaning up
	delete[] fdstname;
}//encrypt_file


/////////////////////////////////////////////////////////
// FUNCTION : decrypt a file
// Input :
//  pkfile    -> pub key file
//  fsrcname  -> file to be decrypted 
//
// AUTHOR : TH <tedi-h@usa.net>, 29 Jan 2000

void decrypt_file(const char* pkfile, const char* fsrcname)
{
  	unsigned long filesize;

	banner();

	FILE* fin;
	fin=fopen(fsrcname,"rb");
	if(!fin)
	{
		cerr<<"\nAZTECC ERROR : File ["<<fsrcname<<"] cannot be opened !";
		exit(1);
	}

	char* str=new char[MAX2];
	char* username; 
	char* sfilesize; 
	char* filename; 

	fgets(str,MAX,fin);
   username=strtok(str," ");
	filename=strtok(0," ");
	sfilesize=strtok(0," ");

	if(username==NULL || filename ==NULL || sfilesize==NULL)
	{
		cerr<<"\nAZTECC ERROR : File ["<<fsrcname<<"] is not an aztecc file"<<endl;
		exit(1);
	}

	filesize=atol(sfilesize);
	
	char* foutname=new char[MAX];
	
	strncpy(foutname,filename,strlen(filename)+1);
	strncat(foutname,".out",4);

	init_ec((char*)pkfile,username);

	// make temporary file
	FILE* ftemp;
	if(!(ftemp=fopen(foutname,"wb")))
	{
		cerr<<"\nAZTECC ERROR : File ["<<foutname<<"] cannot be opened.\n";
		exit(3);
	}

	point kp,H;
	bigint d,xdkp,xkp,ykp;
	int c;
	long index_block=0;

	char* buf1=new char[MAX_BSIZE];		// store x(kP)
	char* buf2=new char[MAX_BSIZE];		// store y(kP)

	get_passphrase(d,blocksize,username);		// get priv key

	char* sd=new char[MAX];
	char* hash_d_pk;
	bigint_to_string(d,sd);
	char* hash_d=new char[MAX];
	hash_d=MD5_hex_digest(sd);
	hash_d_pk=getfield(pkfile,username,HASH_D);

	// hash_d is not the same as hash_d_pk
	if(strcmp(hash_d,hash_d_pk) != 0)
	{
		cerr<<"\nAZTECC ERROR : You've entered wrong passphrase.\n";
		exit(1);
	}

	// show information
	cout<<"\nDecrypting file : ["<<fsrcname<<"] "<<endl;
	cout<<"Result will be stored in : ["<<foutname<<"]"<<endl;
	cout<<"\nProcessing : "<<flush;

	int i;
	// decrypt ciphertext 
	c=fgetc(fin);
	while(c != EOF)
	{
		unsigned char buffer[MAX_BSIZE];

		ungetc(c,fin);

		// get xkp
		for(i=0;i<blocksize;i++)
		{
			if(!feof(fin))
				buf1[i]=fgetc(fin);
			else
			{
	      	cerr<<"\nAZTECC ERROR : Error reading file : ["<<fsrcname<<"]"<<endl;
	      	exit(5);
	    	}
		}

		fixed_string_to_bigint(buf1,xkp,blocksize);
		
		// get ykp
		for(i=0;i<blocksize;i++)
		{
			if(!feof(fin))
				buf2[i]=fgetc(fin);
			else
			{
	      	cerr<<"\nAZTECC ERROR : Error reading file : ["<<fsrcname<<"]"<<endl;
	      	exit(6);
	    	}
		}
		
		fixed_string_to_bigint(buf2,ykp,blocksize);
	
		kp.set_point(bigmod(xkp),bigmod(ykp));					// set the point

		if(!kp.on_curve())
		{
			cerr<<"\nAZTECC ERROR : File ["<<fsrcname<<"] may be corrupt.\n";
			exit(7);
		}

		mul_point(H,d,kp);

		if(!H.on_curve())
		{
			cerr<<"\nAZTECC ERROR : File ["<<fsrcname<<"] may be corrupt.\n";
			exit(8);
		}
		
		get_x(xdkp,H);		
		
		// decrypt a block of message app.20/24 chars
		for(i=0;i<blocksize;i++)
		{
			if(!feof(fin))
				buffer[i]=fgetc(fin);
		}
		
		decrypt_block((unsigned char*)buffer,xdkp);
		
		// write decrypted text to file
		for (i=0; i< blocksize; i++)
		{
			if ((unsigned long)(index_block*blocksize + i) < filesize)
				fputc(buffer[i], ftemp);
		}
      
    	index_block++;

		cout<<"."<<flush;
		c = fgetc(fin);
	}//while !feof

	cout<<"\n\nDone decrypting =>"<<fsrcname<<"<="<<endl;
	cout<<"Decrypted file ["<<foutname<<"]"<<endl;
	fclose(fin);
	fclose(ftemp);

	//cleaning up
	delete[] str;
	delete[] foutname;
	delete[] buf1;
	delete[] buf2;
}//decrypt_file
