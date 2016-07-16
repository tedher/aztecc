/////////////////////////////////////////////////////
// This file contains numerous functions to be used
// by AZTECC
//
// Version : $1.0.0.$February 15,2000
//
// AUTHOR : TH <tedi-h@usa.net>
// For copying/modifying/distributing see license.txt
/////////////////////////////////////////////////////

#include"utils.h"
#include"ecc.h"
#include"md5.h"
#include"crypt.h"
#include<string.h>  
#include<ctype.h>   // for isdigit

#ifdef __unix__
#include <termios.h>
#else
#include <conio.h>
#endif

const char PKFILENAME[]="pubkey.pk";

// FUNCTION : displaying program information
void banner(void)
{
	cout<<header;
}


// FUNCTION : get a field from a file with username as the key
// The fields are separated using '#'
//
// Input  : filename
//          username
//          field number
// Output : content of the requested field
//
// EXAMPLE :
// The public key file has the following structure :
//   username#hash(dP)#a4#a6#xP#yP#xdP#ydP#q
// To get the second field :
//        char* tmp=new char;
//        tmp=getfield("pubkey.pk","tedi-h@usa.net",1);
//
// CONSTRAINTS :
// - field number must be exist 
// AUTHOR : TH <tedi-h@usa.net>, Last debug : 11 Feb 2000.
char* getfield(const char *filename, const char* username, int fieldnum)
{
	FILE* infile;
	infile=fopen(filename,"r");
  	if(!infile)
  	{
   	cerr<<"Error opening file ["<<filename<<"]"<<endl;
   	exit(1);
  	}

	char* result=NULL; 
  	char line[MAX];
	int nfield=1;
  	while(!feof(infile))
  	{
		fgets(line,MAX,infile);
			
		result=strtok(line,SEP);

		// username found
		if(strcmp(username,result) == 0)
		{
			while (nfield < (fieldnum+1)) 
			{
				result=strtok(0,SEP);
				nfield++;
			}
			break;
		}
		
		// username not found
		else
		{
			result=NULL;
			continue;
		}
	}
	fclose(infile);
	return (result);
}

// FUNCTION : Convert a string with blocksize char to bigint
// 
// Input  : string s, number of chars in a block
// Output : a bigint x
//
// AUTHOR : TH <tedi-h@usa.net>, Jan 2000
void str2bigint(char* s, const int blocksize, bigint& x)
{
	ULONG h;

	x=0;
	for(int i=0;i<blocksize;i+=4)
	{
		h=  ((ULONG) s[i] << 24) | ((ULONG) s[i+1] << 16) 
		  | ((ULONG) s[i+2] << 8)| ((ULONG) s[i+3]);
		x<<=32;
		x|=h;
	}
}

///////////////////////////////////////////////
//FUNCTION : check if the user entered a number
//
//Output : true  -> if a number
//         false -> if not a number
//Author : TH <tedi-h@usa.net>
///////////////////////////////////////////////
bool is_number(const char* str)
{
  unsigned int len;

  len=strlen(str);

  int c;
  for(unsigned int i=0;i<len;i++)
  {
   c=(int)str[i];
   if (!isdigit(c))
     return 0;
  }
  return 1;
}

/////////////////////////////////////////////////////
// FUNCTION : get elliptic curve parameter from user
/////////////////////////////////////////////////////
void get_ecparm(bigmod& aa4, bigmod&aa6, bigmod& axp, bigmod& ayp, bigint& aq)
{
	bigmod a4,a6,xp,yp;
	bigint q;
		
	char* sa4=new char[MAX];
	char* sa6=new char[MAX];
	char* sq=new char[MAX];
	char* sxp=new char[MAX];
	char* syp=new char[MAX];

	do
	{
		cout<<"Please enter prime field (p).";
		cout<<"It should be 160 or 192-bit : \n";
		cin>>sq;
	   string_to_bigint(sq,q);
	} while((!is_prime(q)) || ((q.bit_length() != 160) &&
  		(q.bit_length() != 192)));

	bigmod::set_modulus(q);
	cout<<"\nPlease input numbers to the following :"<<endl;

	do
	{	
		cout<<"Coefficient a : ";cin>>sa4;
	} while(!is_number(sa4));
 	
	do
	{	
		cout<<"Coefficient b : ";cin>>sa6;
	} while(!is_number(sa6));

	do
	{	
		cout<<"X-coordinate : ";cin>>sxp;
	} while(!is_number(sxp));

	do
	{
		cout<<"Y-coordinate : ";cin>>syp;
	} while(!is_number(syp));


	string_to_bigmod(sa4,a4);
	string_to_bigmod(sa6,a6);
	string_to_bigmod(sxp,xp);
	string_to_bigmod(syp,yp);

  	bigmod h;

  	h = yp * yp - (xp*xp + a4)*xp - a6;

	// check on curve
  	if (h != 0)
  	{
     cerr<<"\nAZTECC ERROR : P is not on curve\n";
     exit(1);
  	}

	// returning the parameters
	aa4=a4;
	aa6=a6;
	axp=xp;
	ayp=yp;
	aq=q;

	delete[] sa4;
	delete[] sa6;
	delete[] sxp;
	delete[] syp;
}


/////////////////////////////////////////////////////
// FUNCTION : get user private key
//
// Input  : char* username
// Output : bigint d -> user private key
/////////////////////////////////////////////////////
void get_passphrase(bigint& d, int blocksize, const char* username)
{
	int c,i=0;
	char passphrase[MAX2];		// max size 2047 chars
	
	cout<<"\nINPUT PASSPHRASE :";
	cout<<"\n------------------";
	cout<<"\nHello =>"<<username<<"<= please enter your passphrase (up to "<<MAX2<<" chars)";
	cout<<"\nThis is your PRIVATE KEY. Do not forget it.";
	cout<<"\n\nWhen you're done, press <ENTER>."<<endl;
	cout<<"Begin entering your passphrase ==>"<<endl;

#ifdef __unix__
	struct termios terminal;
	
	tcgetattr(0,&terminal);
	terminal.c_lflag &= ! ECHO;
	tcsetattr(0,TCSANOW,&terminal);
#endif
	
#ifdef __unix__
	c = getchar();
	if(c != '\n')
#else
	c = getch();
	if(c != '\r') 
#endif
    	ungetc(c, stdin);

	i=0;
#ifdef __unix__
	while((c=getchar()) != '\n')
#else
	while((c=getch()) != '\r')
#endif
	{
		cout<<"*"<<flush;
		passphrase[i]=c;
		i++;
		if(i>=MAX2)
		{
			cerr<<"\nAZTECC ERROR : Ooopss...passphrase too long. Aborting."<<endl;
			exit(1);
		}
	}
	passphrase[i]='\0';

#ifdef __unix__
	terminal.c_lflag |= ECHO;
	tcsetattr(0,TCSANOW,&terminal);
#endif

	// hash #1 passphrase
	unsigned char* str1=new unsigned char[16];
	str1= MD5_raw_digest(passphrase);
	
	// save to buffer
	unsigned char* buffer=new unsigned char[32];
	for(i=0;i<16;i++)
		buffer[i]=str1[i];
	
	// hash #2 passphrase
	unsigned char* str2=new unsigned char[16];
	strncpy((char*)str2,(char*)str1, strlen((char*)str1));
	strncat((char*)str2,"aaa",3);
	str2=MD5_raw_digest((char*)str2);
	
	// save to buffer
	for(i=16;i<32;i++)
		buffer[i]=str2[i-16];
	
	// convert to bigint
	bigint priv_key;
	str2bigint((char*)buffer,blocksize,priv_key);
	d=priv_key;

	//cleaning up
	delete[] str1;
	delete[] str2;
	delete[] buffer;
}


/////////////////////////////////////////////////////
// FUNCTION : find a point on an elliptic curve
//
// Output : a point on an elliptic curve
// 
// AUTHOR : TH <tedi-h@usa.net>, Feb 2000
/////////////////////////////////////////////////////

void find_point()
{
	bigmod h,x;
	bigint q,a4,a6,y;
	
	char* sa4=new char[MAX];
	char* sa6=new char[MAX];
	char* sq=new char[MAX];
	
	banner();
	cout<<"\nFIND POINT";
	cout<<"\n----------";
	do
	{
		cout<<"\nPlease enter prime field (p).";
     	cout<<"Its length should be 160 or 192-bit : \n";
      cin>>sq;
		string_to_bigint(sq,q);
	} while((!is_prime(q)) || ((q.bit_length() != 160) && 
     (q.bit_length()!=192)));
	bigmod::set_modulus(q);

	cout<<"\nPlease input numbers to the following : "<<endl;
	do
	{
		cout<<"Coefficient a = ";cin>>sa4;
	} while(!is_number(sa4));

	do
	{
		cout<<"Coefficient b = ";cin>>sa6;
	} while(!is_number(sa6));

	string_to_bigint(sa4,a4);
	string_to_bigint(sa6,a6);

	q=next_prime(q-1);

	do
	{
		x.randomize();
		h = (x*x+a4)*x+a6;
	} while(jacobi(h.mantissa(),q) !=1);

	ressol_p(y,h.mantissa(),q);

	cout<<"Point P : ("<<x<<","<<y<<")"<<endl;

	delete[] sa4;
	delete[] sa6;
}


/////////////////////////////////////////////////////
// FUNCTION : test if a point is on an elliptic curve
//
// AUTHOR : TH <tedi-h@usa.net>, Feb 2000
/////////////////////////////////////////////////////

void test_point()
{
	bigmod h,x,y;
	bigint q,a4,a6;

	char* sa4=new char[MAX];
	char* sa6=new char[MAX];
	char* sq=new char[MAX];
	char* sx=new char[MAX];
	char* sy=new char[MAX];

	banner();
	cout<<"\nTEST POINT";
	cout<<"\n----------";
	
	do
	{
		cout<<"\nPlease enter prime field (p).";
   	cout<<"Its length should be 160 or 192-bit : \n";
		cin>>sq;
		string_to_bigint(sq,q);
	} while((!is_prime(q)) || ((q.bit_length() != 160) &&
  		(q.bit_length() != 192)));
	bigmod::set_modulus(q);

	cout<<"\nPlease input numbers to the following : "<<endl;
	
	do
	{
		cout<<"Coefficient a = ";cin>>sa4;
	} while(!is_number(sa4));

	do
	{
		cout<<"Coefficient b = ";cin>>sa6;
	} while(!is_number(sa6));

	do
	{
		cout<<"X-coordinate = ";cin>>sx;
	} while(!is_number(sx));

	do
	{
		cout<<"Y-coordinate = ";cin>>sy;
	} while(!is_number(sy));

	string_to_bigint(sa4,a4);
	string_to_bigint(sa6,a6);
	string_to_bigmod(sx,x);
	string_to_bigmod(sy,y);

	h=y*y-(x*x+a4)*x-a6;
	
	if (h==0)
	{
		cout<<"\nPoint ("<<x<<","<<y<<") is on the curve.\n";
		exit(0);
	}
	else
	{
		cout<<"\nPoint ("<<x<<","<<y<<") is not on the curve.\n";
		exit(0);
	}

	delete[] sa4;
	delete[] sa6;
	delete[] sx;
	delete[] sy;
}


// FUNCTION : generate a public key
//
// Input : username, 
//         a4, a6 -> elliptic curve constants
//         xp, yp -> point's coordinate
//				 prime field
//         passphrase
// Output : file username.pkf which contains all
//          of those information
// 
// AUTHOR : TH <tedi-h@usa.net>, Jan 2000
//
void gen_pubkey(const char* pkfilename, int blocksize)
{
	// declaration of variables
	char username[MAX];
	point P,H;
	bigmod a4,a6,xp,yp;
	bigint xdp,ydp,q;

	banner();
	cout<<"Before you can use encryption/decryption you must generate your public key.";
	cout<<"\nThe following process will guide you through generating your public key.";
	cout<<"\n\nTo achieve a cryptographically secure elliptic curve cryptosystem, you must ";
	cout<<"\nsupply a relatively big prime finite field (q), a good a, b";
	cout<<"\nfor elliptic curve equation and a point that lies on the curve.";

	//get EC parameters from user
	cout<<"\n\nGENERATE PUBLIC KEY\n";
	cout<<"-------------------";
	cout<<"\nPlease enter your user name : ";cin>>username;
		
	get_ecparm(a4,a6,xp,yp,q);
	
	// EC initialization
	P.init_curve(a4,a6);
	P.set_point(xp,yp);

	if (pkfilename==" ")
		pkfilename=PKFILENAME;

	// open public key file
	FILE* pkfile;
	pkfile=fopen(pkfilename,"a+");
	if(!pkfile)
	{
		cout<<"\nAZTECC ERROR : Error writing file ["<<pkfilename<<"]"<<endl;
		exit(1);
	}
	
	bigint d;
	get_passphrase(d,blocksize,username);
	
	// multiply the private key with EC point
	mul_point(H,d,P);
	
	// compute hash(d)
	char* sd=new char[MAX];
	bigint_to_string(d,sd);
	char* hash_d=new char[MAX];
	hash_d=MD5_hex_digest(sd);
	
	// convert the EC coordinate to string
	get_x(xdp,H);
	char* sxdp=new char[MAX];
	bigint_to_string(xdp,sxdp);
	get_y(ydp,H);
	char* sydp=new char[MAX];
	bigint_to_string(ydp,sydp);

	// convert a4, a6, xp, yp to string
	char* sa4=new char[MAX];
	bigmod_to_string(a4,sa4);
	char* sa6=new char[MAX];
	bigmod_to_string(a6,sa6);
	char* sxp=new char[MAX];
	bigmod_to_string(xp,sxp);
	char* syp=new char[MAX];
	bigmod_to_string(yp,syp);
	char* sq=new char[MAX];
	bigint_to_string(q,sq);
	
	// save all the info to public key file
   fputc('\n',pkfile);
	fprintf(pkfile,"%s#%s#%s#%s#%s#%s#%s#%s#%s",username,hash_d,sa4,sa6,sxp,syp,sxdp,sydp,sq);
	fclose(pkfile);
	cout<<"\nDone saving your public key to ["<<pkfilename<<"]"<<endl;

	//cleaning up
	delete[] sd;
	delete[] sxdp;
	delete[] sydp;
	delete[] sa4;
	delete[] sa6;
	delete[] sxp;
	delete[] syp;
	delete[] sq;
}


// FUNCTION : return fname size
//
// CONSTRAINT : only able to count filesize up to 2^32 bytes
// AUTHOR : TH <tedi-h@usa.net>, Last debugged : Feb 11, 2000
//
long fsize(const char* fname)
{
	long filesize;

	ifstream fin(fname,ios::in||ios::binary);
	if(!fin)
		return -1;
	else
	{
		fin.seekg(0,ios::end);
		filesize=fin.tellg();
		fin.seekg(0,ios::beg);
		fin.close();
		return filesize;
	}
}


// FUNCTION : convert from a fixed string to bigint
// Input :
//	bigint x
//  int blocksize
// 
// Output :
//  char* str
//
// AUTHOR : TH <tedi-h@usa.net>, 27 Jan 2000

void bigint_to_fixed_string(bigint x, char* str, int blocksize)
{
  unsigned long hh;

  for(int i=0;i<blocksize;i++)
    {
      hh = x.least_significant_digit();
      str[i] = (char) hh & 0x000000FF;
      x >>= 8;
    }
  str[blocksize]='\0';
}


/////////////////////////////////////////////////////////
// FUNCTION : convert from a fixed string to bigint
// Input :
//	char* str
//  int blocksize
// 
// Output :
//  bigint x
//
// AUTHOR : TH <tedi-h@usa.net>, 27 Jan 2000

void fixed_string_to_bigint(const char* str,bigint& x, int blocksize)
{
	x=0;
	for(int i=blocksize-1;i>0;i--)
	{
		x+=(long)(unsigned char) str[i];
		x <<= 8;
	}
	x += (long)(unsigned char) str[0];
}


/////////////////////////////////////////////////////////
// FUNCTION : wipe a file
// Input :
//	char* victim
//
// Output :
//  victim file wiped
//
// AUTHOR : TH <tedi-h@usa.net>, 30 Jan 2000

void wipe_file(char* victimfile)
{
	FILE* fvictim;
	unsigned long filesize;

	filesize=fsize(victimfile);

	fvictim=fopen(victimfile,"wb");
	if(!fvictim)
	{
		banner();
		cout<<"\nAZTECC ERROR : Error opening file ["<<victimfile<<"]"<<endl;
		exit(1);
	}

	for(unsigned int i=0;i<filesize+1;i++)
		fputc(' ',fvictim);

	fclose(fvictim);
	remove(victimfile);
}
