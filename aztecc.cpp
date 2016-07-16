/////////////////////////////////////////////////////
// aztecc.cpp                                     
//                                                
// This is the main module for AZTEC program.     
// It controls the command line arguments entered 
// by user, and other management stuffs.          
//                                                
// For copying/modifying/distributing see license.txt      
// Version : $1.0.0.$February 15,2000
/////////////////////////////////////////////////////

#include"aztecc.h"
#include"crypt.h"
#include"utils.h"
#include<LiDIA/timer.h>

bool bencrypt, bdecrypt, bgen_pk, bfind_point, btest_point;
bool buser,bfile,bwipe_file, bhelp, bversion, bks;

char* keysize="160";
char* filename=new char[MAX];
char* username=new char[MAX];
char* pubkey="pubkey.pk";

void usage(void)
{
 banner();
 cout<<"\n"<<manual;
}

bool is_option(const char* option)
{
  if((option[0]=='-') || ((option[0]=='-') && (option[1]=='-')))
    return 1;
  else
    return 0;
}

void version(void)
{
	cout<<"AZTECC 1.0.0. Copyright(c) 2000 by Tedi Heriyanto.\n";
	cout<<"URL http://www.linuxstart.com/tdh/\n\n";
}

int main(int argc, char *argv[])
{
	timer t;

	t.set_print_mode(HMS_MODE);

	bencrypt=false;
	bdecrypt=false;
	bgen_pk=false;
	bfind_point=false;
	btest_point=false;
	bwipe_file=false;
	bhelp=false;
	bfile=false;
	buser=false;
	bversion=false;
	bks=false;

	for(int i=1;i<argc;i++)
	{
  		if((strcmp(argv[i],"-e")==0) || (strcmp(argv[i],"--encrypt")==0))
    	{
	      if (i+1 < argc)
				if(!is_option(argv[i+1]))
		  		{
		    		bencrypt=true;
		    		filename=argv[i+1];
				   bfile=true;
		    		i++;
		    		continue;
		  		}
			banner();
	      cerr<<"\nAZTECC ERROR : No filename given."<<endl;
	      exit(1);
	    }
	  
	  if((strcmp(argv[i],"-d")==0) || (strcmp(argv[i],"--decrypt")==0))
	  {
	  		if (i+1 < argc)
				if(!is_option(argv[i+1]))
		  		{
		    		bdecrypt=true;
		    		filename=argv[i+1];
		    		bfile=true;
		    		i++;
		    		continue;
		  		}
	      banner();
	      cerr<<"\nAZTECC ERROR : No filename given."<<endl;
	      exit(1);
    }
	  
	  if((strcmp(argv[i],"-g")==0) || (strcmp(argv[i],"--genkey")==0))
	    	bgen_pk=true;
	  
	  if((strcmp(argv[i],"-k")==0) || (strcmp(argv[i],"--keysize")==0))
	  {
	  		if (i+1 < argc)
				if(!is_option(argv[i+1]))
		  		{
		    		bks=true;
		    		keysize=argv[i+1];
		    		i++;
		    		continue;
		  		}
			banner();
	      cerr<<"\nAZTECC ERROR : No valid keysize given."<<endl;
	      exit(1);
	    }
	  
	  if((strcmp(argv[i],"-u")==0) || (strcmp(argv[i],"--user")==0))
     {
	  		if (i+1 < argc)
				if(!is_option(argv[i+1]))
		  		{
		    		username=argv[i+1];
		    		buser=true;
		    		i++;
		    		continue;
		  		}
			banner();
	      cerr<<"\nAZTECC ERROR : No valid username given."<<endl;
	      exit(1);
	  }
	  
	  if((strcmp(argv[i],"-pk")==0) || (strcmp(argv[i],"--pubkey")==0))
	  {
	  		if(!is_option(argv[i+1]))
			{
		  		pubkey=argv[i+1];
		  		i++;
		  		continue;
			}
			banner();
	      cerr<<"\nAZTECC ERROR : No public key filename given."<<endl;
	      exit(1);
	  }

		// find and test point
	  if((strcmp(argv[i],"-f")==0) || (strcmp(argv[i],"--find")==0))
	    bfind_point=true;
	  if((strcmp(argv[i],"-t")==0) || (strcmp(argv[i],"--test")==0))
	    btest_point=true;
	  
	  if((strcmp(argv[i],"-h")==0) || (strcmp(argv[i],"--help")==0))
	    bhelp=true;
	  if((strcmp(argv[i],"-v")==0) || (strcmp(argv[i],"--version")==0))
	    bversion=true;
	  if((strcmp(argv[i],"-w")==0) || (strcmp(argv[i],"--wipe")==0))
	  {
	  		if (i+1 < argc)
				if(!is_option(argv[i+1]))
		  		{
		    		filename=argv[i+1];
		    		bwipe_file=true;
		    		bfile=true;
		    		i++;
		    		continue;
		  		}
			banner();
	      cerr<<"\nAZTECC ERROR : No filename given."<<endl;
	      exit(1);
	    }
	}

	if((bencrypt) && (buser) && (bfile) && (!bdecrypt) && 
	   (!bgen_pk) && (!bfind_point) && (!btest_point) && 
	   (!bhelp) && (!bwipe_file) && (!bversion) && (!bks))
	{
		 t.start_timer();
	    encrypt_file(pubkey,username,filename);
		 t.stop_timer();
		 cout<<"\nElapsed time : "<<t<<endl;
	    exit(0);
	}
	
	if((bdecrypt) && (bfile) && (!buser) && (!bencrypt) && 
		(!bgen_pk) && (!bfind_point) && (!btest_point) &&
 		(!bhelp) && (!bwipe_file) && (!bversion) && (!bks))
	{
		 t.start_timer();
	    decrypt_file(pubkey,filename);
		 t.stop_timer();
		 cout<<"\nElapsed time : "<<t<<endl;
	    exit(0);
	}
	
	if((bgen_pk) && (bks) && (!buser) && (!bencrypt) && (!bdecrypt) && 
	   (!bfind_point) && (!btest_point) && (!bhelp) && (!bwipe_file) && (!bversion))
	{
	    if(strcmp(keysize,"160")==0)
	      blocksize=20;
	    else if(strcmp(keysize,"192")==0)
	      blocksize=24;
	    else
	    {
			banner();
			cerr<<"\nAZTECC ERROR : Keysize not valid.\n";
			exit(1);
	    }
	    
	    gen_pubkey(pubkey,blocksize);
	    exit(0);
	}
	
	if((bfind_point) && (!bencrypt) && (!bdecrypt) && (!bgen_pk) && 
	   (!btest_point) && (!bhelp) && (!bwipe_file) && (!bversion) &&
   	(!buser) && (!bks))
	{
			find_point();
			exit(0);
	}
	
	if((btest_point) && (!bencrypt) && (!bdecrypt) && (!bgen_pk) && 
		(!bfind_point) && (!bhelp) && (!bwipe_file) && (!bversion) &&
		(!buser) && (!bks))
	{
			test_point();
			exit(0);
	}

	if((bwipe_file) && (bfile) && (!bencrypt) && (!bdecrypt) && (!bgen_pk) && 
		(!bfind_point) && (!btest_point) && (!bhelp) && (!bversion) &&
     	(!buser) && (!bks))
	{
			wipe_file(filename);
			exit(0);
	}


	if((bversion) && (!bencrypt) && (!bdecrypt) && (!bgen_pk) && 
		(!bfind_point) && (!btest_point) && (!bhelp) && (!bwipe_file) &&
		(!buser) && (!bks))
	{
			version();
			exit(0);
	}

	if(bhelp)
	{
		usage();
		exit(0);
	}
  
  else
    usage();			
  return 0;
}
