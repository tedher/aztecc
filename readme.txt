README for AZTECC v.1.0.0 (binary version) 
------------------------------------------ 

Introduction
------------

AZTECC is an implementation of elliptic curve cryptosystem. This program 
has a command line interface. 

AZTECC has the following capabilities :
- Generate   : to generate public key
- Encryption : to encrypt a file.
- Decryption : to decrypt a file.
- Find Point : to find a point on an elliptic curve.
- Test Point : to test if a point is really on the elliptic curve.
- Wipe File  : to wipe a file.

Installation & Uninstallation under Linux/Windows
-------------------------------------------------

Under Linux
~~~~~~~~~~~
To install  : 
copy the executable (aztecc) to your directory.

tdh $ mkdir aztecc
tdh $ cd aztecc
tdh $ mount -t vfat /dev/fd0 /mnt/floppy
tdh $ cp /mnt/floppy/aztecc100bl.tgz .
tdh $ tar xvzf aztecc100bl.tgz
tdh $ umount /mnt/floppy

The binary file and all of the related stuffs are in ~/aztecc/bin/
Note: you must have permission to do mount/umount.

To uninstall: 
delete the executable from your directory.

tdh $ cd aztecc/bin
tdh $ rm aztecc


Under Windows 9x
~~~~~~~~~~~~~~~~
To install : copy the executable to your directory
c:\> md aztecc
c:\> cd aztecc
c:\> copy a:\aztecc100bw.exe .
c:\> aztecc100bw
The binary file and all of the related stuffs are in c:\aztecc\bin\

To uninstall : delete the aztecc directory
c:\> deltree aztecc

Usage :
-------

For usage information, please see the help.

Detailed information can be found on my final project paper.

You can get it from :
http://students.ukdw.ac.id/~22941219/ (valid until May 2000)
http://www.linuxstart.com/~tdh/       (valid from March 2000) 

I have also included two public key files, one for 160-bit keysize and 
the other is for 192-bit keysize. The filenames are "pubkey160.pk" and
"pubkey192.pk". To use it as your own  public key, rename  one of them
to "pubkey.pk". Those files  contains two  username, tedi and tdh, for
tedi the passphrase is "test"  while for tdh the passphrase is "demo".


The Future
----------

If I have enough spare time, these are the to do list :
- Combine elliptic curve cryptosystem (ECC) with RC6, so the 
  encryption/decryption process will be faster. The proposed plan is : 
  the ECC will be used as a key management, while the RC6 will be used 
  in encryption/decryption.
- Do some optimizations, especially for speed.
- Fixed more bugs.
- Enhanced the user interface, may be adding GUI.

Bugs and Optimization
---------------------

This software is still in beta version, please beware that there many 
bugs in it. I have tried hard to eliminate many bugs, but may be there 
are still some errors. If you find bugs in this program, please let me know.

This program is for academic purposes only, so I don't optimize it. 
Do not compare it with a professional program.


History :
---------

25 Jan 2000, v0.9.4 : fixed decoding_file routine
30 Jan 2000, v0.9.8 : able to handle binary file
                      slightly enhanced the user interface
31 Jan 2000, v0.9.9 : public release (Windows Binary Version)
10 Feb 2000, v0.9.11: 
   -fixed wipe_file function
   -fixed memory usage
   -fixed user interface
   -added this file.
11 Feb 2000, v0.9.12:
   -modify some error messages to be more reasonable
   -added facilities to differentiate ciphertext & plaintext
   -added passphrase checking
15 Feb 2000, v1.0.0: stable version
   -fixed command line parsing bugs
   -modified user interface (help)
   -modified gen_passphrase to not echoing the passphrase
     

Acknowledgements :
-----------------

- GOD, who help me programmed.
- Dr. Volker Mueller, Dipl.Inf., my technical advisor.  
- The LiDIA team, Faculty of Informatics, TU-Darmstadt, Jerman. 
  <www.informatik.tu-darmstadt.de/TI/LiDIA/>
- The Institute for Electrical and Electronics Engineers, especially 
  the P1363 Working Group <http://grouper.ieee.org/groups/1363/>
- Certicom, Inc. <www.certicom.com>
- Robert Hoffer, TU-Graz, Austria.
  <http://www.sbox.tu-graz.ac.at/home/j/jonny/projects/crypto/index.htm>
- Eric de Win and Bart Preneel, Katholieke Universiteit Leuven.
- Center for Applied Cryptographic Research, Univ. of Waterloo, Canada
  <http://cacr.math.uwaterloo.ca>


Licensing
---------

If you want to use a part or a whole AZTECC program, see license.txt.


Author
------
Tedi Heriyanto <tedi-h@usa.net>
15 February 2000
