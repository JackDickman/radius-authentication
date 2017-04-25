AUTHOR:		Jack Dickman
LAST UPDATED:	April 24, 2017
PROJECT:	CSC424 Radius Authentication

Description:	The program runs as either client or server, depending on the whether the -h option is present. 
		If server, the password-file is opened and the servers listens on a listen port number given 
		after the -p flag. If client, the username and password given after the -h flag are authenticated
		to the server, and YES or NO is printed.
		
Targets:	build, test-server, test-client, clean

Usage:		mradius [-vR -k shared-key -p port] -h host username password
    		mradius [-vLR -k shared-key -p port] password-file

Options:	-k the shared key for encrypting, the default is pa55word0
		-p the port the server listens (is listening) on, the default is 1812
		-h the radius server hostname
		-v Verbose. Helpful debugging output to stdout. 
		-R no randomness. The stream of random bytes used by the program is set to 1, 2, 3, ...
		-L when run as a server, do not loop; answer one full request and terminate
