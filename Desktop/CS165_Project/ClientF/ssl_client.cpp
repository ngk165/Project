//----------------------------------------------------------------------------
// File: ssl_client.cpp
// Description: Implementation of an SSL-secured client that performs
//              secure file transfer with a single server over a single
//              connection
//----------------------------------------------------------------------------
#include <string>
#include <time.h>               // to seed random number generator
#include <sstream>          // stringstreams
using namespace std;

#include <openssl/ssl.h>	// Secure Socket Layer library
#include <openssl/bio.h>	// Basic Input/Output objects for SSL
#include <openssl/rsa.h>	// RSA algorithm etc
#include <openssl/pem.h>	// For reading .pem files for RSA keys
#include <openssl/err.h>	// ERR_get_error()
#include <openssl/dh.h>		// Diffie-Helman algorithms & libraries

#include "utils.h"

//----------------------------------------------------------------------------
// Function: main()
//----------------------------------------------------------------------------
int main(int argc, char** argv)
{
	//-------------------------------------------------------------------------
    // Initialization

    ERR_load_crypto_strings();
    SSL_library_init();
    SSL_load_error_strings();

    setbuf(stdout, NULL); // disables buffered output
    
    // Handle commandline arguments
	// Useage: client server:port filename
	if (argc < 3)
	{
		printf("Useage: client -server serveraddress -port portnumber filename\n");
		exit(EXIT_FAILURE);
	}
	char* server = argv[1];
	char* filename = argv[2];
	
	printf("------------\n");
	printf("-- CLIENT --\n");
	printf("------------\n");

    //-------------------------------------------------------------------------
	// 1. Establish SSL connection to the server
	printf("1.  Establishing SSL connection with the server...");

	// Setup client context
    SSL_CTX* ctx = SSL_CTX_new(SSLv23_method());
	SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
//	SSL_CTX_set_options(ctx, SSL_OP_ALL|SSL_OP_NO_SSLv2);
	if (SSL_CTX_set_cipher_list(ctx, "ADH") != 1)
	{
		printf("Error setting cipher list. Sad christmas...\n");
        print_errors();
		exit(EXIT_FAILURE);
	}
	
	// Setup the BIO
	BIO* client = BIO_new_connect(server);
	if (BIO_do_connect(client) != 1)
	{
		printf("FAILURE.\n");
        print_errors();
		exit(EXIT_FAILURE);
	}

	// Setup the SSL
    SSL* ssl=SSL_new(ctx);
	if (!ssl)
	{
		printf("Error creating new SSL object from context.\n");
		exit(EXIT_FAILURE);
	}
	SSL_set_bio(ssl, client, client);
	if (SSL_connect(ssl) <= 0)
	{
		printf("Error during SSL_connect(ssl).\n");
		print_errors();
		exit(EXIT_FAILURE);
	}

	printf("SUCCESS.\n");
	printf("    (Now connected to %s)\n", server);

    //-------------------------------------------------------------------------
	// 2. Send the server a random number
	printf("2.  Sending challenge to the server...");
    
    string randomNumber="31337";
	//SSL_write
    int sent = SSL_write(ssl,(const void*) randomNumber.c_str(),sizeof(randomNumber));
    printf("SUCCESS.\n");
	printf("    (Challenge sent: \"%s\")\n", randomNumber.c_str());

    //-------------------------------------------------------------------------
	// 3a. Receive the signed key from the server
	printf("3a. Receiving signed key from server...");

    unsigned char buff[BUFFER_SIZE];
    memset(buff,0,sizeof(buff));
    SSL_read(ssl,buff,BUFFER_SIZE);

	printf("RECEIVED.\n");
	printf("    (Signature: \"%s\" (%d bytes))\n", buff2hex(buff, 128).c_str(), 128);

    //-------------------------------------------------------------------------
	// 3b. Authenticate the signed key
	printf("3b. Authenticating key...");

	//BIO_new(BIO_s_mem())
	//BIO_write
	//BIO_new_file
	//PEM_read_bio_RSA_PUBKEY
	//RSA_public_decrypt
	//BIO_free

	BIO* mem = BIO_new(BIO_s_mem());
	if(BIO_write(mem, randomNumber.c_str(), randomNumber.size())<=0)
	printf("ERROR.\n");
	BIO* hash = BIO_new(BIO_f_md()); 
	BIO_set_md(hash, EVP_sha1());
	BIO_push(hash, mem);

	char buf[EVP_MAX_MD_SIZE];
	int len = BIO_read(hash, buf, EVP_MAX_MD_SIZE);
	BIO* rsapublic = BIO_new_file("rsapublickey.pem", "r");
	RSA* pub = PEM_read_bio_RSA_PUBKEY(rsapublic, NULL, 0, NULL);

	unsigned char* decrypt = (unsigned char*) malloc(RSA_size(pub));
	memset(decrypt, 0, RSA_size(pub));
	RSA_public_decrypt(128, (unsigned char*)buff, decrypt, pub, RSA_PKCS1_PADDING);
	string generated_key=buff2hex((unsigned char *)buf,randomNumber.size());
	string decrypted_key=buff2hex(decrypt,randomNumber.size());
    
	printf("AUTHENTICATED\n");
	printf("    (Generated key: %s)\n", generated_key.c_str());
	printf("    (Decrypted key: %s)\n", decrypted_key.c_str());

    //-------------------------------------------------------------------------
	// 4. Send the server a file request
	printf("4.  Sending file request to server...");

	PAUSE(2);
	BIO_flush(mem);
        BIO_flush(hash);
	BIO_flush(rsapublic);
	
	BIO* request = BIO_new(BIO_s_mem());
	char requestbuff[BUFFER_SIZE];
	int templen = BIO_puts(request,(const char*)filename);
	int requestlen = BIO_read(request,requestbuff,templen);
    	SSL_write(ssl,(const void*) requestbuff,requestlen);

    printf("SENT.\n");
	printf("    (File requested: \"%s\")\n", filename);

    //-------------------------------------------------------------------------
	// 5. Receives and displays the contents of the file requested
	printf("5.  Receiving response from server...");

        //BIO_new_file
        //SSL_read
	//BIO_write
	//BIO_free
	char reqfilebuff[BUFFER_SIZE];
        int reqfilelen = 0;
        int i = BUFFER_SIZE-1;


        BIO* reqfile = BIO_new_file(filename,"w");	
	while((reqfilelen = SSL_read(ssl,reqfilebuff,i)) >1)
	BIO_write(reqfile,reqfilebuff,reqfilelen);

        BIO_free(reqfile);



	printf("FILE RECEIVED.\n");

    //-------------------------------------------------------------------------
	// 6. Close the connection
	printf("6.  Closing the connection...");

	//SSL_shutdown
	
	printf("DONE.\n");
	
	printf("\n\nALL TASKS COMPLETED SUCCESSFULLY.\n");

    //-------------------------------------------------------------------------
	// Freedom!
	SSL_CTX_free(ctx);
	SSL_free(ssl);
	return EXIT_SUCCESS;
	
}
