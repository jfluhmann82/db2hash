/*
 * hash.C
 *
 *  Created on: Feb 21, 2015
 *      Author: Justin Fluhmann <justin@fluhmann.com>
 */

#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sqludf.h>
#include <sqlca.h>
#include <openssl/sha.h>

/*Set the path separator*/
#if(defined(DB2NT))
#define PATH_SEP "\\"
#else /* *NIX */
#define PATH_SEP "/"
#endif

extern "C" void SQL_API_FN sha512(SQLUDF_VARCHAR	*inText,
					   SQLUDF_CHAR		*outText,
					   SQLUDF_NULLIND	*inTextNullInd,
					   SQLUDF_NULLIND	*outTextNullInd,
					   SQLUDF_TRAIL_ARGS )
{
	/* Argument definition:
	 * inText: Input text to be hashed
	 * outText: Output hashed text
	 */

	unsigned char digest[SHA512_DIGEST_LENGTH];
	char mdString[SHA512_DIGEST_LENGTH*2+1];
	std::string text(inText);
	SHA512_CTX ctx;
	struct sqlca sqlca;


	/* Return Null value if any of the input is NULL. */
	//@todo I want to change this to throw an error
	if(*inTextNullInd == -1) {
		strcpy(SQLUDF_STATE, "22002");
		sprintf(SQLUDF_MSGTX, "Null values not allowed for SHA512 call.");
		return;
	}


	SHA512_Init(&ctx);
	SHA512_Update(&ctx, text.c_str(), text.size());
	SHA512_Final(digest, &ctx);
	for (int i = 0; i < SHA512_DIGEST_LENGTH; i++) {
		sprintf(&mdString[i*2], "%02x", (unsigned int) digest[i]);
	}
	strcpy(outText, mdString);

	return;

} //end Sha512()

/*
 * @todo need to move this to using the openssl library for hashing
 * this is just for quick functionality right now.
 */
extern "C" void SQL_API_FN salt(SQLUDF_CHAR		*outText,
								SQLUDF_NULLIND	*outTextNullInd,
								SQLUDF_TRAIL_ARGS)
{
	/* Argument definition:
	 * outText: an 8 character salt
	 */
	int size = 8;
	char salt[size];
	static const char alphanum[] =
		"0123456789"
		"abcdefghijklmnopqrstuvwxyz";

	srand(time(NULL));
	for (int i = 0; i < size; ++i) {
		salt[i] = alphanum[rand() % (sizeof(alphanum) - 1)];
	}



	strcpy(outText, salt);

	return;


} //end salt

