/*
 * Copyright 2012 <James.Bottomley@HansenPartnership.com>
 *
 * see COPYING file
 */
#include <stdint.h>
#define __STDC_VERSION__ 199901L
#include <efi.h>
#ifdef CONFIG_arm
/* FIXME:
 * arm efi leaves a visibilit pragma pushed that won't work for
 * non efi programs, so eliminate it */
#pragma GCC visibility pop
#endif

#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <openssl/pem.h>
#include <openssl/err.h>

#include <variables.h>
#include <guid.h>

void
parse_db(const char *name, uint8_t *data, uint32_t len, int sig, int entry)
{
	EFI_SIGNATURE_LIST  *CertList = (EFI_SIGNATURE_LIST *)data;
	EFI_SIGNATURE_DATA  *Cert;
	long count = 0, DataSize = len;
	int size;

	certlist_for_each_certentry(CertList, data, size, DataSize) {
		int Index = 0;
		const char *ext;

		if (sig != -1 && count != sig)
			continue;


		if (compare_guid(&CertList->SignatureType, &X509_GUID)== 0) {
			ext = "X509";
		} else if (compare_guid(&CertList->SignatureType, &RSA2048_GUID) == 0) {
			ext = "RSA2048";
		} else if (compare_guid(&CertList->SignatureType, &PKCS7_GUID) == 0) {
			ext = "PKCS7";
		} else if (compare_guid(&CertList->SignatureType, &EFI_CERT_SHA256_GUID) == 0) {
			ext = "SHA256";
		} else {
			ext = "Unknown";
		}

		printf("%s: List %ld, type %s\n", name, count++, ext);

		certentry_for_each_cert(Cert, CertList) {
			if (entry != -1 && Index != entry)
				continue;

			printf("    Signature %d, size %d, owner %s\n",
			      Index++, CertList->SignatureSize,
			      guid_to_str(&Cert->SignatureOwner));

			if (strcmp(ext, "X509") == 0) {
				const unsigned char *buf = (unsigned char *)Cert->SignatureData;
				X509 *X = d2i_X509(NULL, &buf,
						   CertList->SignatureSize);
				X509_NAME *issuer = X509_get_issuer_name(X);
				X509_NAME *subject = X509_get_subject_name(X);
				
				printf("        Subject:\n");
				X509_NAME_print_ex_fp(stdout, subject, 12, XN_FLAG_SEP_CPLUS_SPC);
				printf("\n        Issuer:\n");
				X509_NAME_print_ex_fp(stdout, issuer, 12, XN_FLAG_SEP_CPLUS_SPC);
				printf("\n");

			} else if (strcmp(ext, "SHA256") == 0) {
				uint8_t *hash = Cert->SignatureData;
				int j;

				printf("        Hash:");
				for (j = 0; j < SHA256_DIGEST_SIZE; j++) {
					printf("%02x", hash[j]);
				}
				printf("\n");
			}
		}
	}
}

int
main(int argc, char *argv[])
{
	char *efifile, *name, *esl_name;
	const char *progname = argv[0];
	int sig = -1, entry = -1;

	if (argc != 2) {
		printf("Usage: %s <efi sig list file>\n", progname);
		exit(1);
	}

	efifile = argv[1];

	int fd = open(efifile, O_RDONLY | O_BINARY);
	if (fd < 0) {
		fprintf(stderr, "Failed to open file %s: ", efifile);
		perror("");
		exit(1);
	}

	struct stat st;
	if (fstat(fd, &st) < 0) {
		fprintf(stderr, "Failed to stat file %s: ", efifile);
		perror("");
		exit(1);
	}

	void *buf = malloc(st.st_size);
	if (!buf) {
		fprintf(stderr, "Malloc failed: ");
		perror("");
		exit(1);
	}

	if (read(fd, buf, st.st_size) != st.st_size) {
		fprintf(stderr, "Failed to read %d bytes from %s: ",
			(int)st.st_size, efifile);
		perror("");
		exit(1);
	}
	close(fd);

	parse_db(efifile, buf, st.st_size, sig, entry);
	free(buf);

	return 0;
}
