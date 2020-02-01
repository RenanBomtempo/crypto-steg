/*
 * Title: Encoder - Main
 * ------------------------------
 * Encrypt and encode the msg.
 * ------------------------------
 * User Input:
 *    - image.ppm
 *    - message to be encoded (string)
 *    - name of the output .ppm file
 *    - prime number 'p' (integer)
 *    - prime number 'q' (integer)
 * Program Output:
 *    - encoded_image.ppm
 *    - private.txt
 * ------------------------------
 * LIMITATIONS:
 *  - Maximum values for 'p' and 'q' are 46327 and 46337.
 */

 /*
gcc encoder.c rsa.c ppm.c -o ..\bin\encoder -I..\include
.\encoder test.ppm "Mensagem de teste." encoded_image.ppm 46337 46327
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "..\include\rsa.h"
#include "..\include\ppm.h"

int main(int argc, char *argv[]){
   /*ECHO*/printf("---DEBUG---\n");

   //Check arguments
   if (argc < 5){
      /*ECHO*/printf("TOO FEW ARGUMENTS!\n");
      /*ECHO*/printf("Expected the following arguments sequence:\n");
      /*ECHO*/printf(".\\program_name \"message\" output_image_name.ppm 7 5\n");
      exit(0);
   }

   //Get prime numbers from arguments
   int p, q;
   sscanf(argv[4],"%d",&p);
   sscanf(argv[5],"%d",&q);
   if ((p > 46327 && q > 46327) || (p > 46337 || q > 46337)){
      /*ECHO*/printf("PRIME NUMBES ARE TOO BIG!\n");
      exit(0);
   }

   //Get PPM file name from arguments
   char *in_ppm = new_string(strlen(argv[1]));
   strcpy(in_ppm, argv[1]);
   char *out_ppm = new_string(strlen(argv[3]));
   strcpy(out_ppm, argv[3]);

   //Get message from arguments and store it into a string.
   int msg_size = strlen(argv[2]);
   char *msg = new_string(msg_size);
   strcpy(msg, argv[2]);
   /*ECHO*/printf("\nInput string:\n\"%s\"\n", msg);
   char msg_delim = msg[msg_size-1];

   //Generating Keys
   generate_keys(p, q);

   //Encrypt Message
   unsigned long long *encrypted_message = encrypt(msg, g_public_key.n, g_public_key.value);

   //Encode message onto PPM image
   encode_message(in_ppm, encrypted_message, get_number_of_blocks(), out_ppm, msg_delim);

   //Exporting private key
   /*ECHO*/printf("\nEXPORTING PRIVATE KEY...\n", msg);
   FILE *f = fopen("private.txt", "w");
   fprintf(f, "%u\n%u\n", g_private_key.n, g_private_key.value);
   fclose(f);
   /*ECHO*/printf(" Private key succesfully exported!\n", msg);

   //Free all mallocs
   free(msg);
   free(in_ppm);
   free(out_ppm);

   return 0;
}
