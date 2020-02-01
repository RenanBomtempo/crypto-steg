/*
 * Title: Decoder - Main
 * ------------------------------
 * Decode and decrypt the message.
 * ------------------------------
 * User Input:
 *    - encoded_image.ppm
 *    - end of message char ' '
 *    - private.txt
 * Program Output:
 *    - [screen] Decrypted message
 * ------------------------------
 * LIMITATIONS:
 *  - Maximum values for 'p' and 'q' are 46327 and 46337.
 */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include "..\include\rsa.h"
 #include "..\include\ppm.h"

 int main(int argc, char *argv[]){
   /*ECHO*/printf("---DEBUG---\n");

   //Check Arguments
   if (argc < 3){
      /*ECHO*/printf("TOO FEW ARGUMENTS!\n");
      /*ECHO*/printf("Expected the following arguments sequence:\n");
      /*ECHO*/printf(".\\program_name 'delim' private.txt\n");
      exit(0);
   }

   //Get Arguments
   char *encoded_image = new_string(strlen(argv[1]));
   strcpy(encoded_image, argv[1]);
   char delim = argv[2][1];
   /*ECHO*/printf("Delim: '%c'\n", argv[2][1]);
   char *txt_name = new_string(strlen(argv[3]));
   strcpy(txt_name, argv[3]);

   //Open private.txt
   FILE *priv_txt = fopen(txt_name, "r");
   char buffer[12];
   long n, d;
   fgets(buffer, 12, priv_txt);
   n = atoi(buffer);
   fgets(buffer, 12, priv_txt);
   d = atoi(buffer);

   //Decode and decrypt the message
   unsigned long long *encrypted_message = decode_message(encoded_image, delim);
   int num_blocks_dec = get_g_num_blocks_dec();
   decrypt(encrypted_message, num_blocks_dec, n, d);

   free(encrypted_message);
   return 0;
}
