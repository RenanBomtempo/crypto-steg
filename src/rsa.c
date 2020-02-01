/*
 * Title: RSA Cryptography Implementation - Lib
 * ------------------------------
 * This contains the all functions necessary to encrypt and decrypt a message
 * using the RSA method.
 */
 #include <stdio.h>
 #include <stdlib.h>
 #include <string.h>
 #include <math.h>
 #include "..\include\rsa.h"

// Auxilary Functions---------------------------------------------------------//

int calculate_totient(int p, int q) {
   return (p-1)*(q-1);
}

int calculate_multiplicative_inverse(int a, int b) {
   int b0 = b, x0 = 0, x1 = 1;
	int t, q;
	if (b == 1) return 1;
	while (a > 1) {
		q = a / b;
		t = b, b = a % b, a = t;
		t = x0, x0 = x1 - q * x0, x1 = t;
	}
	if (x1 < 0) x1 += b0;
	return x1;
}

int calculate_gcd(int a, int b) {
   int mdc;

   if (b==0)
      mdc = a;
   else
      mdc = calculate_gcd(b, a%b);

   return mdc;
}

int calculate_e(int totient) {
   int e;

   for (e=2; e<totient; e++){
      if (calculate_gcd(totient, e) == 1)
         break;
   }
   return e;
}

int number_of_digits(int number){
	int num_size = 0;

	while (number > 0){
		number /= 10;
		num_size++;
	}

	return num_size;
}

unsigned long long mod_exp(unsigned long long base, unsigned long long exponent, unsigned long long n){
   unsigned long long res = 1; // Initialize result

   base = base % n;  // Update x if it is more than or equal to p

   while (exponent > 0) {
      // If y is odd, multiply x with result
      if (exponent & 1)
      res = (res*base) % n;

      // y must be even now
      exponent = exponent>>1; // y = y/2
      base = (base*base) % n;
   }
   return res;
}

int *new_int_array(int size){
   return (int*)malloc(size * sizeof(int));
}

unsigned long long *new_long_array(int size){
   return (unsigned long long*)malloc(size * sizeof(unsigned long long));
}

char *new_string(int size){
   char *str = (char*)malloc((1+size) * sizeof(char));
   str[0] = '\0';
   return str;
}

char *convert_to_ascii(char *msg){
   //Store each char ASCII value into an int array.
   /*ECHO*/printf("\nCONVERTING STRING TO ASCII ARRAY...\n");
   int msg_size = strlen(msg);
   int *ascii_arr = new_int_array(msg_size);
   if(ascii_arr == NULL){
      /*ECHO*/printf("MALLOC ERROR - 'ascii_arr' memmory not allocated.");
      exit(0);
   }

   int i, ndigits_ascii_arr = 0;
   for (i = 0; i < msg_size; i++){
      ascii_arr[i] = msg[i];
      ndigits_ascii_arr += number_of_digits(ascii_arr[i]);
      /*ECHO*/printf(" -'%c' converted to %d\n", msg[i], ascii_arr[i]);
      if (ascii_arr[i] < 0){
         /*ECHO*/printf("ERROR - THE CHARACTER '%c' IS NOT SUPPORTED!\n", msg[i]);
         exit(0);
      }
   }
   /*ECHO*/printf(" String converted succesfully!\n");

   //Create a string containing all digits of the message in ASCII form
   /*ECHO*/printf("\nCONVERTING ASCII ARRAY TO ASCII STRING...\n");
   char *temp_ascii_str = new_string(ndigits_ascii_arr);
   if(temp_ascii_str == NULL){
      /*ECHO*/printf("MALLOC ERROR - 'temp_ascii_str' memmory not allocated.");
      exit(0);
   }

   for (i = 0; i < msg_size; i++){
      char *digits = new_string(number_of_digits(ascii_arr[i]));
      if(digits == NULL){
         /*ECHO*/printf("MALLOC ERROR - 'digits' memmory not allocated.");
         exit(0);
      }
      sprintf(digits, "%d", ascii_arr[i]);
      strcat(temp_ascii_str, digits);
      free(digits);
   }
   /*ECHO*/printf(" ASCII string:\n \"%s\"\n Length: %d characters.\n", temp_ascii_str, strlen(temp_ascii_str));
   /*ECHO*/printf(" Array converted succesfully!\n");

   //Free all mallocs
   free(ascii_arr);
   return temp_ascii_str;
}

int char_to_int(char c){
   switch (c) {
      case '0':
         return 0;
      break;
      case '1':
         return 1;
      break;
      case '2':
         return 2;
      break;
      case '3':
         return 3;
      break;
      case '4':
         return 4;
      break;
      case '5':
         return 5;
      break;
      case '6':
         return 6;
      break;
      case '7':
         return 7;
      break;
      case '8':
         return 8;
      break;
      case '9':
         return 9;
      break;
      default:
         return 0;
      break;
   }
}

unsigned long long conc_int(unsigned long long a, int b){
   unsigned long long conc;
   if (b != 0)
      conc = (a*pow(10,number_of_digits(b))) + b;
   else
      conc = a*10;
   return conc;
}


// Main Functions-------------------------------------------------------------//


void generate_keys(int p, int q) {
  int n, totient, e, d;
  /*ECHO*/printf("GENERATING KEYS...\n");
  /*ECHO*/printf(" Prime numbers:\n  p = %d\n  q = %d\n", p, q);

  n = p*q;
  /*ECHO*/printf(" N = %d\n", n);
  totient = calculate_totient(p, q);
  /*ECHO*/printf(" Euler Totient = %d\n", n);
  e = calculate_e(totient);
  d = calculate_multiplicative_inverse(e, totient);

  /*ECHO*/printf(" Private key:\n  d = %d\n", d, n);
  /*ECHO*/printf(" Public key:\n  e = %d\n", e, n);
  g_public_key.n = n;
  g_public_key.value = e;
  g_private_key.n = n;
  g_private_key.value = d;
  /*ECHO*/printf(" Keys generated succesfully!\n");


}

key get_private_key() {
     return g_private_key;
}

key get_public_key() {
     return g_public_key;
}

int g_num_blocks = 0;
unsigned long long *encrypt(char *msg, int n, int e) {
   char *ascii_str = convert_to_ascii(msg);
   int ascii_str_len = strlen(ascii_str);

   //Message Processing (creating Blocks)
   /*ECHO*/printf("\nPREPARING MESSAGE BLOCKS FOR ENCRYPTION...\n");
   unsigned long long *temp_arr = new_long_array(ascii_str_len); //Temporary array for holding blocks
   int i, offset;
   unsigned long long block, check_block;

   for (i = 0; i < ascii_str_len; ){
      block = char_to_int(ascii_str[i]);
      check_block = block;
      offset = 0;

      if(block != 0){
         while (check_block < n && (i+offset) <= ascii_str_len-1){
            block = check_block;
            offset++;
            check_block = conc_int(block, char_to_int(ascii_str[i+offset]));
         }
      } else {
         offset++;
      }
      temp_arr[g_num_blocks] = block;

      g_num_blocks++;
      /*ECHO*/printf(" Block[%d] = %lld\n", g_num_blocks-1, block);
      i+=offset;
      if (g_num_blocks > 300)
         break;
   }
   /*ECHO*/printf(" Blocks succesfully created!\n");

   //Encrypt and store blocks in an array
   /*ECHO*/printf("\nENCRYPTING MESSAGE BLOCKS...\n");
   unsigned long long *encrypted_blocks = new_long_array(g_num_blocks);
   for (i = 0; i < g_num_blocks; i++){
      encrypted_blocks[i] = mod_exp(temp_arr[i], e, n);
      /*ECHO*/printf(" Block[%d] = %lld >(RSA)> %lld\n", i, temp_arr[i], encrypted_blocks[i]);
   }
   /*ECHO*/printf(" Blocks succesfully encrypted!\n");
   free(temp_arr);

   return encrypted_blocks;
}

int get_number_of_blocks(){
   return g_num_blocks;
}

void decrypt(unsigned long long *encrypted_blocks, int num_blocks, long n, long d) {
   //Decrypt and store blocks in an array
   /*ECHO*/printf("\nDECRYPTING MESSAGE BLOCKS...\n");
   unsigned long long *decrypted_blocks = new_long_array(num_blocks);
   int i;
   for (i = 0; i < num_blocks; i++){
      decrypted_blocks[i] = mod_exp(encrypted_blocks[i], d, n);
      /*ECHO*/printf(" Block[%d] = %llu >(RSA)> %llu\n", i, encrypted_blocks[i], decrypted_blocks[i]);
   }
   /*ECHO*/printf(" Blocks succesfully decrypted!\n");

   //Blocks -> ASCII string
   char *decrypted_ascii_str = new_string(300);
   /*ECHO*/printf("\nCONVERTING BLOCKS TO ASCII STRING...\n");
   for (i = 0; i < num_blocks; i++){
      char *block_str = new_string(number_of_digits(decrypted_blocks[i]));
      if(block_str == NULL){
         /*ECHO*/printf("MALLOC ERROR - 'block_str' memmory not allocated.");
         exit(0);
      }

      sprintf(block_str, "%llu", decrypted_blocks[i]);
      strcat(decrypted_ascii_str, block_str);
      /*ECHO*/printf(" Block[%d] = %lu -> ", i, decrypted_blocks[i]);
      /*ECHO*/printf("\"%s\"\n", block_str);
      free(block_str);
   }
   free(decrypted_blocks);
   /*ECHO*/printf(" ASCII string:\n\"%s\"\n", decrypted_ascii_str);

   //ASCII string -> Message string
   char *temp_msg_str = new_string(100); //Temporary string with arbritraty size
   /*ECHO*/printf("\nCONVERTING ASCII STRING TO MESSAGE STRING...\n");
   int decrypted_ascii_str_len = strlen(decrypted_ascii_str);
   int offset, char_index = 0;
   char msg_char;
   for (i = 0; i < decrypted_ascii_str_len; ){
      offset = 0;
      if (decrypted_ascii_str[i] != '1'){
         msg_char = conc_int(char_to_int(decrypted_ascii_str[i]), char_to_int(decrypted_ascii_str[i+1]));
         /*ECHO*/printf(" ASCII = %d -> '%c'\n", msg_char, msg_char);
         offset += 2;
      } else {
         msg_char = conc_int(char_to_int(decrypted_ascii_str[i]), char_to_int(decrypted_ascii_str[i+1]));
         msg_char = conc_int(msg_char, char_to_int(decrypted_ascii_str[i+2]));
         offset += 3;
         /*ECHO*/printf(" ASCII = %d -> '%c'\n", msg_char, msg_char);
      }

      i += offset;
      temp_msg_str[char_index] = msg_char;
      char_index++;
   }
   free(decrypted_ascii_str);
   /*ECHO*/printf("\nMessage succesfully decrypted!\n");

   //Decryption Output
   printf(" Decrypted message:\n \"");
   for (i=0; i<char_index; i++){
      printf("%c", temp_msg_str[i]);
   }
   printf("\"");
   free(temp_msg_str);
}
