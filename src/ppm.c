/*
 * Title: PPM Handler - Lib
 * ------------------------------
 * This contains the all functions necessary to encrypt and decrypt a message
 * using the RSA method.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include "..\include\ppm.h"
#include "..\include\rsa.h"

#define MAX_LINE_SIZE 70

// Auxilary Functions---------------------------------------------------------//

int **new_2D_int_array(int width, int height){
   int **arr = (int**)malloc(height * sizeof(int*)), i;

   for (i=0; i<height; i++){
      arr[i] = (int*)malloc(width * sizeof(int));
   }

   return arr;
}

char **new_string_array(int size, int buffer){
   char **str = (char**)malloc((1+size) * sizeof(char*));
   int i;
   for (i=0; i<size; i++){
      str[i] = new_string(buffer);
   }
   return str;
}

long get_dec(char *bin){
   int i, dec=0, mult;

   for (i=0; i<32; i++){
      mult = 1 << i;
      dec += mult * char_to_int(bin[31-i]);
   }

   return dec;
}

void get_bin(unsigned long long n, char *bin){
   int c, d, count=0;
   for ( c = 31 ; c >= 0 ; c-- ){
      d = n >> c;
      if ( d & 1 )
         *(bin+count) = 1 + '0';
      else
         *(bin+count) = 0 + '0';
      count++;
   }
   *(bin+count) = '\0';
}

// Main Functions-------------------------------------------------------------//

void encode_message(const char *in_ppm, unsigned long long *encrypted_message, int num_blocks, const char *out_ppm, char msg_delim){
   //Open PPM image
   /*ECHO*/printf("\nOPENING IMAGE\n");
   FILE *ppm = fopen(in_ppm, "r");
   if (!ppm){
      /*ECHO*/printf("IMAGE NOT FOUND!\n");
      exit(0);
   }

   //Create PPM encoded image
   FILE *encoded_ppm = fopen(out_ppm, "w");

   //Read Header
   int  i, height, width;
   char buffer[MAX_LINE_SIZE];
   char **header = new_string_array(4, MAX_LINE_SIZE);
   /*ECHO*/printf(" Header:\n");
   for (i=0; i<4; i++){
      fgets(buffer, MAX_LINE_SIZE, ppm);
      strcpy(header[i], buffer);
      /*ECHO*/printf("  Line %d -> %s", i+1, header[i]);
   }
   //Print Header in encoded image
   for (i=0; i<4; i++){
      fprintf(encoded_ppm, header[i]);
   }

   //Processing Header Information
   if (!strchr(header[0], '3')){
      /*ECHO*/printf("PPM VERSION NOT SUPPORTED\n");
   }
   char *token, delim[2] = " ";
   token = strtok(header[2], delim);
   width = atoi(token);
   token = strtok(NULL, delim);
   height = atoi(token);

   //Check if the image can hold all message information
   if(3*height*width < 32*num_blocks){
      printf(" NOT ENOUGH PIXELS IN THE IMAGE TO ENCODE THE MESSAGE!\n");
      printf(" Image must have at least %d pixels.", (32*num_blocks/3)+1);
      exit(0);
   }

   //Read Pixel Data
   int lines = 4;
   while (fgets(buffer, MAX_LINE_SIZE, ppm)){
      lines++;
   }
   rewind(ppm);
   char **ppm_data_cpy = new_string_array(lines-4, MAX_LINE_SIZE);
   for (i=0; i<lines; i++){
      fgets(buffer, MAX_LINE_SIZE, ppm);
      if (i>3){
      strcpy(ppm_data_cpy[i-4], buffer);
      }
   }

   //Take all data values and store them onto an array
   int num_values = 3*width*height;
   int *data_values = new_int_array(num_values);
   int j=0, value=0, offset=0, counter=0;
   for (i=0; i<lines-4; i++){
      for (j=0; j<70; ){
         if (ppm_data_cpy[i][j] == '\n'){
            break;
         }
         if (ppm_data_cpy[i][j] != ' ' && ppm_data_cpy[i][j] != '\n'){
            value = char_to_int(ppm_data_cpy[i][j]);
            offset = 1;

            while(ppm_data_cpy[i][j+offset] != ' ' && ppm_data_cpy[i][j+offset] != '\n'){
               value = conc_int(value, char_to_int(ppm_data_cpy[i][j+offset]));
               offset++;
            }
            data_values[counter] = value;
            j+=offset;
            counter++;
         } else
            j++;
      }
   }

   //Encode message
   char *bin = new_string(32);
   for (i=0; i<num_blocks; i++){
      get_bin(encrypted_message[i], bin);

      for (j=0; j<32; j++){
         if (bin[j] == '0'){
            if (data_values[(i*32)+j] % 2 != 0){
               data_values[(i*32)+j]--;
            }
         } else if (bin[j] == '1'){
            if (data_values[(i*32)+j] % 2 == 0){
               data_values[(i*32)+j]++;
            }
         }
      }
   }

   //Insert Delimitator
   get_bin(msg_delim, bin);
   for (i=0; i<32; i++){
      if (bin[i] == '0'){
         if (data_values[(num_blocks*32)+i] % 2 != 0){
            data_values[(num_blocks*32)+i]--;
         }
      } else if (bin[i] == '1'){
         if (data_values[(num_blocks*32)+i] % 2 == 0){
            data_values[(num_blocks*32)+i]++;
         }
      }
   }

   //Print to output PPM
   counter=0;
   for (i=0; i<lines-4; i++){
      for (j=0; j<12;j++){
         if (counter < num_values){
            fprintf(encoded_ppm, "%d ", data_values[counter]);
            counter++;
         }
      }
      fprintf(encoded_ppm, "\n");
   }

   //Close Files
   fclose(ppm);
   fclose(encoded_ppm);

   //Free all mallocs
   for (i=0; i<4; i++){
      free(header[i]);
   }
   free(header);
   free(bin);
}

int g_num_blocks_dec;
unsigned long long *decode_message(const char *in_ppm, char msg_delim){
   //Open encoded_image
   FILE *ppm = fopen(in_ppm, "r");
   if (!ppm){
      /*ECHO*/printf("IMAGE NOT FOUND!\n");
      exit(0);
   }

   //Read Header
   int  i, height, width;
   char buffer[MAX_LINE_SIZE];
   char **header = new_string_array(4, MAX_LINE_SIZE);
   /*ECHO*/printf(" Header:\n");
   for (i=0; i<4; i++){
      fgets(buffer, MAX_LINE_SIZE, ppm);
      strcpy(header[i], buffer);
      /*ECHO*/printf("  Line %d -> %s", i+1, header[i]);
   }

   //Processing Header Information
   if (!strchr(header[0], '3')){
      /*ECHO*/printf("PPM VERSION NOT SUPPORTED\n");
   }
   char *token, delim[2] = " ";
   token = strtok(header[2], delim);
   width = atoi(token);
   token = strtok(NULL, delim);
   height = atoi(token);

   //Read Pixel Data
   int lines = 4;
   while (fgets(buffer, MAX_LINE_SIZE, ppm)){
      lines++;
   }
   rewind(ppm);
   char **ppm_data_cpy = new_string_array(lines-4, MAX_LINE_SIZE);
   for (i=0; i<lines; i++){
      fgets(buffer, MAX_LINE_SIZE, ppm);
      if (i>3){
      strcpy(ppm_data_cpy[i-4], buffer);
      }
   }

   //Take all data values and store them onto an array
   int num_values = 3*width*height;
   int *data_values = new_int_array(num_values);
   int j=0, value=0, offset=0, counter=0;
   for (i=0; i<lines-4; i++){
      for (j=0; j<70; ){
         if (ppm_data_cpy[i][j] == '\n'){
            break;
         }
         if (ppm_data_cpy[i][j] != ' ' && ppm_data_cpy[i][j] != '\n'){
            value = char_to_int(ppm_data_cpy[i][j]);
            offset = 1;

            while(ppm_data_cpy[i][j+offset] != ' ' && ppm_data_cpy[i][j+offset] != '\n'){
               value = conc_int(value, char_to_int(ppm_data_cpy[i][j+offset]));
               offset++;
            }
            data_values[counter] = value;
            j+=offset;
            counter++;
         } else
            j++;
      }
   }

   //Decode message
   /*ECHO*/printf("\nDECODING MESSAGE...\n");
   char *bin = new_string(32);
   g_num_blocks_dec = 0;
   int max_num_blocks = (3*width*height)/32;
   unsigned long long *temp_arr = new_long_array(max_num_blocks);

   long block;
   for (i=0; i<max_num_blocks; i++){
      for (j=0; j<32; j++){
         if (data_values[(i*32)+j] % 2 == 0){
            bin[j] = '0';
         } else {
            bin[j] = '1';
         }
      }
      block = get_dec(bin);
      if (block == msg_delim){
         break;
      }
      temp_arr[i] = block;
      g_num_blocks_dec++;
      /*ECHO*/printf("%lu\n",temp_arr[i] );
   }

   unsigned long long *encrypted_blocks = new_long_array(g_num_blocks_dec);
   for (i=0; i<g_num_blocks_dec; i++){
      encrypted_blocks[i] = temp_arr[i];

   }

   //Free all mallocs
   free(temp_arr);
   free(bin);

   return encrypted_blocks;
}

int get_g_num_blocks_dec(){
   return g_num_blocks_dec;
}
