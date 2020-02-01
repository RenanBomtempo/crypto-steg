/*
 * Title: PPM Handler Interface - Header
 * ------------------------------
 * This contains the all function prototypes, tydef and global variables used to
 * manipulate a PPM image.
 */
#ifndef PPM_H
#define PPM_H

// Auxilary Functions---------------------------------------------------------//

int **new_2D_int_array(int width, int height);

char **new_string_array(int size, int buffer);

long get_dec(char *binaryChar);

void get_bin(unsigned long long n, char *bin);

// Main Functions-------------------------------------------------------------//

void encode_message(const char *in_ppm, unsigned long long *encrypted_message, int num_blocks, const char *out_ppm, char delim);

unsigned long long *decode_message(const char *ppm, char msg_delim);

int get_g_num_blocks_dec();

#endif
