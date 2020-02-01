/*
 * Title: RSA Cryptography Interface - Header
 * ------------------------------
 * This contains the all function prototypes, tydef and global variables used to
 * encrypt and decrypt a message using the RSA method.
 */

#ifndef RSA_H
#define RSA_H

typedef struct Key {          /* Struct created to hold all Key information */
     unsigned int n;          /* Product of the primes 'p' and 'q' */
     unsigned int value;      /* Key values: 'e' in public and 'd' in private */
}key;

// Global Variables-----------------------------------------------------------//
key g_public_key, g_private_key;   /* Declaring global variables Key */

// Auxilary Functions---------------------------------------------------------//

/*
 * Calculate Totient
 * -----------------------
 * Input: Prime numbers p & q
 * Output: phi(n) = (p-1)(q-1)
 */
int calculate_totient(int p, int q);

/*
 * Calculate Multiplicative Inverse
 * -----------------------
 * Input: Integers a & b.
 * Process: Extended Euclidean Algorithm
 * Output: Multiplicative inverse of a mod totient
 */
int calculate_multiplicative_inverse(int a, int b);

/*
 * Calculate Great Common Divisor (Recursive Function)
 * -----------------------
 * Input: Integers a & b.
 * Output: Great common divisor between a & b.
 */
int calculate_gcd(int a, int b);

/*
 * Calculate Public Key Value (e)
 * -----------------------
 * Input: totient
 * Output: Smallest value that satisfy: 1 < e < totient and GCD(e, totient)=1.
 * -----------------------
 * Auxilary Functions Used:
 * - calculate_gcd
 */
int calculate_e(int totient);

/*
 * Number of digits
 * -----------------------
 * Input:
 * Output:
 */
int number_of_digits(int number);

/*
 * Modular Exponentiation
 * -----------------------
 * Input: base, exponent and n (mod)
 * Output: (base ^ exponent) mod n
 */
unsigned long long mod_exp(unsigned long long base, unsigned long long exponent, unsigned long long n);

/*
 * Dynamic memory allocation for INT array
 * -----------------------
 * Input: size of array
 * Output: array
 */
int *new_int_array(int size);

/*
 * Dynamic memory allocation for LONG array
 * -----------------------
 * Input: size of array
 * Output: array
 */
unsigned long long *new_long_array(int size);

/*
 * Dynamic memory allocation for STRING
 * -----------------------
 * Input: size of string
 * Output: string
 */
char *new_string(int size);

/*
 * Convert message to ASCII string
 * -----------------------
 * Input: size of string
 * Output: string
 */
char *convert_to_ascii(char *msg);


int char_to_int(char c);

unsigned long long conc_int(unsigned long long a, int b);


// Main Functions-------------------------------------------------------------//

void generate_keys(int p, int q);
/*
 * Encrypt Message
 * -----------------------
 * Input: unciphered message (string)
 * Output: ciphered message (string)
 */
unsigned long long *encrypt(char *msg, int n, int e);

/*
 * Decrypt Message
 * -----------------------
 * Input: ciphered message (c)
 * Output: print on screen the decrypted message
 */
void decrypt(unsigned long long *encrypted_blocks, int num_blocks, long d, long n);

/*
 * Decrypt Message
 * -----------------------
 * Input: ciphered message (c)
 * Output: c^d mod n
 */
int get_number_of_blocks();

#endif
