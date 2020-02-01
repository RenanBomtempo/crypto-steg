# README #

This is a program designed to encode a message onto an image (PPM format) and also decode it.
It is composed of two executable files:

* encoder.exe
* decoder.exe

### How do I get set up? ###

You need first to compile each executable, by executing the following commands on the CMD:

* gcc encoder.c rsa.c ppm.c -o ..\bin\encoder -I..\include
* gcc decoder.c rsa.c ppm.c -o ..\bin\decoder -I..\include

Now the executables are located in the "bin" folder.

### How do I execute the programs? ###

The encoder program is designed to encrypt a message using the RSA method and then encoding that encrypted message onto a PPM P3 image. To run the encoder, you'll need to choose a message, two different prime numbers (between 2 and 46337) and an image file of type PPM P3.

To run the encoder, use the following command on CMD while on the "\bin" folder:
	
.\encoder image_name.ppm "Message." encoded_image.ppm p q

Where "image_name.ppm" is the name of the image, "Message." is the message to be encoded (the last character in the message is the delimitator, it will be used in the decoder program), "encoded_image.ppm" is the name of the output encoded image and "p" and "q" are the prime numbers.

To run the decoder, use the following command on CMD while on the "\bin" folder:
	
.\decoder encoded_image.ppm '.' private.txt

Where "encoded_image.ppm" is the name of the encoded image, '.' is the delimitator which indicates the end of the message and "private.txt" is the txt file containing the private key for decrypting the message.

	
	