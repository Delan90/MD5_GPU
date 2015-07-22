#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*Integer variable used to store the password found by different threads at a designated location without race conditions*/
__device__ int pass_index = 0;

__device__ int signal_to_finish = 0;

/*Array containing the md5 hashes of passwords*/
__constant__ int digests[] = {
	0x753213d1, 0xbe1821ee, 0xaf77a563, 0x52c09f75,
	0xdf8e57d8, 0x06ce5884, 0x76bbc5fb, 0xa45c8ca5,
	0x097d100d, 0x0ce4bbf5, 0x5cdee3ad, 0xb7e9e971,
	0x9ad1e705, 0x1821006d, 0xd270efde, 0x6e22f41f
};

/*Number of passwords*/
#define MAX_DG (4)
/*Number of threads in X dimension of the block*/
#define NUM_THREAD_X 26
/*Number of threads in Y dimension of the block*/
#define NUM_THREAD_Y 26
/*Number of threads in Z dimension of the block*/
#define NUM_THREAD_Z 26

/*Number of blocks in X dimension*/
#define NUM_BLOCK_X 26
/*Number of blocks in Y dimension*/
#define NUM_BLOCK_Y 26
/*Number of blocks in Z dimension*/
#define NUM_BLOCK_Z 26

/*Length of each password*/
#define LENGTH 6

/*Macro to copy the found password to destination location. It uses atomicCAS increment
of the pass_index to avoid multiple threads writing at the same location*/
#define COPY_PASSWORD	int i;\
		do\
												{\
			i = pass_index;\
												}while((i != atomicCAS(&pass_index, pass_index, pass_index+1)));\
		i = i*LENGTH;\
		password[i] = pass_local[0];\
		password[i+1] = pass_local[1];\
		password[i+2] = pass_local[2];\
		password[i+3] = pass_local[3];\
		password[i+4] = pass_local[4];\
		password[i+5] = pass_local[5];\
		if(pass_index==(MAX_DG)) \
			signal_to_finish = 1; \

/*Macro to do the FF transform in md5 algorithm*/
#define FFTRANSFORM(a, b, c, d, x, s, ac) \
		  {(a) += (((b) & (c)) | ((~b) & (d))) + (x) + (unsigned int)(ac); \
   (a) = (((a) << (s)) | ((a) >> (32-(s)))); \
   (a) += (b); \
		  }

/*Macro to do the GG transform in md5 algorithm*/
#define GGTRANSFORM(a, b, c, d, x, s, ac) \
		  {(a) += (((b) & (d)) | ((c) & (~d))) + (x) + (unsigned int)(ac); \
   (a) = (((a) << (s)) | ((a) >> (32-(s)))); \
   (a) += (b); \
		  }

/*Macro to do the HH transform in md5 algorithm*/
#define HHTRANSFORM(a, b, c, d, x, s, ac) \
		  {(a) += ((b) ^ (c) ^ (d)) + (x) + (unsigned int)(ac); \
   (a) = (((a) << (s)) | ((a) >> (32-(s)))); \
   (a) += (b); \
		  }

/*Macro to do the II transform in md5 algorithm*/
#define IITRANSFORM(a, b, c, d, x, s, ac) \
		  {(a) += ((c) ^ ((b) | (~d))) + (x) + (unsigned int)(ac); \
   (a) = (((a) << (s)) | ((a) >> (32-(s)))); \
   (a) += (b); \
		  }
/*======================================================*
*	Kernel function to be called from host		*
*====================================================== *
*	Function name: 			kernel		*
*	Input parameters: 		char*		*
*	Return:				void		*
*======================================================*/
__global__ void kernel(char* password)
{
	char pass_local[LENGTH + 1];

	/*Index assigning based on thread id and block id*/
	//int g = threadIdx.x / 26;// / (26);
	//int h = (threadIdx.x) % 26;// % 26;// / (26 * 26*26);

	int l = threadIdx.x;
	int k = blockIdx.x;
	int j = threadIdx.y;
	int i = blockIdx.y;
	int g = threadIdx.z;
	int h = blockIdx.z;

	if (signal_to_finish == 1)
	{
		//asm("trap;");
		return;
	}

	/*Initializing the anticipated password based on thread id and block id*/
			{
				pass_local[0] = 'a' + l;
				pass_local[1] = 'a' + k;
				pass_local[2] = 'a' + j;
				pass_local[3] = 'a' + i;
				pass_local[4] = 'a' + h;
				pass_local[5] = 'a' + g;
				pass_local[6] = 0;


				/*Array to store calculated hash for the anticipated password*/
				unsigned int dg[4];

				/*Initializing variables to be used in md5 hash calculation*/
				unsigned int a0 = 0x67452301;
				unsigned int b0 = 0xefcdab89;
				unsigned int c0 = 0x98badcfe;
				unsigned int d0 = 0x10325476;
				unsigned int A = a0;
				unsigned int B = b0;
				unsigned int C = c0;
				unsigned int D = d0;
				unsigned int M[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };

				/*Copying the anticipated password byte by byte into structure M*/
				char* mcopy = (char*)M;
				mcopy[0] = pass_local[0];
				mcopy[1] = pass_local[1];
				mcopy[2] = pass_local[2];
				mcopy[3] = pass_local[3];
				mcopy[4] = pass_local[4];
				mcopy[5] = pass_local[5];
				//memcpy(M,message,length);

				((char*)M)[LENGTH] = 0x80;
				M[14] = LENGTH * 8;

				/*invoking md5 transform to generate the hash*/
				FFTRANSFORM(A, B, C, D, M[0], 7, 0xd76aa478);
				FFTRANSFORM(D, A, B, C, M[1], 12, 0xe8c7b756);
				FFTRANSFORM(C, D, A, B, M[2], 17, 0x242070db);
				FFTRANSFORM(B, C, D, A, M[3], 22, 0xc1bdceee);
				FFTRANSFORM(A, B, C, D, M[4], 7, 0xf57c0faf);
				FFTRANSFORM(D, A, B, C, M[5], 12, 0x4787c62a);
				FFTRANSFORM(C, D, A, B, M[6], 17, 0xa8304613);
				FFTRANSFORM(B, C, D, A, M[7], 22, 0xfd469501);
				FFTRANSFORM(A, B, C, D, M[8], 7, 0x698098d8);
				FFTRANSFORM(D, A, B, C, M[9], 12, 0x8b44f7af);
				FFTRANSFORM(C, D, A, B, M[10], 17, 0xffff5bb1);
				FFTRANSFORM(B, C, D, A, M[11], 22, 0x895cd7be);
				FFTRANSFORM(A, B, C, D, M[12], 7, 0x6b901122);
				FFTRANSFORM(D, A, B, C, M[13], 12, 0xfd987193);
				FFTRANSFORM(C, D, A, B, M[14], 17, 0xa679438e);
				FFTRANSFORM(B, C, D, A, M[15], 22, 0x49b40821);
				GGTRANSFORM(A, B, C, D, M[1], 5, 0xf61e2562);
				GGTRANSFORM(D, A, B, C, M[6], 9, 0xc040b340);
				GGTRANSFORM(C, D, A, B, M[11], 14, 0x265e5a51);
				GGTRANSFORM(B, C, D, A, M[0], 20, 0xe9b6c7aa);
				GGTRANSFORM(A, B, C, D, M[5], 5, 0xd62f105d);
				GGTRANSFORM(D, A, B, C, M[10], 9, 0x02441453);
				GGTRANSFORM(C, D, A, B, M[15], 14, 0xd8a1e681);
				GGTRANSFORM(B, C, D, A, M[4], 20, 0xe7d3fbc8);
				GGTRANSFORM(A, B, C, D, M[9], 5, 0x21e1cde6);
				GGTRANSFORM(D, A, B, C, M[14], 9, 0xc33707d6);
				GGTRANSFORM(C, D, A, B, M[3], 14, 0xf4d50d87);
				GGTRANSFORM(B, C, D, A, M[8], 20, 0x455a14ed);
				GGTRANSFORM(A, B, C, D, M[13], 5, 0xa9e3e905);
				GGTRANSFORM(D, A, B, C, M[2], 9, 0xfcefa3f8);
				GGTRANSFORM(C, D, A, B, M[7], 14, 0x676f02d9);
				GGTRANSFORM(B, C, D, A, M[12], 20, 0x8d2a4c8a);
				HHTRANSFORM(A, B, C, D, M[5], 4, 0xfffa3942);
				HHTRANSFORM(D, A, B, C, M[8], 11, 0x8771f681);
				HHTRANSFORM(C, D, A, B, M[11], 16, 0x6d9d6122);
				HHTRANSFORM(B, C, D, A, M[14], 23, 0xfde5380c);
				HHTRANSFORM(A, B, C, D, M[1], 4, 0xa4beea44);
				HHTRANSFORM(D, A, B, C, M[4], 11, 0x4bdecfa9);
				HHTRANSFORM(C, D, A, B, M[7], 16, 0xf6bb4b60);
				HHTRANSFORM(B, C, D, A, M[10], 23, 0xbebfbc70);
				HHTRANSFORM(A, B, C, D, M[13], 4, 0x289b7ec6);
				HHTRANSFORM(D, A, B, C, M[0], 11, 0xeaa127fa);
				HHTRANSFORM(C, D, A, B, M[3], 16, 0xd4ef3085);
				HHTRANSFORM(B, C, D, A, M[6], 23, 0x04881d05);
				HHTRANSFORM(A, B, C, D, M[9], 4, 0xd9d4d039);
				HHTRANSFORM(D, A, B, C, M[12], 11, 0xe6db99e5);
				HHTRANSFORM(C, D, A, B, M[15], 16, 0x1fa27cf8);
				HHTRANSFORM(B, C, D, A, M[2], 23, 0xc4ac5665);
				IITRANSFORM(A, B, C, D, M[0], 6, 0xf4292244);
				IITRANSFORM(D, A, B, C, M[7], 10, 0x432aff97);
				IITRANSFORM(C, D, A, B, M[14], 15, 0xab9423a7);
				IITRANSFORM(B, C, D, A, M[5], 21, 0xfc93a039);
				IITRANSFORM(A, B, C, D, M[12], 6, 0x655b59c3);
				IITRANSFORM(D, A, B, C, M[3], 10, 0x8f0ccc92);
				IITRANSFORM(C, D, A, B, M[10], 15, 0xffeff47d);
				IITRANSFORM(B, C, D, A, M[1], 21, 0x85845dd1);
				IITRANSFORM(A, B, C, D, M[8], 6, 0x6fa87e4f);
				IITRANSFORM(D, A, B, C, M[15], 10, 0xfe2ce6e0);
				IITRANSFORM(C, D, A, B, M[6], 15, 0xa3014314);
				IITRANSFORM(B, C, D, A, M[13], 21, 0x4e0811a1);
				IITRANSFORM(A, B, C, D, M[4], 6, 0xf7537e82);
				IITRANSFORM(D, A, B, C, M[11], 10, 0xbd3af235);
				IITRANSFORM(C, D, A, B, M[2], 15, 0x2ad7d2bb);
				IITRANSFORM(B, C, D, A, M[9], 21, 0xeb86d391);

				/*Assigning the calculated hash values*/
				dg[0] = a0 + A;
				dg[1] = b0 + B;
				dg[2] = c0 + C;
				dg[3] = d0 + D;

				//asm("prefetch.global.L1 [%0];":: "r"(digests));
				//asm("prefetch.global.L1 [%0];":: "r"(digests + 16));
				//asm("prefetch.global.L1 [%0];":: "r"(digests + 32));
				//asm("prefetch.global.L1 [%0];":: "r"(digests + 48));
				//asm("prefetch.global.L1 [%0];":: "r"(digests + 64));
				/*Comparing the calcualted hash values with the given 4 letter password hashes*/
				if ((dg[0] == digests[0]) && (dg[1] == digests[1]) && (dg[2] == digests[2]) && (dg[3] == digests[3])) {
					/*A md5 hash match has been found. Copy the password and let the thread return. */
					COPY_PASSWORD
						return;
				}
				else if ((dg[0] == digests[4]) && (dg[1] == digests[5]) && (dg[2] == digests[6]) && (dg[3] == digests[7])) {
					COPY_PASSWORD
						return;
				}
				else if ((dg[0] == digests[8]) && (dg[1] == digests[9]) && (dg[2] == digests[10]) && (dg[3] == digests[11])) {
					COPY_PASSWORD
						return;
				}
				else if ((dg[0] == digests[12]) && (dg[1] == digests[13]) && (dg[2] == digests[14]) && (dg[3] == digests[15])) {
					COPY_PASSWORD
						return;
				}
				else if ((dg[0] == digests[16]) && (dg[1] == digests[17]) && (dg[2] == digests[18]) && (dg[3] == digests[19])) {
					COPY_PASSWORD
						return;
				}
				else if ((dg[0] == digests[20]) && (dg[1] == digests[21]) && (dg[2] == digests[22]) && (dg[3] == digests[23])) {
					COPY_PASSWORD
						return;
				}
				else if ((dg[0] == digests[24]) && (dg[1] == digests[25]) && (dg[2] == digests[26]) && (dg[3] == digests[27])) {
					COPY_PASSWORD
						return;
				}
				else if ((dg[0] == digests[28]) && (dg[1] == digests[29]) && (dg[2] == digests[30]) && (dg[3] == digests[31])) {
					COPY_PASSWORD
						return;
				}
				else if ((dg[0] == digests[32]) && (dg[1] == digests[33]) && (dg[2] == digests[34]) && (dg[3] == digests[35])) {
					COPY_PASSWORD
						return;
				}
				else if ((dg[0] == digests[36]) && (dg[1] == digests[37]) && (dg[2] == digests[38]) && (dg[3] == digests[39])) {
					COPY_PASSWORD
						return;
				}
			}
}

/*======================================================*
*	Main function to be called from host		*
*====================================================== *
*	Function name: 			main		*
*	Input parameters: 		int		*
char**		*
*	Return:				int		*
*======================================================*/
int main(int argc, char** args)
{
	char* password;
	char* pass;

	/*Structure to pass thread information to GPU*/
	dim3 threads;

	/*Structure to pass block information to GPU*/
	dim3 block;

	/*Allocating the memory for pass on CPU*/
	pass = (char*)malloc(LENGTH * MAX_DG + 1);
	memset(pass, 0, LENGTH * MAX_DG + 1);

	/*Allocating the memory for password on GPU device*/
	cudaMalloc((void**)&password, LENGTH * MAX_DG + 1);

	/*Assigning thread counts in every block*/
	threads.x = NUM_THREAD_X;
	threads.y = NUM_THREAD_Y;
	threads.z = NUM_THREAD_Z;

	/*Assigning the block dimensions*/
	block.x = NUM_BLOCK_X;
	block.y = NUM_BLOCK_Y;
	block.z = NUM_BLOCK_Z;

	/*Calling the kernel to be executed on GPU with block and thread information*/
	kernel << <block, threads >> >(password);


	/*Copying the password from GPU memory to CPU memory*/
	cudaMemcpy(pass, password, LENGTH * MAX_DG + 1, cudaMemcpyDeviceToHost);

	/*Freeing the memory allocated for password on GPU memory*/
	cudaFree(password);

	/*Char array to be used to segregate the passwords in pass structure*/
	char pass_print[LENGTH + 1];
	memset(pass_print, 0, LENGTH + 1);

	/*Segregating the passwords from pass strcuture and printing them at console.*/
	for (int i = 0; i<MAX_DG; i++)
	{
		strncpy(pass_print, pass + (i*LENGTH), LENGTH);
		printf("password %d is:%s\n", i, pass_print);
	}
	/*Freeing the memory allocated for passwords on CPU memory*/
	free(pass);
	return 0;
}
