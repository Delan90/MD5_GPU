#include <stdio.h>
#include <stdlib.h>
#include <string.h>

__constant__ unsigned int s_table_device[] = {
7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22, 7, 12, 17, 22,
5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20, 5, 9, 14, 20,
4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23, 4, 11, 16, 23,
6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21, 6, 10, 15, 21 };
__constant__  unsigned int k_table_device[] = {
0xd76aa478, 0xe8c7b756, 0x242070db, 0xc1bdceee,
0xf57c0faf, 0x4787c62a, 0xa8304613, 0xfd469501,
0x698098d8, 0x8b44f7af, 0xffff5bb1, 0x895cd7be,
0x6b901122, 0xfd987193, 0xa679438e, 0x49b40821,
0xf61e2562, 0xc040b340, 0x265e5a51, 0xe9b6c7aa,
0xd62f105d, 0x02441453, 0xd8a1e681, 0xe7d3fbc8,
0x21e1cde6, 0xc33707d6, 0xf4d50d87, 0x455a14ed,
0xa9e3e905, 0xfcefa3f8, 0x676f02d9, 0x8d2a4c8a,
0xfffa3942, 0x8771f681, 0x6d9d6122, 0xfde5380c,
0xa4beea44, 0x4bdecfa9, 0xf6bb4b60, 0xbebfbc70,
0x289b7ec6, 0xeaa127fa, 0xd4ef3085, 0x04881d05,
0xd9d4d039, 0xe6db99e5, 0x1fa27cf8, 0xc4ac5665,
0xf4292244, 0x432aff97, 0xab9423a7, 0xfc93a039,
0x655b59c3, 0x8f0ccc92, 0xffeff47d, 0x85845dd1,
0x6fa87e4f, 0xfe2ce6e0, 0xa3014314, 0x4e0811a1,
0xf7537e82, 0xbd3af235, 0x2ad7d2bb, 0xeb86d391 };
__constant__ int digests_4letters[] = {
0x1cc91d1a , 0xc6257390 , 0xf0dd7192 , 0x72bc44c9 ,
0xd0122096 , 0xd970819b , 0x9f66f012 , 0x079d7d6d ,
0xcd6b8f09 , 0x73d32146 , 0x834edeca , 0xf6b42726 ,
0x5921d648 , 0x62f5df03 , 0x882ee538 , 0x8f0c3891 ,
0xb9285f01 , 0x36dd1bdf , 0x76d97d42 , 0x9db273fb ,
0xa5f9f4b1 , 0xd96fe323 , 0x3e57f469 , 0x4045af25 ,
0x352cd3fb , 0x468d4cbb , 0xa202fcf8 , 0xeff1ab74 ,
0x8572cb61 , 0xb923e58b , 0x3dcc6e92 , 0xc6d0a57d ,
0x5dd92fa8 , 0x5df20fb1 , 0x079fd3fa , 0x37be2e37 ,
0xa51a803d , 0xc3cec132 , 0x7ad882ee , 0x3ff6fd99};

const int digests_6letters[] = {
	0x753213d1, 0xbe1821ee, 0xaf77a563, 0x52c09f75,
	0xdf8e57d8, 0x06ce5884, 0x76bbc5fb, 0xa45c8ca5,
	0x097d100d, 0x0ce4bbf5, 0x5cdee3ad, 0xb7e9e971,
	0x9ad1e705, 0x1821006d, 0xd270efde, 0x6e22f41f
};

#define MAX_DG (10)
#define NUM_THREAD_X 26
#define NUM_THREAD_Y 26
#define NUM_THREAD_Z 1

#define NUM_BLOCK_X 26
#define NUM_BLOCK_Y 26
#define NUM_BLOCK_Z 1


__device__ void md5(char* message, int length, unsigned int* digest)
{
	unsigned int a0 = 0x67452301;
	unsigned int b0 = 0xefcdab89;
	unsigned int c0 = 0x98badcfe;
	unsigned int d0 = 0x10325476;
	unsigned int A = a0;
	unsigned int B = b0;
	unsigned int C = c0;
	unsigned int D = d0;
	unsigned int M[16] = { 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0 };
	char* mcopy = (char*)M;
	for (int i = 0; i <= length; i++)
	{
		mcopy[i] = message[i];
	}
	//memcpy(M,message,length);
	((char*)M)[length] = 0x80;
	M[14] = length * 8;
	for (int i = 0; i<64; i++)
	{
		unsigned int F = (B & C) | ((~B) & D);
		unsigned int G = (D & B) | ((~D) & C);
		unsigned int H = B ^ C ^ D;
		unsigned int I = C ^ (B | (~D));
		unsigned int tempD = D;
		D = C;
		C = B;
		unsigned int X = I;
		unsigned int g = (7 * i) & 15;
		if (i < 48) { X = H; g = (3 * i + 5) & 15; }
		if (i < 32) { X = G; g = (5 * i + 1) & 15; }
		if (i < 16) { X = F; g = i; }

		unsigned int tmp = A + X + k_table_device[i] + M[g];
		B = B + ((tmp << s_table_device[i]) | ((tmp & 0xffffffff) >> (32 - s_table_device[i])));
		A = tempD;
	}
	digest[0] = a0 + A;
	digest[1] = b0 + B;
	digest[2] = c0 + C;
	digest[3] = d0 + D;
}


__device__ int check_password(char *passwd, const int *digests, int num_digests)
{
	unsigned int dg[4];
	md5(passwd, 4, dg);

	for (int i = 0; i< num_digests; i++)
	{
		if ((dg[0] == digests[i * 4]) && (dg[1] == digests[i * 4 + 1]) && (dg[2] == digests[i * 4 + 2]) && (dg[3] == digests[i * 4 + 3])) {
			
			return i;
		}
	}
	return -1;
}


__global__ void kernel(char* password)
{
	//inc = 0;
	char pass_local[5];

	int l = threadIdx.x;
	int k = blockIdx.x;
    int j = threadIdx.y;
    int i = blockIdx.y;

		{
			pass_local[0]='a'+l;
			pass_local[1]='a'+k;
			pass_local[2]='a'+j;
			pass_local[3]='a'+i;
			pass_local[4]=0;
			if (check_password(pass_local, digests_4letters, MAX_DG) != -1)
			{
                //atomicAdd(&inc, 1);
                for(int i=0; i<10; i++)
                {
                    if(atomicCAS((int*)&password[i*5], 0, 1) != 0)
                    {
                        //atomicAdd((int*)&password[i*4], 1);
                        continue;
                    }
                    password[i*5 +1] = pass_local[0];
                    password[i*5 +2] = pass_local[1];
                    password[i*5 +3] = pass_local[2];
                    password[i*5 +4] = pass_local[3];
                    break;
                }
			};
		}
    password[51] = '\0';
}

int main(int argc, char** args)
{
	char* password;
	char* pass;
	dim3 threads;
	dim3 block;
	pass = (char*)malloc(51);
	memset(pass, 0, 51);
	cudaMalloc((void**)&password, 51);
	threads.x = NUM_THREAD_X;
	threads.y = NUM_THREAD_Y;
	threads.z = NUM_THREAD_Z;

	block.x = NUM_BLOCK_X;
	block.y = NUM_BLOCK_Y;
	block.z = NUM_BLOCK_Z;

	printf("calling the kernel");
	kernel << <block, threads >> >(password);
	printf("kernel call is done\n");
	cudaMemcpy(pass, password, 51, cudaMemcpyDeviceToHost);
	cudaFree(password);
	printf("pass is:%s\n", pass);
}
