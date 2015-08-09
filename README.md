# MD5_GPU

##Introduction

In this lab, We have transformed a CPU version of a password cracker to a GPU version. The purpose was to exploit the GPU capabilities to execute the program in parallel in order to achieve the results faster. GPU provides a lot of computational resources which can be used for computation in parallel. However the key to exploit these resources is to find the parallelism in the application: The blocks of the program which can be run in parallel will be executed on different threads of the GPU in parallel. Additionally, to not have memory accesses as the barrier for the performance improvement, it has to be made sure that memory accesses to DRAM have to be avoided as much as possible.

##Simulation Results

The 4 letter passwords found are as follows:

              fire, blue, tong, cool, dark, qian, temp, qwer, test, pass
              
We also found the password for 6 letters running it on the GPU cluster: 
              
             <https://www.pdc.kth.se/resources/computers/zorn/hardware>

The 6 letter passwords found are as follows:

              joshua, energy, qwerty, rkqian
              
Table 1 provides the performance statistics of the two version of the programs we developed for GPU in two stages. The unoptimized version was developed in the first stage and provided only parallel execution of the code block. In the second stage, the program was optimized with various techniques like loop unrolling, function coalescing and reduced memory accesses etc., to provide a better execution performance. As evident from the table, with the unoptimized version, the simulation cycles required to get the result is more than 5 times the cycles required for the optimized version. We observed that the simulation for our program on the TUB Ubuntu server takes on average 12 to 15 minutes to complete and provide the result.


