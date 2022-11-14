# Popquiz

## Challenge description

> Geez, I feel these quizzes I keep getting are completely arbitrary.  Could you help me pass? (Hint: use Ghidra to reverse engineer this program!)

## Solution

### Running `popquiz`

Upon running the `popquiz` executable, we are greeted with a prompt:

```txt
POP QUIZ TIME! Can you solve these challenging questions?
What number am I thinking of?
```

Uh...maybe I'll try 42?

```txt
WRONG
```

Nope that didn't work. Time to pull out Ghidra :)

### Ghidra fun

After importing the `popquiz` binary into a project, the first function that stands out is the `main` function:

```c
undefined8 main(void)

{
  int iVar1;

  printf("%d\n",1);
  puts("POP QUIZ TIME! Can you solve these challenging questions?");
  iVar1 = question_1();
  if (((iVar1 != 0) && (iVar1 = question_2(), iVar1 != 0)) && (iVar1 = question_3(), iVar1 != 0)) {
    readFlag();
    return 0;
  }
  puts("WRONG");
  return 1;
}
```

So in order to get the flag, the `question_1`, `question_2`, and `question_3` functions all have to return nonzero values. I'll have to go through each of those functions to figure out the correct answers to each question.

### Question 1

I don't think it's a stretch to assume that that `question_1` corresponds to the first question I was trying to answer, which is confirmed by a `printf()` call. Here's the entire decompiled function in Ghidra:

```c
bool question_1(void)

{
  long in_FS_OFFSET;
  int local_18;
  int local_14;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  local_14 = 0x2325;
  printf("What number am I thinking of? ");
  __isoc99_scanf(&DAT_00100e27,&local_18);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return local_14 == local_18;
}
```

I don't really care about `local_10`, but `local_14` and `local_18` look interesting. `local_14` is initialized to a constant (2325 hex/8997 decimal), while the user input is somehow read into `local_18`. Looking at `DAT_00100e27` in Ghidra shows that it's the string `%d`, which as a format specifier just returns the input string as a decimal number (i.e. an `int`). Since these are just checked for equality, entering 8997 should be the correct answer to this question, which allows us to move on to question 2.

### Question 2

After answering question 1 correctly, we're greeted with this prompt:

```
POP QUIZ TIME! Can you solve these challenging questions?
What number am I thinking of? 8997
Gimme some characters:
```

Typing in random characters doesn't work this time either, so back to Ghidra:

```c
bool question_2(void)

{
  long in_FS_OFFSET;
  undefined4 local_14;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  printf("Gimme some characters: ");
  local_14 = 0;
  __isoc99_scanf("\n%c%c%c%c",&local_14,(long)&local_14 + 1,(long)&local_14 + 2,(long)&local_14 + 3)
  ;
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return (int)local_14._3_1_ + (int)(char)local_14 + (int)local_14._1_1_ + (int)local_14._2_1_ ==
         0x1a0;
}
```

So this time it's expecting 4 characters, which are read directly into `local_14`. Since we know `local_14` is a 4-character string, we can retype it in Ghidra to a `char[4]`, which makes the return statement easier to read:

```c
return (int)local_14[3] + (int)local_14[0] + (int)local_14[1] + (int)local_14[2] == 0x1a0;
```

So it's just summing the ASCII codepoints of the four characters and seeing if that sum is equal to 1a0 hex, which turns out to be 416 in decimal. 416 / 4 is 104, and luckily a (typeable) ASCII character exists at that codepoint: lowercase h. Typing `hhhh` as an answer confirms that this is the case, and we're now greeted with `???` as a prompt.

### Question 3

As with the previous two, here's the body of the `question_3()` function:

```c
void question_3(void)

{
  long in_FS_OFFSET;
  undefined4 local_14;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puts("???");
  local_14 = 0;
  __isoc99_scanf(&DAT_00100e27,&local_14);
  check(local_14);
  if (local_10 != *(long *)(in_FS_OFFSET + 0x28)) {
                    /* WARNING: Subroutine does not return */
    __stack_chk_fail();
  }
  return;
}
```

Even though the return statement doesn't seem to return anything, I'll assume that the result of the `check()` function is returned since `question_3()`'s return value is compared to 0 in `main()`. `DAT_00100e27` is again just the `%d` format specifier, so the input to question 3 is going to be a number again. Now the body of the check function:

```c
undefined8 check(uint param_1)

{
  int iVar1;
  int iVar2;
  size_t sVar3;
  undefined8 uVar4;
  long lVar5;
  undefined8 *puVar6;
  long in_FS_OFFSET;
  int local_128;
  int local_124;
  undefined8 local_118;
  long local_10;

  local_10 = *(long *)(in_FS_OFFSET + 0x28);
  puVar6 = &local_118;
  for (lVar5 = 0x1f; lVar5 != 0; lVar5 = lVar5 + -1) {
    *puVar6 = 0;
    puVar6 = puVar6 + 1;
  }
  *(undefined4 *)puVar6 = 0;
  *(undefined2 *)((long)puVar6 + 4) = 0;
  *(undefined *)((long)puVar6 + 6) = 0;
  sprintf((char *)&local_118,"%d",(ulong)param_1);
  sVar3 = strnlen((char *)&local_118,0xff);
  iVar2 = (int)sVar3;
  if ((sVar3 & 1) == 0) {
    if (iVar2 < 4) {
      uVar4 = 0;
    }
    else {
      for (local_128 = 1; iVar1 = iVar2 / 2, local_128 < iVar2 / 2; local_128 = local_128 + 1) {
        if (*(char *)((long)&local_118 + (long)local_128) <=
            *(char *)((long)&local_118 + (long)(local_128 + -1))) {
          uVar4 = 0;
          goto LAB_00100baf;
        }
      }
      do {
        local_124 = iVar1 + 1;
        if (iVar2 <= local_124) {
          uVar4 = 1;
          goto LAB_00100baf;
        }
        lVar5 = (long)iVar1;
        iVar1 = local_124;
      } while (*(char *)((long)&local_118 + (long)local_124) < *(char *)((long)&local_118 + lVar5));
      uVar4 = 0;
    }
  }
  else {
    uVar4 = 0;
  }
LAB_00100baf:
  if (local_10 == *(long *)(in_FS_OFFSET + 0x28)) {
    return uVar4;
  }
                    /* WARNING: Subroutine does not return */
  __stack_chk_fail();
}
```

Most of the `puVar` stuff looks like zeroing memory so I think it's safe to ignore that. In order to get question 3 correct, `check()` has to return a nonzero value, meaning we can't hit any of the `uVar4 = 0` lines.

The first thing that happens aside from `sprintf`ing the input number into a string is a check that `(sVar3 & 1) == 0`. Because `&` is the bitwise and operator, this condition is only true if `sVar3` doesn't have a 1 in the 1 bit, or alternatively when it is even. This means in turn that the length of the input has to be even as well. The length of the input also can't be less than 4 because of the next if statement within that one.

Then we hit the first for loop (I renamed some variables for clarity):

```c
for (i = 1; iVar1 = lengthInt / 2, i < lengthInt / 2; i = i + 1) {
  if (*(char *)((long)&local_118 + (long)i) <= *(char *)((long)&local_118 + (long)(i + -1))) {
    uVar2 = 0;
    goto LAB_00100baf;
  }
}
```

This only iterates over the first half of the string. In order for `check()` to return 0, the inner if statement can't run, so the condition has to always be false. In this case, it's checking that each character\* in the input is less than or equal to the previous one in the input (i.e. if the first half of the string is descending or constant). To avoid that if condition being true, the first part of the input must then consist of ascending digits.

\*It's actually comparing each character's ASCII codepoint, but the comparisons end up being the same as the digits' codepoints still increase with the digit if that makes sense.

Now for the second loop, which turns out to be a do-while loop:

```c
do {
  local_124 = iVar1 + 1;
  if (lengthInt <= local_124) {
    uVar2 = 1;
    goto LAB_00100baf;
  }
  lVar3 = (long)iVar1;
  iVar1 = local_124;
} while (*(char *)((long)&local_118 + (long)local_124) < *(char *)((long)&local_118 + lVar3));
uVar2 = 0;
```

`iVar1` is initialized to half of the length of the input in the first for loop, so this loop starts at the character after the middle of the string. The if statement checks if we've gone beyond the end of the string, in which case the check will have succeeded and we will have found a correct answer to question 3. The last two lines inside the loop just update the positions of the current and previous characters in the string. The while condition is similar to the if condition inside the for loop, but this time it needs to be true for the loop to continue iterating until the inner if statement evaluates to true. The condition in this loop is checking if each character('s ASCII codepoint) is *less* than the previous character, meaning that the second half of the string has to be descending.

Combining all that, the answer to question 3 must be a number with an even number of digits whose digits are *ascending* for the first half and *descending* for the second half of the number. A simple answer to this should be `1221`, which when submitted gives us the flag:

```txt
The flag.txt file not found locally
```

Oops, I probably have to answer the questions on the server to get the flag:

```shell
$ nc chal.ctf-league.osusec.org 31300
POP QUIZ TIME! Can you solve these challenging questions?
What number am I thinking of? 8997
Gimme some characters: hhhh
???
1221
osu{e@s13r_th@n_ph21x_s3r13s}
```

While I haven't taken any classes at OSU in the PH 21X series, I did take AP Physics C: Mechanics and E&M and I will say I had more trouble on this than in those classes (probably due to my lack of experience with C :) ).
