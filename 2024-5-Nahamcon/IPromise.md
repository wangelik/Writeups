# Nahamcon 2024 Challenge: IPromise

This challenge from Nahamcon 2024 CTF is of topic category `reverse engineering` and focuses on encryption within Linux (easy difficulty).
The challenge text was given as:
> Instead of making the next IPhone, I made this challenge. I do make a truthful promise though...   
> Download the file(s) below.

## Enumeration

After downloading the binary, we see, that it is a 64-bit dyn-linked, non-stripped ELF file:
```console
$ file IPromise
IPromise: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, BuildID[sha1]=89878e2c4353d02a9ae4a40d8c831124197d2e30, for GNU/Linux 3.2.0, not stripped
```
There are many tools to start from here (e.g., IDA, gdb, radare, Ghidra), we will use radare.
```console
$ r2 IPromise
[0x004010d0]> iz
[Strings]
nth paddr      vaddr      len size section type  string
―――――――――――――――――――――――――――――――――――――――――――――――――――――――
0   0x00002090 0x00402090 4   5    .rodata ascii lpHP
1   0x0000213b 0x0040213b 9   10   .rodata ascii cU!\f}c|w{
2   0x00002188 0x00402188 4   6    .rodata utf8  R;ֳ) blocks=Basic Latin,Hebrew
3   0x00002197 0x00402197 7   9    .rodata utf8  [j˾9JLX blocks=Basic Latin,Spacing Modifier Letters
4   0x000021c8 0x004021c8 5   7    .rodata utf8  ħ~=d] blocks=Latin Extended-A,Basic Latin
5   0x000021e1 0x004021e1 4   5    .rodata ascii 2:\nI
6   0x00002240 0x00402240 108 109  .rodata ascii I promise that I do some decryption! You just have to find out where. Writing code shouldn't be necessary ;)
7   0x00003044 0x00404044 4   5    .data   ascii \t#qP
```
The stored strings already point into the direction of data encryption, but do not help at this point.   
Moreover, the string at `0x00402240` suggests, that a decryption routine has to be found. Hence, we look at symbols:
```console
[0x004010d0]> aaa
[0x004010d0]> afl
0x00401040    1     11 sym.imp.puts
0x004010d0    1     37 entry0
0x00401065    1     93 sym.decryptIPromise
0x00401633    1      9 sym.AES_init_ctx
0x00401678    1     12 sym.AES_ECB_decrypt
0x00401110    4     31 sym.deregister_tm_clones
0x00401140    4     49 sym.register_tm_clones
0x00401180    3     32 sym.__do_global_dtors_aux
0x004011b0    1      6 sym.frame_dummy
0x004011b6    7    152 sym.KeyExpansion
0x0040124e    5     55 sym.AddRoundKey
0x00401285    1     15 sym.xtime
0x00401294   10    369 sym.Cipher
0x00401405   10    558 sym.InvCipher
0x00401684    6     96 sym.AES_CBC_encrypt_buffer
0x004016e4    6     92 sym.AES_CBC_decrypt_buffer
0x004017c8    1     13 sym._fini
0x0040163c    1     33 sym.AES_init_ctx_iv
0x0040165d    1     15 sym.AES_ctx_set_iv
0x00401740   11    136 sym.AES_CTR_xcrypt_buffer
0x00401100    1      5 sym._dl_relocate_static_pie
0x00401050    1     21 main
0x00401000    3     27 sym._init
0x0040166c    1     12 sym.AES_ECB_encrypt
```
The AES-related entries together with `sym.KeyExpansion` and `sym.AddRoundKey` tell us, that apparently, some AES functionality with ECB and CBC is present. 

## Static Analysis

The main function disassembly looks like:
```asm
[0x004010d0]> pdf @ main
            ;-- section..text:
            ; DATA XREF from entry0 @ 0x4010e8(r)
╭ 21: int main (int argc, char **argv, char **envp);
│           0x00401050      f30f1efa       endbr64                     ; [15] -r-x section size 1912 named .text
│           0x00401054      50             push rax
│           0x00401055      488d3de411..   lea rdi, str.I_promise_that_I_do_some_decryption__You_just_have_to_find_out_where._Writing_code_shouldnt_be_necessary___ ; 0x402240 ; "I promise that I do some decryption! You just have to find out where. Writing code shouldn't be necessary ;)" ; const char *s
│           0x0040105c      e8dfffffff     call sym.imp.puts           ; int puts(const char *s)
│           0x00401061      31c0           xor eax, eax
│           0x00401063      5a             pop rdx
╰           0x00401064      c3             ret
```
Besides shifting our hint to stdout, it does not do much. We thus inspect `sym.decryptIPromise`:
```asm
[0x00401065]> pdf @ sym.decryptIPromise
            ;-- entry.init1:
╭ 93: sym.decryptIPromise ();
│           ; var int64_t var_10h @ rsp+0x10
│           0x00401065      f30f1efa       endbr64
; prepare stack frame
│           0x00401069      55             push rbp
│           0x0040106a      4881ecd000..   sub rsp, 0xd0
│           0x00401071      0f28053812..   movaps xmm0, xmmword [0x004022b0] ; [0x4022b0:16]=-1
; prepare arguments for AES init
│           0x00401078      488d6c2410     lea rbp, [var_10h]
│           0x0040107d      4889e6         mov rsi, rsp
│           0x00401080      4889ef         mov rdi, rbp
│           0x00401083      0f110424       movups xmmword [rsp], xmm0
│           0x00401087      e8a7050000     call sym.AES_init_ctx
; prepare arguments (incl. decrypted bytes) for AES ECB decrypt routines
│           0x0040108c      4889ef         mov rdi, rbp                ; int64_t arg2
│           0x0040108f      488d35aa2f..   lea rsi, obj.encrypted      ; 0x404040
│           0x00401096      e8dd050000     call sym.AES_ECB_decrypt
│           0x0040109b      4889ef         mov rdi, rbp                ; int64_t arg2
│           0x0040109e      488d35ab2f..   lea rsi, [0x00404050]
│           0x004010a5      e8ce050000     call sym.AES_ECB_decrypt
│           0x004010aa      4889ef         mov rdi, rbp                ; int64_t arg2
│           0x004010ad      488d35ac2f..   lea rsi, [0x00404060]
│           0x004010b4      e8bf050000     call sym.AES_ECB_decrypt
│           0x004010b9      4881c4d000..   add rsp, 0xd0
│           0x004010c0      5d             pop rbp
╰           0x004010c1      c3             ret
```
Likely, this is the section we were hinted at in the main print. The encrypted bytes seem to be loaded here:
```asm
0x0040108f      488d35aa2f..   lea rsi, obj.encrypted      ; 0x404040
```
The section does not provide anything interesting as expected:
```asm
[0x00401065]> px 128 @ obj.encrypted
- offset -  4041 4243 4445 4647 4849 4A4B 4C4D 4E4F  0123456789ABCDEF
0x00404040  0f5f a3b9 0923 7150 bb4f 6f6b 881d 96c2  ._...#qP.Ook....
0x00404050  8029 5fe0 7190 64a6 e535 8664 b40c cbb4  .)_.q.d..5.d....
0x00404060  d823 6f12 0254 e20b 9483 de09 f43e 6d24  .#o..T.......>m$
0x00404070  0000 0000 0000 0000 ffff ffff ffff ffff  ................
```

## Dynamic Analysis

As the decryption seems to just run fine in the background, we will run the binary and set a breakpoint at the end of `sym.decryptIPromise`:
```asm
[0x00401065]> db 0x004010b9
[0x00401065]> ood
WARN: Relocs has not been applied. Please use `-e bin.relocs.apply=true` or `-e bin.cache=true` next time
[0x7f9ebc4e1810]> dc
INFO: hit breakpoint at: 0x4010b9
[0x004010b9]> px 128 @ obj.encrypted
- offset -  4041 4243 4445 4647 4849 4A4B 4C4D 4E4F  0123456789ABCDEF
0x00404040  666c 6167 7b64 3431 6438 6364 3938 6630  flag{d41d8cd98f0
0x00404050  3062 3230 3465 3938 3030 3939 3865 6366  xxxxxxxxxxxxxxxf
0x00404060  3834 3237 657d 0a20 2020 2020 2020 2020  8427e}.
0x00404070  0000 0000 0000 0000 0000 0000 0000 0000  ................
```
As expected, the encrypted bytes have been successfully decrypted, revealing our flag.
