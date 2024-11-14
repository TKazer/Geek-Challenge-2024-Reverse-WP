# Geek Challenge 2024 Reverse WP
队伍名：UF@F菜鸟向后冲 

成员：Liv、yyyxxx

萌新第一次组队参加CTF比赛，这边给出Reverse四周的WP

- [1. Week1](#Week1)
  * [(1) 先来一道签到题](#先来一道签到题)
  * [(2) Hello_re](#Hello_re)
  * [(3) 让我康康你的调试](#让我康康你的调试)
  * [(4) ezzzz](#ezzzz)
  * [(5) 也许你也听jay](#也许你也听jay)
  * [(6) 我勒个z3啊](#我勒个z3啊)
- [2. Week2](#Week2)
  * [(1) 玩就行了](#玩就行了)
  * [(2) 好像是python?](#好像是python)
  * [(3) 奇怪的RC4](#奇怪的RC4)
  * [(4) 长颈鹿喜欢吃彩虹](#长颈鹿喜欢吃彩虹)
  * [(5) DH爱喝茶](#DH爱喝茶)
  * [(6) CPP_flower](#CPP_flower)
- [3. Week3](#Week3)
  * [(1) ez_hook](#ez_hook)
  * [(2) AES!](#AES)
  * [(3) 致我的星星 (非预期解)](#致我的星星)
  * [(4) 你干嘛~~ (非预期解)](#你干嘛)
  * [(5) LinkedListModular](#LinkedListModular)
  * [(6) blasting_master](#blasting_master)
- [4. Week4](#Week4)
  * [(1) ez_re](#ez_re)
  * [(2) ez_raw](#ez_raw)
  * [(3) 贝斯！贝斯！](#贝斯_贝斯_)
  * [(4) baby_vm](#baby_vm)

## Week1

### 先来一道签到题

下载得到一份汇编代码源码文件

关注重点文本加密代码

```
.L3:
    movl    -84(%rbp), %eax          
    movl    %eax, %ecx               
    shl     %ecx                      
    movzbl  (%rdi,%rcx), %eax        
    xorb    $7, %al                  
    movb    %al, (%rdi,%rcx)          
    movzbl  1(%rdi,%rcx), %eax        
    subb    $5, %al                    
    movb    %al, 1(%rdi,%rcx)       
    addl    $1, -84(%rbp)           
.L2:
    movl    -84(%rbp), %eax
    imull   $2, %eax                  
    cmpl    $36, %eax                 
    jl      .L3
```

以上代码转成c++伪代码如下

```c++
char Str[36] = "..."
for(int i = 0; i < 36; i+=2)
{
    Str[i] ^= 7;
    Str[i + 1] -= 5;
}
```

通过逆向计算，就可以解密被加密的Flag文本。

```c++
char Str[36] = "TTDv^jrZu`Gg6tXfi+pZojpZSjXmbqbmt.&x"
for(int i = 0; i < 36; i+=2)
{
    Str[i] ^= 7;
    Str[i + 1] += 5;
}
// SYC{H3lI0_@_new_R3vers3_Ctf3r!!}
```

### Hello_re

用Detect It Easy查壳发现加了UPX壳，尝试直接用upx.exe进行脱壳，发现没办法直接脱壳，应该是变异UPX。

直接用dbg手动脱壳，找到解压段，这个jmp前面是循环解压代码段，在这个jmp后的pop命令下断点然后直接dump即可。

![QQ_1730893559926]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/hello_re_dbg.png)

直接启动IDA分析dump的exe文件，然后在string窗口里面找到关键字符串跳过去，查看交叉引用定位到主函数。

```c++
__int64 sub_7FF7FC8214CA()
{
  _DWORD v1[34]; // [rsp+20h] [rbp-60h] BYREF
  __int64 v2; // [rsp+A8h] [rbp+28h] BYREF
  char v3[32]; // [rsp+B0h] [rbp+30h] BYREF
  _DWORD v4[34]; // [rsp+D0h] [rbp+50h]
  int i; // [rsp+158h] [rbp+D8h]
  int v6; // [rsp+15Ch] [rbp+DCh]

  sub_7FF7FC82173E();
  v4[0] = 0;
  v4[1] = 1;
  v4[2] = 2;
  v4[3] = 52;
  v4[4] = 3;
  v4[5] = 96;
  v4[6] = 47;
  v4[7] = 28;
  v4[8] = 107;
  v4[9] = 15;
  v4[10] = 9;
  v4[11] = 24;
  v4[12] = 45;
  v4[13] = 62;
  v4[14] = 60;
  v4[15] = 2;
  v4[16] = 17;
  v4[17] = 123;
  v4[18] = 39;
  v4[19] = 58;
  v4[20] = 41;
  v4[21] = 48;
  v4[22] = 96;
  v4[23] = 26;
  v4[24] = 8;
  v4[25] = 52;
  v4[26] = 63;
  v4[27] = 100;
  v4[28] = 33;
  v4[29] = 106;
  v4[30] = 122;
  v4[31] = 48;
  v2 = 0x5245564F4C435953LL;
  sub_7FF7FC8213B4(aPleaseEnterYou);
  sub_7FF7FC821360("%32s", v3);
  sub_7FF7FC821408((__int64)v3, (__int64)&v2, (__int64)v1);
  v6 = 1;
  for ( i = 0; i <= 31; ++i )
  {
    if ( v1[i] != v4[i] )
    {
      v6 = 0;
      break;
    }
  }
  if ( v6 )
    sub_7FF7FC8213B4(aCongratulation);
  else
    sub_7FF7FC8213B4(aTryAgain);
  return 0LL;
}
```

以下为加密函数。

```c++
__int64 __fastcall sub_7FF7FC821408(__int64 a1, __int64 a2, __int64 a3)
{
  __int64 result; // rax
  int j; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 31; ++i )
  {
    result = (unsigned int)*(char *)(i + a1);
    *(_DWORD *)(4LL * i + a3) = result;
  }
  for ( j = 0; j <= 31; ++j )
  {
    result = j ^ *(_DWORD *)(4LL * j + a3) ^ (unsigned int)*(char *)(j % 8 + a2);
    *(_DWORD *)(4LL * j + a3) = result;
  }
  return result;
}
```

可以看到是简单的异或计算，并且观察到v2 = 0x5245564F4C435953LL;即为用来异或计算的一个Key。

直接写出解密代码即可。

```c++
DWORD e_Flag[] = 
{0, 1, 2, 52, 3, 96, 47, 28,
107, 15, 9, 24, 45, 62, 60, 2,
17, 123, 39, 58, 41, 48, 96, 26,
8, 52, 63, 100, 33, 106, 122, 48};
DWORD64 Key = 0x5245564F4C435953LL;

std::string Flag;

char KeyBuffer[8]{};
memcpy_s(KeyBuffer, 8, (void*)&Key, 8);

for (int i = 0; i <= 31; i++) 
{
	DWORD Result = i ^ e_Flag[i] ^ static_cast<DWORD>(KeyBuffer[i % 8]);
	Flag += (char)Result;
}

std::cout<< Flag <<std::endl;

// SYC{H3lI0_@_new_R3vers3_Ctf3r!!}
```

### 让我康康你的调试

直接拖入IDA分析

主函数：

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  unsigned int i; // [rsp+4h] [rbp-7Ch]
  char v5[57]; // [rsp+17h] [rbp-69h] BYREF
  _QWORD s2[4]; // [rsp+50h] [rbp-30h] BYREF
  char v7; // [rsp+70h] [rbp-10h]
  unsigned __int64 v8; // [rsp+78h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  strcpy(v5, "syclover");
  s2[0] = 0xA67A02C9047D5B94LL;
  s2[1] = 0x7EF9680DBC980739LL;
  s2[2] = 0x7104F81698BFBD08LL;
  s2[3] = 0x61DB8498B686155FLL;
  v7 = 109;
  puts(&s);
  __isoc99_scanf("%33s", &v5[9]);
  for ( i = 0; i <= 32; ++i )
    v5[i + 9] ^= 20u;
  sub_14A6((__int64)&v5[9], 0x21uLL, (__int64)v5, 8uLL);
  if ( !memcmp(&v5[9], s2, 33uLL) )
    puts(&byte_2048);
  else
    puts(&byte_2090);
  puts("Press Enter to exit...");
  getchar();
  getchar();
  return 0;
}
```

加密函数：

```c++
unsigned __int64 __fastcall sub_14A6(__int64 pStr, unsigned __int64 StrLen, __int64 Key, unsigned __int64 KeyLen)
{
  char v5; // [rsp+2Bh] [rbp-125h]
  int v6; // [rsp+2Ch] [rbp-124h]
  int v7; // [rsp+30h] [rbp-120h]
  unsigned __int64 i; // [rsp+38h] [rbp-118h]
  _BYTE state[264]; // [rsp+40h] [rbp-110h] BYREF
  unsigned __int64 v10; // [rsp+148h] [rbp-8h]

  v10 = __readfsqword(0x28u);
  // 这里用Key初始化state数组
  sub_11C9((__int64)state, Key, KeyLen);
  v6 = 0;
  v7 = 0;
  // 以下是用state对原始Str进行加密计算
  for ( i = 0LL; i < StrLen; ++i )
  {
    v6 = (v6 + 1) % 256;
    v7 = (v7 + (unsigned __int8)state[v6]) % 256;
    v5 = state[v6];
    state[v6] = state[v7];
    state[v7] = v5;
    *(_BYTE *)(pStr + i) ^= state[(unsigned __int8)(state[v6] + state[v7])];
  }
  return __readfsqword(0x28u) ^ v10;
}
```

Key初始化函数：

```c++
unsigned __int64 __fastcall sub_11C9(__int64 pState, __int64 Key, unsigned __int64 KeyLen)
{
  char v4; // [rsp+27h] [rbp-119h]
  int i; // [rsp+28h] [rbp-118h]
  int j; // [rsp+28h] [rbp-118h]
  int v7; // [rsp+2Ch] [rbp-114h]
  _QWORD v8[33]; // [rsp+30h] [rbp-110h] BYREF
  unsigned __int64 v9; // [rsp+138h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v7 = 0;
  memset(v8, 0, 256);
  for ( i = 0; i <= 255; ++i )
  {
    *(_BYTE *)(i + pState) = i;
    *((_BYTE *)v8 + i) = *(_BYTE *)(i % KeyLen + Key);
  }
  for ( j = 0; j <= 255; ++j )
  {
    v7 = (*((char *)v8 + j) + v7 + *(unsigned __int8 *)(j + pState)) % 256;
    v4 = *(_BYTE *)(j + pState);
    *(_BYTE *)(j + pState) = *(_BYTE *)(v7 + pState);
    *(_BYTE *)(pState + v7) = v4;
  }
  return __readfsqword(0x28u) ^ v9;
}
```

分析下来，主流程为：输入字符串->输入字符串 Xor 20->RC4加密

就可以直接开始写解密脚本，Key是"syclover"，s2为密文，进行RC4解密即可。

```c++
// sub_11C9
void InitKey(BYTE* State, char* Key, DWORD KeyLen)
{
	for (int i = 0; i < 256; i++)
		State[i] = i;
    
	for (int i = 0; i < 256; i++)
	{
		int Result = (Result + State[i] + Key[i % KeyLen]) % 256;
		std::swap(State[Result], State[i]);
	}
}

// sub_14A6
void Decrypt(char* Data, DWORD DataLen, char* Key, DWORD KeyLen)
{
	BYTE State[264]{};
	InitKey(State, Key, KeyLen);

	int v6 = 0, v7 = 0;
	for (int i = 0; i < DataLen; i++)
	{
		v6 = (v6 + 1) % 256;
		v7 = (v7 + State[v6]) % 256;
		std::swap(State[v6], State[v7]);
		Data[i] ^= State[(unsigned __int8)(State[v6] + State[v7])];
	}
}

int main()
{
    char s2[] = {
        0x94, 0x5B, 0x7D, 0x04, 0xC9, 0x02, 0x7A, 0xA6,
        0x39, 0x07, 0x98, 0x0D, 0x0B, 0x68, 0xF9, 0x7E,
        0x08, 0xBD, 0xBF, 0x98, 0x16, 0xF8, 0x04, 0x71,
        0x5F, 0x15, 0x86, 0xB6, 0x98, 0x84, 0xDB, 0x61,
        0x6D
    };

    char Key[] = "syclover";

    Decrypt(s2, 33, Key, 8);

    for (int i = 0; i < 33; ++i) 
        s2[i] ^= 20;

    std::cout<< s2 <<std::endl;

    // SYC{we1come_t0_Geek's_3asy_rc4!}
}

```

### ezzzz

APK逆向题目，直接用jadx加载。

MainActivity文件：

```java
package com.example.ezzzz;

import android.os.Bundle;
import android.view.View;
import android.widget.Button;
import android.widget.EditText;
import android.widget.Toast;
import androidx.appcompat.app.AppCompatActivity;

/* loaded from: classes.dex */
public class MainActivity extends AppCompatActivity {
    private Button btn;
    private EditText et;

    /* JADX INFO: Access modifiers changed from: protected */
    @Override // androidx.fragment.app.FragmentActivity, androidx.activity.ComponentActivity, androidx.core.app.ComponentActivity, android.app.Activity
    public void onCreate(Bundle bundle) {
        super.onCreate(bundle);
        setContentView(R.layout.activity_main);
        this.btn = (Button) findViewById(R.id.btn);
        this.et = (EditText) findViewById(R.id.et);
        this.btn.setOnClickListener(new View.OnClickListener() { // from class: com.example.ezzzz.MainActivity.1
            @Override // android.view.View.OnClickListener
            public void onClick(View view) {
                MainActivity.this.check();
            }
        });
    }

    public void check() {
        if (Enc.encrypt(this.et.getText().toString()).equals(getResources().getString(R.string.target))) {
            Toast.makeText(this, "Wow!You are right!!!", 0).show();
        } else {
            Toast.makeText(this, "Emmmmm……wrong????", 0).show();
        }
    }
}
```

Enc文件：

```java
package com.example.ezzzz;

/* loaded from: classes.dex */
public class Enc {
    private static final int DELTA = -1640531527;

    public static String encrypt(String str) {
        int length = str.length();
        int[] Flag = new int[length];
        for (int i = 0; i < length; i++) {
            Flag[i] = str.charAt(i);
        }
        int[] Key = new int[4];
        for (int i2 = 0; i2 < 4; i2++) {
            Key[i2] = "GEEK".charAt(i2);
        }
        for (int i3 = 0; i3 < length; i3 += 2) {
            int i4 = i3 + 1;
            int[] En_Str = {Flag[i3], Flag[i4]};
            encrypt(En_Str, Key);
            Flag[i3] = En_Str[0];
            Flag[i4] = En_Str[1];
        }
        StringBuilder sb = new StringBuilder();
        for (int i5 = 0; i5 < length; i5++) {
            sb.append(String.format("%08x", Integer.valueOf(Flag[i5])));
        }
        return sb.toString();
    }

    private static void encrypt(int[] iArr, int[] iArr2) {
        int i = iArr[0];
        int i2 = iArr[1];
        int i3 = 0;
        for (int i4 = 0; i4 < 32; i4++) {
            i += ((((i2 << 4) ^ (i2 >> 5)) + i2) ^ (iArr2[i3 & 3] + i3)) ^ (i3 + i4);
            i3 -= 1640531527;
            i2 += ((((i << 4) ^ (i >> 5)) + i) ^ (iArr2[(i3 >>> 11) & 3] + i3)) ^ (i3 + i4);
        }
        iArr[0] = i;
        iArr[1] = i2;
    }
}
```

发现是Xtea加密，现在主要的问题是拿到Flag加密后的字节数据，这边是使用AndroidKiller修改代码将错误输出的文本改成加密的Flag资源数据。

把上面获取Flag加密字节数据的代码复制替换第二个Text输出的字符串数据，编译安装运行，随便输入一串字符串即可输出加密后的Flag字节。

![QQ_1730896023797]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/AndroidKiller.png)

![QQ_1730896161671]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/AndroidOuput.png)

拿到加密Flag数据后就可以利用Xtea解密出Flag。

```java
public class Main {
       public static String decrypt_s(String hexStr) {
        int length = hexStr.length() / 8;
        int[] Flag = new int[length];
        for (int i = 0; i < length; i++) {
            Flag[i] = (int) Long.parseLong(hexStr.substring(i * 8, (i + 1) * 8), 16);
        }
        int[] Key = new int[4];
        for (int i2 = 0; i2 < 4; i2++) {
            Key[i2] = "GEEK".charAt(i2);
        }

        for (int i3 = 0; i3 < length; i3 += 2) {
            int i4 = i3 + 1;
            int[] En_Str = {Flag[i3], Flag[i4]};
            decrypt(En_Str, Key);
            Flag[i3] = En_Str[0];
            Flag[i4] = En_Str[1];
        }

        StringBuilder sb = new StringBuilder();
        for (int i5 = 0; i5 < length; i5++) {
            sb.append((char) Flag[i5]);
        }
        return sb.toString();
    }

    private static void decrypt(int[] iArr, int[] iArr2) {
        int i = iArr[0];
        int i2 = iArr[1];
        int i3 = -1640531527 * 32;
        for (int i4 = 31; i4 >= 0; i4--) {
            i2 -= ((((i << 4) ^ (i >> 5)) + i) ^ (iArr2[(i3 >>> 11) & 3] + i3)) ^ (i3 + i4);
            i3 += 1640531527;
            i -= ((((i2 << 4) ^ (i2 >> 5)) + i2) ^ (iArr2[i3 & 3] + i3)) ^ (i3 + i4);
        }
        iArr[0] = i;
        iArr[1] = i2;
    }

    public static void main(String[] args) {
        System.out.printf(decrypt_s("f1f186b25a96c782e6c63a0b70b61b5ced6bf84889700d6b09381b5ccb2f24fab1c79e796d822d9cdcc55f760f780e750d65c4afb89084a9e978c3827a8dd81091f28df3a84dbacab4d75f75f19af8e5b90f80fcfc10a5c3d20679fb2bc734c8ccb31c921ac52ad3e7f922b72e24d923fb4ce9f53548a9e571ebc25adf38862e10059186327509463dd4d54c905abc36c26d5312d2cd42c0772d99e50cd4c4665c3178d63a7ffe71ada251c070568d5a5798c2921ec0f7fc3ae9d8418460762930ca6a2dccef51d2a1a8085491b0f82d686ca34774c52d0f0f26449fc28d362c86f3311b8adc4fb1a4497e34e0f0915d"));
    
        // SYC{g0od_j0b_wweLCoMeToooSSSyC_zz_1_et3start_yoUr_j0urney!!}
    }
}
```

### 也许你也听jay

下载得到key.txt

```c++
#include <stdio.h>

int main() {
   
    char URL[46];
    char o00O0OO000OO0oooo0o0oo0O0oo000000O0O0OO0O0O00OO0OO0O[46];
    strcpy(o00O0OO000OO0oooo0o0oo0O0oo000000O0O0OO0O0O00OO0OO0O, URL);
    char o00O0OO000OO0oooo0o0oo0O0oo000000O0O0OO0O00000O0OO0O[] = {0x96, 0xa1, 0xa0, 0x9b, 0x9b, 0x5f, 0x49, 0x46, 0x85, 0x82, 0x53, 0x95, 0x7d, 0x36, 0x8d, 0x74, 0x82, 0x88, 0x46, 0x7a, 0x81, 0x65, 0x80, 0x6c, 0x78, 0x2f, 0x6b, 0x6a, 0x27, 0x50, 0x61, 0x38, 0x3f, 0x37, 0x33, 0xf1, 0x27, 0x32, 0x34, 0x1f, 0x39, 0x23, 0xde, 0x1c, 0x17, 0xd4};
    int  o00O0OO000OO0oooo0o0oo0O0000oooooooO0O0OO0O0O00OO0OO0O[] = {0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D};
    int  o00O0OO000OO0oooo0o0oo0O000O0OO0O0O00OO0OO0O00000[] = {0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4F, 0x4E, 0x4D, 0x4C, 0x4B, 0x4A, 0x49, 0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, 0x40, 0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20, 0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01};
    int o00O0OO000OO0oooo0o0oo0O000000O00O0O0OO0O0O00OO0OO0O[]={0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4F, 0x4E, 0x4D, 0x4C, 0x4B, 0x4A, 0x49, 0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, 0x40, 0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x00, 0x31, 0x30, 0x2F};
    int len = strlen(URL);
    for(int i = 0; i < len; i++) {
        o00O0OO000OO0oooo0o0oo0O000000O00O0O0OO0O0O00OO0OO0O[i] ^=  o00O0OO000OO0oooo0o0oo0O000O0OO0O0O00OO0OO0O00000[i+1];  
        
    }
    for(int i = 0; i < len; i++) {
        o00O0OO000OO0oooo0o0oo0O0oo000000O0O0OO0O0O00OO0OO0O[i] ^=  o00O0OO000OO0oooo0o0oo0O0000oooooooO0O0OO0O0O00OO0OO0O[i];  
        
    }
     for(int i = 0; i < len; i++) {
        o00O0OO000OO0oooo0o0oo0O000000O00O0O0OO0O0O00OO0OO0O[i] -=  o00O0OO000OO0oooo0o0oo0O0000oooooooO0O0OO0O0O00OO0OO0O[i];  
        
    }
    for(int i = 0; i < len; i++) {
            o00O0OO000OO0oooo0o0oo0O0oo000000O0O0OO0O0O00OO0OO0O[i] -=  o00O0OO000OO0oooo0o0oo0O0000oooooooO0O0OO0O0O00OO0OO0O[47 + i];  
             o00O0OO000OO0oooo0o0oo0O0000oooooooO0O0OO0O0O00OO0OO0O[i]^=o00O0OO000OO0oooo0o0oo0O000000O00O0O0OO0O0O00OO0OO0O[51];
        
}
    for(int i = 0; i < len; i++) {
        o00O0OO000OO0oooo0o0oo0O0oo000000O0O0OO0O0O00OO0OO0O[i] +=  o00O0OO000OO0oooo0o0oo0O000O0OO0O0O00OO0OO0O00000[i];  
    }
    for(int i=0;i<len;i++){
        if(o00O0OO000OO0oooo0o0oo0O0oo000000O0O0OO0O0O00OO0OO0O[i] != o00O0OO000OO0oooo0o0oo0O0oo000000O0O0OO0O00000O0OO0O[i]){
            printf("Error");
        }
    }
    
    return 0;
}
```

直接用VS重命名变量名

```c++
int main() {

	char URL[46];
	char Input[46];
	strcpy(Input, URL);
	char Origin[] = { 0x96, 0xa1, 0xa0, 0x9b, 0x9b, 0x5f, 0x49, 0x46, 0x85, 0x82, 0x53, 0x95, 0x7d, 0x36, 0x8d, 0x74, 0x82, 0x88, 0x46, 0x7a, 0x81, 0x65, 0x80, 0x6c, 0x78, 0x2f, 0x6b, 0x6a, 0x27, 0x50, 0x61, 0x38, 0x3f, 0x37, 0x33, 0xf1, 0x27, 0x32, 0x34, 0x1f, 0x39, 0x23, 0xde, 0x1c, 0x17, 0xd4 };
	int  Key1[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D };
	int  Key2[] = { 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4F, 0x4E, 0x4D, 0x4C, 0x4B, 0x4A, 0x49, 0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, 0x40, 0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20, 0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };
	int Key3[] = { 0x65, 0x64, 0x63, 0x62, 0x61, 0x60, 0x5F, 0x5E, 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4F, 0x4E, 0x4D, 0x4C, 0x4B, 0x4A, 0x49, 0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, 0x40, 0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x00, 0x31, 0x30, 0x2F };
	int len = strlen(URL);
	for (int i = 0; i < len; i++) {
		Key3[i] ^= Key2[i + 1];

	}
	for (int i = 0; i < len; i++) {
		Input[i] ^= Key1[i];

	}
	for (int i = 0; i < len; i++) {
		Key3[i] -= Key1[i];

	}
	for (int i = 0; i < len; i++) {
		Input[i] -= Key1[47 + i];
		Key1[i] ^= Key3[51];

	}
	for (int i = 0; i < len; i++) {
		Input[i] += Key2[i];
	}
	for (int i = 0; i < len; i++) {
		if (Input[i] != Origin[i]) {
			printf("Error");
		}
	}

	return 0;
}
```

可以发现Key3没有用到，可以直接省略Key3相关代码，然后进行解密计算，解密Origin数据

```c++
char Origin[] = { 0x96, 0xa1, 0xa0, 0x9b, 0x9b, 0x5f, 0x49, 0x46, 0x85, 0x82, 0x53, 0x95, 0x7d, 0x36, 0x8d, 0x74, 0x82, 0x88, 0x46, 0x7a, 0x81, 0x65, 0x80, 0x6c, 0x78, 0x2f, 0x6b, 0x6a, 0x27, 0x50, 0x61, 0x38, 0x3f, 0x37, 0x33, 0xf1, 0x27, 0x32, 0x34, 0x1f, 0x39, 0x23, 0xde, 0x1c, 0x17, 0xd4 };
int  Key2[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F, 0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F, 0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3A, 0x3B, 0x3C, 0x3D, 0x3E, 0x3F, 0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4A, 0x4B, 0x4C, 0x4D, 0x4E, 0x4F, 0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5A, 0x5B, 0x5C, 0x5D, 0x5E, 0x5F, 0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6A, 0x6B, 0x6C, 0x6D, 0x6E, 0x6F, 0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7A, 0x7B, 0x7C, 0x7D, 0x7E, 0x7F, 0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87, 0x88, 0x89, 0x8A, 0x8B, 0x8C, 0x8D };
int  Key1[] = { 0x5D, 0x5C, 0x5B, 0x5A, 0x59, 0x58, 0x57, 0x56, 0x55, 0x54, 0x53, 0x52, 0x51, 0x50, 0x4F, 0x4E, 0x4D, 0x4C, 0x4B, 0x4A, 0x49, 0x48, 0x47, 0x46, 0x45, 0x44, 0x43, 0x42, 0x41, 0x40, 0x3F, 0x3E, 0x3D, 0x3C, 0x3B, 0x3A, 0x39, 0x38, 0x37, 0x36, 0x35, 0x34, 0x33, 0x32, 0x31, 0x30, 0x2F, 0x2E, 0x2D, 0x2C, 0x2B, 0x2A, 0x29, 0x28, 0x27, 0x26, 0x25, 0x24, 0x23, 0x22, 0x21, 0x20, 0x1F, 0x1E, 0x1D, 0x1C, 0x1B, 0x1A, 0x19, 0x18, 0x17, 0x16, 0x15, 0x14, 0x13, 0x12, 0x11, 0x10, 0x0F, 0x0E, 0x0D, 0x0C, 0x0B, 0x0A, 0x09, 0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01 };


for (int i = 0; i < 46; i++)
{
	Origin[i] -= Key1[i];
    Origin[i] += Key2[47 + i];
    Origin[i] ^= Key2[i];
}

// https://am1re-sudo.github.io/Coisni.github.io/

std::cout << Origin <<std::endl;
```

解密得到一个网站，在网站里找到密文"Q7u+cyiOQtKHRMqZNzPpApgmTL4j+TE="和密码"lovebeforeBC"。

根据网站文本提示用RC4进行解密，得到"SYC{ILIKELISTENJAYSONG}"

### 我勒个z3啊

直接IDA分析

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD key[2]; // [rsp+30h] [rbp-50h] BYREF
  int v5; // [rsp+40h] [rbp-40h]
  _BYTE flag[96]; // [rsp+50h] [rbp-30h] BYREF
  int v7; // [rsp+B0h] [rbp+30h]
  int i; // [rsp+BCh] [rbp+3Ch]

  sub_401F00(argc, argv, envp);
  memset(flag, 0, sizeof(flag));
  v7 = 0;
  key[0] = 0LL;
  key[1] = 0LL;
  v5 = 0;
  sub_401C41();
  for ( i = 0; ; ++i )
  {
    tempChar = getchar();
    if ( tempChar == 10 || i == 16 )
      break;
    *((_BYTE *)key + i) = tempChar;
  }
  *((_BYTE *)key + i) = 0;
  // sub_401B7B
  CheckKey((const char *)key);
  puts("[+]>>>flag:");
  for ( i = 0; ; ++i )
  {
    tempChar = getchar();
    if ( tempChar == 10 || i == 32 )
      break;
    flag[i] = tempChar;
  }
  Encode(flag, (__int64)key);
  if ( !(unsigned int)sub_40179A((__int64)flag) )
  {
    puts("[~]NO,Something_gets_wrong. TT.TT");
    exit(0);
  }
  puts("[~]Wow_you_get_it!!");
  return 0;
}
```

首先找加密后的Flag数据，发现没有直接数据，在sub_40179A是通过一堆计算进行检查Flag，直接进行约束条件求解。

```c++
__int64 __fastcall sub_40179A(__int64 a1)
{
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 31; i += 4 )
  {
    if ( *(char *)(a1 + i) + 8 * *(char *)(a1 + i + 1) + 6 * *(char *)(a1 + i + 2) + *(char *)(a1 + i + 3) != dword_4040A0[i]
      || *(char *)(a1 + i + 1) + 8 * *(char *)(a1 + i + 2) + 6 * *(char *)(a1 + i + 3) + *(char *)(a1 + i) != dword_4040A0[i + 1]
      || *(char *)(a1 + i + 2) + 8 * *(char *)(a1 + i + 3) + 6 * *(char *)(a1 + i) + *(char *)(a1 + i + 1) != dword_4040A0[i + 2]
      || *(char *)(a1 + i + 3) + 8 * *(char *)(a1 + i) + 6 * *(char *)(a1 + i + 1) + *(char *)(a1 + i + 2) != dword_4040A0[i + 3] )
    {
      return 0LL;
    }
  }
  return 1LL;
}
```

这边我是使用sympy库进行求解，没有用题目所说z3 

```python
from sympy import symbols, Eq, solve

a = symbols('a0:32')

constraints = [
411,275,393,457,592,1334,1246,444,1051,1828,1744,1185,1605,1141,1226,1676,997
,455,829,1463,653,580,782,657,625,769,1119,1135,1303,1054,1062,1205
]

eqs = []
for i in range(0, 32, 4):
    eqs.append(Eq(a[i] + 8 * a[i+1] + 6 * a[i+2] + a[i+3], constraints[i]))
    eqs.append(Eq(a[i+1] + 8 * a[i+2] + 6 * a[i+3] + a[i], constraints[i+1]))
    eqs.append(Eq(a[i+2] + 8 * a[i+3] + 6 * a[i] + a[i+1], constraints[i+2]))
    eqs.append(Eq(a[i+3] + 8 * a[i] + 6 * a[i+1] + a[i+2], constraints[i+3]))

solution = solve(eqs)

for i in range(0,32):
    print(solution[a[i]],end=",")

#23,40,7,26,29,3,69,125,111,9,125,118,99,126,74,54,112,89,28,5,25,63,9,70,111,26,43,48,58,102,60,69

```

求解出符合条件的加密后数据。

接下来分析加密过程，第一步是先输入Key，然后检查Key是否合法。

```c++
// sub_401B7B
int __fastcall CheckKey(const char *a1)
{
  char Destination[24]; // [rsp+20h] [rbp-20h] BYREF
  int j; // [rsp+38h] [rbp-8h]
  int i; // [rsp+3Ch] [rbp-4h]

  strncpy(Destination, a1, 0x11uLL);
  for ( i = 0; Destination[i]; ++i )
  {
    for ( j = 0; j <= 63; ++j )
    {
      if ( Destination[i] == (unsigned __int8)a0123456789abcd[j] )
      {
        Destination[i] = j;
        break;
      }
    }
  }
  if ( strcmp(Destination, Str2) )
  {
    puts("[~]Maybe you should reverse this data creafully.see you again!(or idapatch is a good choise also)");
    exit(0);
  }
  return puts("[~]Good lets check your flag.");
}
```

是取输入Key的对应字符下标构成下标数组，然后与Str2对比。

那么直接导出Str2的下标数据数组，进行逆向匹配字符数组即可拿到Key。

```c++
int Str2[]{ 42,14,14,20,63, 63,63,38,17, 10,21,21,14, 23,16,14 };
char chrList[] = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ?_";

for (int i = 0; i < 16; i++)
{
	std::cout << chrList[Str2[i]];
}
// Geek___Challenge

```

接下来分析Encode函数

```c++
__int64 __fastcall sub_4019EB(__int64 a1)
{
  __int64 result; // rax
  char v2; // [rsp+3h] [rbp-Dh]
  int k; // [rsp+4h] [rbp-Ch]
  int j; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 7; ++i )
  {
    for ( j = 0; ; ++j )
    {
      result = (unsigned int)j;
      if ( j >= i )
        break;
      v2 = *(_BYTE *)(a1 + 4 * i);
      for ( k = 0; k <= 2; ++k )
        *(_BYTE *)(a1 + 4 * i + k) = *(_BYTE *)(4 * i + k + 1LL + a1);
      *(_BYTE *)(a1 + 4 * i + 3LL) = v2;
    }
  }
  return result;
}

const char *__fastcall Encode(const char *a1, __int64 Key)
{
  const char *result; // rax
  int v3; // [rsp+28h] [rbp-8h]
  int i; // [rsp+2Ch] [rbp-4h]

  sub_4019EB((__int64)a1);
  result = (const char *)strlen(a1);
  v3 = (int)result;
  for ( i = 0; i <= 31; ++i )
  {
    a1[i] ^= a1[(v3 + i - 1) % v3];
    result = &a1[i];
    *result ^= *(_BYTE *)(Key + (47 - i) % 16) ^ (unsigned __int8)i;
  }
  return result;
}
```

 观察到，他是先将输入的字符串用sub_4019EB函数进行处理，然后再进行一次加密计算。

sub_4019EB是将字符串进行左移操作，简化伪代码如下

```c++
char a1[]{};
// 将32字节分为8组
for(int i = 0; i <= 7; i++)
{
    // 每4个字符为一组，将第i-1组字符左移i次
    for(int j = 0; j < i; j++)
    {
        // 保存第一个字节
        char FirstChar = a1[4*i];
        for(int k = 0; k <= 2; k++)
        {
            a1[4*i + k] = a1[4*i + k + 1]
        }
        a1[4*i + k + 3] = FirstChar;
    }
}
```

通过以上逻辑即可写出逆向解密代码，右移回去，以下为sub_4019EB的逆向计算代码。

```c++
void Re_sub_4019EB(char* a1)
{
    for (int i = 7; i >= 0; --i)
    {
        for (int j = i - 1; j >= 0; --j)
        {
            char LastChar = a1[4 * i + 3];
            for (int k = 2; k >= 0; --k)
                a1[4 * i + k + 1] = a1[4 * i + k];
            a1[4 * i] = LastChar;
        }
    }
}
```

再结合Encode函数内调用左移函数后的加密代码，写出解密代码解密出Flag。

完整解密代码如下：

```c++
void Re_sub_4019EB(char* a1)
{
    for (int i = 7; i >= 0; --i)
    {
        for (int j = i - 1; j >= 0; --j)
        {
            char LastChar = a1[4 * i + 3];
            for (int k = 2; k >= 0; --k)
                a1[4 * i + k + 1] = a1[4 * i + k];
            a1[4 * i] = LastChar;
        }
    }
}

void Decrypt(char* Str, char* Key)
{
    char result;
    int v3 = strlen(Str);
    
    for (int i = 31; i >= 0; --i)
    {
        result = a1[i] ^ Key[(47 - i) % 16] ^ (unsigned __int8)i;
        a1[i] = a1[(v3 + i - 1) % v3] ^ result;
        result = a1[i];
    }

    Re_sub_4019EB(Str);
}

int main()
{
	char e_Flag[]{23,40,7,26,29,3,69,125,111,9,125,118,99,126,74,54,112,89,28,5,25,63,9,70,111,26,43,48,58,102,60,69};
    char Key_str[] = "Geek___Challenge";

    Decrypt(e_Flag, Key_str);

    std::cout << b << std::endl;

    // SYC{Wow!!_Y0u_4r3_9o0d_At_r3$!!}   
}
```

## Week2

### 玩就行了

打开游戏，发现要求目标钱数为666，直接用CheatEngine修改当前金钱为666，然后再抓一次矿物，发现游戏目录下输出了一个Data.txt文件，发现是一个exe程序的字节数据，直接转储为exe程序，然后用IDA分析程序。

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char v4[117]; // [rsp+2Bh] [rbp-55h] BYREF
  char Str[108]; // [rsp+A0h] [rbp+20h] BYREF
  int v6; // [rsp+10Ch] [rbp+8Ch]

  sub_14000181E(argc, argv, envp);
  strcpy(v4, "GEEK");
  sub_1400013B4("WOW~~Niceeeee to see you here!!!\n");
  sub_1400013B4("Welcome to GEEK Challenge!!!!!\n");
  sub_1400013B4("Please input your answer~\n");
  sub_140001360("%s", Str);
  v6 = strlen(Str);
  sub_14000144B(Str, 20);
  sub_140001596(Str, v4);
  sub_14000161C(Str, (__int64)&v4[5]);
  if ( !strcmp(&v4[5], "0A161230300C2D0A2B303D2428233005242C2D26182206233E097F133A") )
    sub_1400013B4("G00D!!!");
  else
    sub_1400013B4("Try again.");
  sub_1400013B4("\nPress any key to continue...");
  getchar();
  return 0;
}

__int64 __fastcall sub_14000144B(const char *a1, int a2)
{
  __int64 result; // rax
  char v3; // [rsp+27h] [rbp-9h]
  int v4; // [rsp+28h] [rbp-8h]
  unsigned int i; // [rsp+2Ch] [rbp-4h]

  v4 = strlen(a1);
  for ( i = 0; ; ++i )
  {
    result = i;
    if ( (int)i >= v4 )
      break;
    v3 = a1[i];
    if ( v3 <= 96 || v3 > 122 )
    {
      if ( v3 <= 64 || v3 > 90 )
      {
        if ( v3 > 47 && v3 <= 57 )
          a1[i] = (a2 + v3 - 48) % 10 + 48;
      }
      else
      {
        a1[i] = (v3 - 65 + a2) % 26 + 65;
      }
    }
    else
    {
      a1[i] = (v3 - 97 + a2) % 26 + 97;
    }
  }
  return result;
}

__int64 __fastcall sub_140001596(const char *a1, const char *a2)
{
  __int64 result; // rax
  int v3; // [rsp+24h] [rbp-Ch]
  int v4; // [rsp+28h] [rbp-8h]
  signed int i; // [rsp+2Ch] [rbp-4h]

  v4 = strlen(a1);
  v3 = strlen(a2);
  for ( i = 0; ; ++i )
  {
    result = (unsigned int)i;
    if ( i >= v4 )
      break;
    a1[i] ^= a2[i % v3];
  }
  return result;
}

_BYTE *__fastcall sub_14000161C(const char *a1, __int64 a2)
{
  _BYTE *result; // rax
  int v3; // [rsp+24h] [rbp-Ch]
  int v4; // [rsp+28h] [rbp-8h]
  int i; // [rsp+2Ch] [rbp-4h]

  v3 = strlen(a1);
  v4 = 0;
  for ( i = 0; i < v3; ++i )
  {
    sub_140001408(v4 + a2, "%02X", a1[i]);
    v4 += 2;
  }
  result = (_BYTE *)(v4 + a2);
  *result = 0;
  return result;
}
```

这边发现一共两次的加密， sub_14000144B为凯撒加密，移动20位，sub_140001596是将凯撒加密后的字符串与"GEEK"进行XOR计算，调用sub_14000161C最后再将加密后的字节数据以2位的16进制文本输出。

逆向解密计算即为 密文按2字节取出字节数据数组->加密字节数据 XOR Key->凯撒解密

解密代码如下：

```c++
void Ceasar(char* Str, int Shift)
{
	int Size = strlen(Str);
	for (int i = 0; i < Size; i++)
	{
		if (Str[i] >= 'a' && Str[i] <= 'z')
			Str[i] = (Str[i] - 'a' + Shift) % 26 + 'a';
		else if (Str[i] >= 'A' && Str[i] <= 'Z')
			Str[i] = (Str[i] - 'A' + Shift) % 26 + 'A';
		else if (Str[i] >= '0' && Str[i] <= '9')
			Str[i] = (Str[i] - '0' + Shift) % 10 + '0';
	}
}


std::string Str = "0A161230300C2D0A2B303D2428233005242C2D26182206233E097F133A";
std::string Key = "GEEK";

char e_Flag[30]{};

for (int i = 0, j = 0; i < Str.length(); i += 2, j++)
{
    e_Flag[j] = std::stoi(Str.substr(i, 2), nullptr, 16);
}

// XOR解密
for (int i = 0; i < 29; i++)
{
    e_Flag[i] ^= Key[i % 4];
}
// Ceasar解密
Ceasar(e_Flag, 26 - 20);

std::cout << e_Flag << std::endl;

// SYC{cOnGraduulaTions_mIneR:D}

```

### 好像是python

下载得到program文件，打开发现是python编译过程中的文件，直接甩给GPT分析出原代码。

```python
flag = 'SYC{MD5(input)}'
print("Please input0:")
input0 = input()

def test2(s2):
    key = 'SYC'
    length = 18
    cipher = []
    for i in range(length):
        cipher.append(chr(ord(s2[i]) ^ i ^ ord(key[i % len(key)]) ^ 3))
    return ''.join(cipher)

def test(s, R):
    result = []
    for i in s:
        if 'A' <= i <= 'Z':
            result.append(chr(((ord(i) - ord('A') + R) % 26) + ord('A')))
        elif 'a' <= i <= 'z':
            result.append(chr(((ord(i) - ord('a') + R) % 26) + ord('a')))
        elif '0' <= i <= '9':
            result.append(chr(((ord(i) - ord('0') + R) % 10) + ord('0')))
        else:
            result.append(i)
    return ''.join(result)

a = 13
b = 14
c = a ^ b + a
d = b * 100
e = a ^ b
m = (d * c - e) - 1
r = m % 26

cipher1 = test(input0, r)
cipher2 = test2(cipher1)

num = [
    -1, -36, 26, -5, 14, 41, 6, -9, 60, 29, -28, 17, 21, 7, 35, 38, 26, 48
]

for i in range(18):
    if cipher2[i] != chr(num[i] ^ ord(cipher2[i])):
        print("wrong!")
        break
else:
    print("Rrrright!")
```

可以看到一共是两次加密，一次xor计算一次凯撒加密。

解密代码如下：

```python
import hashlib

def decrypt_test2(cipher):
    key = 'SYC'
    length = 18
    result = []
    for i in range(length):
        original = (cipher[i] - (~ord(key[i % 3]) + 1)) ^ i
        result.append(chr(original))
    return ''.join(result)

def decrypt_test(s, R):
    result = []

    for i in s:
        if 'A' <= i <= 'Z':
            result.append(
                chr(((ord(i) - ord('A') + R) % 26) + ord('A'))
            )
        elif 'a' <= i <= 'z':
            result.append(
                chr(((ord(i) - ord('a') + R) % 26) + ord('a'))
            )
        elif '0' <= i <= '9':
            result.append(
                chr(((ord(i) - ord('0') + R) % 10) + ord('0'))
            )
        else:
            result.append(i)
    return ''.join(result)

num = [-1, -36, 26, -5, 14, 41, 6, -9, 60, 29, -28, 17, 21, 7, 35, 38, 26, 48]

str1 = decrypt_test2(num)

input_ = decrypt_test(str1, -14)

print(input_)

print("SYC{" + hashlib.md5(input_.encode("UTF-8")).hexdigest()+"}")

# D0_You_Iik3_python
# SYC{ed798fdd74e5c382b9c7fcca88500aca}

```

### 奇怪的RC4

下载得到easy_xor_and_rc4.exe，发现图标是python编译得到的exe，直接用pyinstxtractor脚本解包exe，注意要用和exe版本一致的python运行解包脚本，不然得不到被压缩的Rc4.pyc。解包后得到easy_xor_and_rc4.pyc和Rc4.pyc，在[pyc反编译网站](https://tool.lu/pyc/)进行pyc解密。

Rc4.py

```python
def KSA(key):
    j = 0
    S = list(range(256))
    key_length = len(key)
    for i in range(256):
        j = (j + S[i] + key[i % key_length]) % 256
        S[i] = S[j]
        S[j] = S[i]
    return S


def PRGA(S):
    i = 0
    j = 0
    i = (i + 1) % 256
    j = (j + S[i]) % 256
    S[i] = S[j]
    S[j] = S[i]
    k = (S[i] + S[j]) % 256
    yield k
    continue


def rc4(plaintext, key):
    
    try:
        key = (lambda .0: [ ord(i) for i in .0 ])(key)
    finally:
        pass
    
    try:
        plaintext = (lambda .0: [ ord(i) for i in .0 ])(plaintext)
    finally:
        pass
    for i in range(len(plaintext)):
        plaintext[i] += i
    S = KSA(key)
    xor_value = PRGA(S)
    for i in range(len(plaintext)):
        plaintext[i] ^= int(next(xor_value)) + 6
    return plaintext
```

easy_xor_and_rc4.py

```python
from rc4 import *

def xor1(plaintext, xor_list):
    try:
        xor_list = [ord(i) for i in xor_list]
    except TypeError: # More specific exception handling
        pass
    
    try:
        plaintext = [ord(i) for i in plaintext]
    except TypeError: # More specific exception handling
        pass
    
    for i in range(min(len(plaintext), len(xor_list))): # Prevent IndexError
        plaintext[i] ^= xor_list[i]
    return plaintext


def xor2(plaintext):
    try:
        plaintext = [ord(i) for i in plaintext]
    except TypeError: # More specific exception handling
        pass
    
    for i in range(len(plaintext) - 1):
        plaintext[i + 1] ^= plaintext[i] # Corrected XOR operation
    return plaintext


def enc(plaintext, key, xor_list):
    plaintext = rc4(plaintext, key)
    plaintext = xor1(plaintext, xor_list)
    print(plaintext)
    plaintext = xor2(plaintext)
    print(plaintext)
    return plaintext


plaintext = input('please give your input:')
key = 'SYCFOREVER'
xor_list = list(range(len(plaintext)))
for i in range(len(xor_list)):
    xor_list[i]+=2
cipher = [158, 31, 205, 434, 354, 15, 383, 298, 304, 351, 465, 312, 261, 442,
          397, 474, 310, 397, 31, 21, 78, 67, 47, 133, 168, 48, 153, 99, 103,
          204, 137, 29, 22, 13, 228, 3, 136, 141, 248, 124, 26, 26, 65, 200,
          7]
plaintext = enc(plaintext, key, xor_list)

if len(cipher) != len(plaintext):
    print('Wrong')  # Handle length mismatch
    exit(1)

print(plaintext)

for i in range(len(cipher)):
    if cipher[i] != plaintext[i]:
        print('Wrong')
        exit(1)
else:
    print('You know the flag!!')

```

可以看到是被魔改的RC4加密，总加密流程： RC4加密->xor1->xor2

通过Rc4.py写出Rc4的解密代码

xor1是将字符串于xorList进行XOR计算，xorList为整数数组 [0,1,2,3,...,Length(cipher)-1]

以下为解密代码：

```c++
std::vector<int> KSA(const std::string& key) 
{
	int j = 0;
	std::vector<int> S(256);
	int key_length = key.length();

	for (int i = 0; i < 256; ++i) 
    {
		S[i] = i;
	}

	for (int i = 0; i < 256; ++i) 
    {
		j = (j + S[i] + static_cast<int>(key[i % key_length])) % 256;
		std::swap(S[i], S[j]);
	}

	return S;
}

std::vector<int> PRGA(std::vector<int>& S, int length)
{
	int i = 0, j = 0;
	std::vector<int> keystream(length);

	for (int n = 0; n < length; ++n) 
    {
		i = (i + 1) % 256;
		j = (j + S[i]) % 256;
		std::swap(S[i], S[j]);
		int k = (S[i] + S[j]) % 256;
		keystream[n] = k;
	}

	return keystream;
}

std::vector<int> rc4(const std::vector<int>& data, const std::string& key) 
{
	std::vector<int> key_int(key.begin(), key.end());

	std::vector<int> data_copy = data;

	std::vector<int> S = KSA(key);
	std::vector<int> keystream = PRGA(S, data_copy.size());

	for (int i = 0; i < data_copy.size(); ++i) 
    {
		data_copy[i] ^= (keystream[i] + 6);
	}

	for (int i = 0; i < data_copy.size(); ++i) 
    {
		data_copy[i] -= i;
	}

	return data_copy;
}

void xor2(std::vector<int>& Plaintext)
{
	for (int i = Plaintext.size() - 2; i >= 0; i--)
	{
		Plaintext[i + 1] ^= Plaintext[i];
	}
}

void xor1(std::vector<int>& Plaintext, std::vector<int>& xor_list)
{
	for (int i = 0; i < 45; i++)
	{
		Plaintext[i] ^= xor_list[i];
	}
}

int main()
{
    std::string Key = "SYCFOREVER";
    std::vector<int> xor_list;
    std::vector<int> cipher
    { 158, 31, 205, 434, 354, 15, 383, 298, 304, 351, 465, 312, 261, 442,
    397, 474, 310, 397, 31, 21, 78, 67, 47, 133, 168, 48, 153, 99, 103,
    204, 137, 29, 22, 13, 228, 3, 136, 141, 248, 124, 26, 26, 65, 200,
    7 };

    // 得到XorList
    for (int i = 0; i < 45; i++)
        xor_list.push_back(i);
    // 第一次xor计算
    xor2(cipher);
    // 第二次xor计算
    xor1(cipher, xor_list);
    // rc4解密
    auto Result = rc4(cipher, Key);
    for (auto i : Result)
        std::cout << (char)i;

    // SYC{Bel1eve_thAt_you_a3e_Unique_@nd_tHe_beSt}
}

```

### 长颈鹿喜欢吃彩虹

这题主要是去除混淆，两种方法，一种是动态调试走流程进行简化代码，一种是GPT直接一键去混淆。将文件拖入IDA分析，得到main伪代码

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
      int v3; // eax
      int v4; // eax
      int v6; // [rsp+8Ch] [rbp-D4h]
      char v7[48]; // [rsp+90h] [rbp-D0h] BYREF
      _BYTE s1[40]; // [rsp+C0h] [rbp-A0h] BYREF
      size_t n; // [rsp+E8h] [rbp-78h]
      char v10[9]; // [rsp+F7h] [rbp-69h] BYREF
      unsigned __int8 s2[36]; // [rsp+100h] [rbp-60h] BYREF
      int v12; // [rsp+124h] [rbp-3Ch]
      char *s; // [rsp+128h] [rbp-38h]
      size_t v14; // [rsp+130h] [rbp-30h]
      size_t v15; // [rsp+138h] [rbp-28h]
      char *v16; // [rsp+140h] [rbp-20h]
      char *v17; // [rsp+148h] [rbp-18h]
      unsigned __int8 *v18; // [rsp+150h] [rbp-10h]
      int v19; // [rsp+158h] [rbp-8h]
      int v20; // [rsp+15Ch] [rbp-4h]

      v12 = 0;
      printf("  ____   __   __   ____   _        ___   __     __  _____   ____  \n");
      printf(" / ___|  \\ \\ / /  / ___| | |      / _ \\  \\ \\   / / | ____| |  _ \\ \n");
      printf(" \\___ \\   \\ V /  | |     | |     | | | |  \\ \\ / /  |  _|   | |_) |\n");
      printf("  ___) |   | |   | |___  | |___  | |_| |   \\ V /   | |___  |  _ < \n");
      printf(" |____/    |_|    \\____| |_____|  \\___/     \\_/    |_____| |_| \\_\\\n");
      enc_data(s2, 0x20uLL);
      enc_key(v10, 9uLL);
      n = 32LL;
      printf("please input what you want: ");
      s = v7;
      v6 = 1961608457;
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              while ( 1 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        while ( 1 )
                        {
                          while ( 1 )
                          {
                            while ( 1 )
                            {
                              while ( 1 )
                              {
                                while ( 1 )
                                {
                                  while ( 1 )
                                  {
                                    while ( v6 == -1960029910 )
                                      v6 = -42450044;
                                    if ( v6 != -1801976412 )
                                      break;
                                    v7[v14] = 0;
                                    v15 = strlen(v7);
                                    v6 = 880826124;
                                  }
                                  if ( v6 != -1698770122 )
                                    break;
                                  v6 = 76843210;
                                  printf("wow!you eat it\n");
                                }
                                if ( v6 != -1565280882 )
                                  break;
                                v6 = 1993122584;
                              }
                              if ( v6 != -1473518171 )
                                break;
                              v6 = -42450044;
                            }
                            if ( v6 != -1322091372 )
                              break;
                            v12 = 1;
                            v6 = -1960029910;
                          }
                          if ( v6 != -931614668 )
                            break;
                          v4 = -922711339;
                          if ( !v19 )
                            v4 = -1698770122;
                          v6 = v4;
                        }
                        if ( v6 != -922711339 )
                          break;
                        v6 = 207397448;
                        printf("do you want to eat rainbow again? \n");
                      }
                      if ( v6 != -42450044 )
                        break;
                      v20 = v12;
                      v6 = 1242905709;
                    }
                    if ( v6 != 76843210 )
                      break;
                    v6 = 1237312745;
                  }
                  if ( v6 != 207397448 )
                    break;
                  v6 = 1237312745;
                }
                if ( v6 != 612458639 )
                  break;
                encrypt(v16, v17, v18);
                v6 = 873358392;
              }
              if ( v6 != 873358392 )
                break;
              v19 = memcmp(s1, s2, n);
              v6 = -931614668;
            }
            if ( v6 != 880826124 )
              break;
            v3 = 1299047512;
            if ( v15 != n )
              v3 = -1565280882;
            v6 = v3;
          }
          if ( v6 != 1237312745 )
            break;
          v12 = 0;
          v6 = -1473518171;
        }
        if ( v6 == 1242905709 )
          break;
        if ( v6 == 1299047512 )
        {
          v16 = v7;
          v17 = v10;
          v18 = s1;
          v6 = 612458639;
        }
        else if ( v6 == 1961608457 )
        {
          fgets(s, 33, _bss_start);
          v14 = strcspn(v7, "\n");
          v6 = -1801976412;
        }
        else
        {
          v6 = -1322091372;
          printf("your height wrong ,not a really giraffe ");
        }
      }
      return v20;
}
```

发现代码明显是被混淆了，不过混淆程度低，基本跟着走一遍流程就可以去除混淆代码，这边是用动态调试的方法走流程，在linux下直接IDA动态调试，简化代码如下：

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
      int v3; // eax
      int v4; // eax
      int v6; // [rsp+8Ch] [rbp-D4h]
      char v7[48]; // [rsp+90h] [rbp-D0h] BYREF
      _BYTE s1[40]; // [rsp+C0h] [rbp-A0h] BYREF
      size_t n; // [rsp+E8h] [rbp-78h]
      char v10[9]; // [rsp+F7h] [rbp-69h] BYREF
      unsigned __int8 s2[36]; // [rsp+100h] [rbp-60h] BYREF
      int v12; // [rsp+124h] [rbp-3Ch]
      char *s; // [rsp+128h] [rbp-38h]
      size_t v14; // [rsp+130h] [rbp-30h]
      size_t v15; // [rsp+138h] [rbp-28h]
      char *v16; // [rsp+140h] [rbp-20h]
      char *v17; // [rsp+148h] [rbp-18h]
      unsigned __int8 *v18; // [rsp+150h] [rbp-10h]
      int v19; // [rsp+158h] [rbp-8h]
      int v20; // [rsp+15Ch] [rbp-4h]

      v12 = 0;
      printf("  ____   __   __   ____   _        ___   __     __  _____   ____  \n");
      printf(" / ___|  \\ \\ / /  / ___| | |      / _ \\  \\ \\   / / | ____| |  _ \\ \n");
      printf(" \\___ \\   \\ V /  | |     | |     | | | |  \\ \\ / /  |  _|   | |_) |\n");
      printf("  ___) |   | |   | |___  | |___  | |_| |   \\ V /   | |___  |  _ < \n");
      printf(" |____/    |_|    \\____| |_____|  \\___/     \\_/    |_____| |_| \\_\\\n");
      // 获取加密的数据
      enc_data(s2, 0x20uLL);
      // 获取Key
      enc_key(v10, 9uLL);
      n = 32LL;
      printf("please input what you want: ");
      // 输入
      fgets(v7, 33, _bss_start);
      v15 = strlen(v7);

      if(v15 != n)
      {
            printf("your height wrong ,not a really giraffe ");
            return 0;
      }

      // 输入字符串
      v16 = v7;
      // Key
      v17 = v10;
      // 加密结果
      v18 = s1;
      encrypt(v16,v17,v18);
	  // 比对输入字符串加密后是否等于加密数据
      v19 = memcmp(s1, s2, n);

        if(v19 == 0) 
        {
            printf("wow!you eat it\n");
            printf("do you want to eat rainbow again? \n");
        } else {
            printf("your height wrong ,not a really giraffe ");
        }

      return v20;
}
```

由于是动态调试，直接可以导出enc_data和enc_key两个数据，当然直接复制这两个函数伪代码到c++运行也是可以拿到data和key两个数据。

![image12]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/gri_2.png)

![QQ_1730941819584]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/gri_3.png)

encrypt函数：

```c++
__int64 __fastcall encrypt(char *a1, const char *a2, unsigned __int8 *a3)
{
  __int64 result; // rax
  size_t v4; // rax
  int v5; // eax
  unsigned __int8 *v6; // [rsp+0h] [rbp-110h] BYREF
  int v7; // [rsp+Ch] [rbp-104h]
  int v8; // [rsp+10h] [rbp-100h]
  int v9; // [rsp+14h] [rbp-FCh]
  int v10; // [rsp+18h] [rbp-F8h]
  int v11; // [rsp+1Ch] [rbp-F4h]
  int v12; // [rsp+20h] [rbp-F0h]
  int v13; // [rsp+24h] [rbp-ECh]
  int v14; // [rsp+28h] [rbp-E8h]
  int v15; // [rsp+2Ch] [rbp-E4h]
  int v16; // [rsp+30h] [rbp-E0h]
  int v17; // [rsp+34h] [rbp-DCh]
  int v18; // [rsp+38h] [rbp-D8h]
  int v19; // [rsp+3Ch] [rbp-D4h]
  int v20; // [rsp+40h] [rbp-D0h]
  int v21; // [rsp+44h] [rbp-CCh]
  int v22; // [rsp+48h] [rbp-C8h]
  int v23; // [rsp+4Ch] [rbp-C4h]
  unsigned __int8 *v24; // [rsp+50h] [rbp-C0h]
  char *v25; // [rsp+58h] [rbp-B8h]
  const char *v26; // [rsp+60h] [rbp-B0h]
  int v27; // [rsp+6Ch] [rbp-A4h]
  char *s; // [rsp+70h] [rbp-A0h]
  const char **v29; // [rsp+78h] [rbp-98h]
  unsigned __int8 **v30; // [rsp+80h] [rbp-90h]
  size_t *v31; // [rsp+88h] [rbp-88h]
  size_t *v32; // [rsp+90h] [rbp-80h]
  size_t *v33; // [rsp+98h] [rbp-78h]
  _BYTE *v34; // [rsp+A0h] [rbp-70h]
  char *v35; // [rsp+A8h] [rbp-68h]
  unsigned __int8 *v36; // [rsp+B0h] [rbp-60h]
  size_t v37; // [rsp+B8h] [rbp-58h]
  size_t v38; // [rsp+C0h] [rbp-50h]
  size_t v39; // [rsp+C8h] [rbp-48h]
  bool v40; // [rsp+D7h] [rbp-39h]
  char *v41; // [rsp+D8h] [rbp-38h]
  size_t v42; // [rsp+E0h] [rbp-30h]
  const char *v43; // [rsp+E8h] [rbp-28h]
  __int64 v44; // [rsp+F0h] [rbp-20h]
  int v45; // [rsp+F8h] [rbp-18h]
  char v46; // [rsp+FFh] [rbp-11h]
  size_t v47; // [rsp+100h] [rbp-10h]
  size_t v48; // [rsp+108h] [rbp-8h]

  v27 = 509491216;
  v26 = a2;
  v25 = a1;
  v24 = a3;
  while ( 1 )
  {
    while ( 1 )
    {
      while ( 1 )
      {
        while ( 1 )
        {
          while ( 1 )
          {
            while ( 1 )
            {
              while ( 1 )
              {
                while ( 1 )
                {
                  while ( 1 )
                  {
                    while ( 1 )
                    {
                      while ( 1 )
                      {
                        while ( 1 )
                        {
                          while ( 1 )
                          {
                            v23 = v27;
                            v22 = v27 + 1132146882;
                            if ( v27 != -1132146882 )
                              break;
                            *v36 = v46 ^ v45;
                            (*v30)[*v33] = *v36;
                            v27 = 541252275;
                          }
                          v21 = v23 + 1005509852;
                          if ( v23 != -1005509852 )
                            break;
                          v38 = *v33;
                          v27 = 1110970360;
                        }
                        v20 = v23 + 911004694;
                        if ( v23 != -911004694 )
                          break;
                        v40 = v38 < v39;
                        v27 = 32509293;
                      }
                      v19 = v23 + 290148803;
                      if ( v23 != -290148803 )
                        break;
                      *v33 = v48;
                      v27 = 2049158165;
                    }
                    v18 = v23 - 32509293;
                    if ( v23 != 32509293 )
                      break;
                    v5 = 1712900817;
                    if ( v40 )
                      v5 = 1761996910;
                    v27 = v5;
                  }
                  v17 = v23 - 509491216;
                  if ( v23 != 509491216 )
                    break;
                  v29 = (const char **)&v6;
                  v30 = &v6;
                  v31 = (size_t *)&v6;
                  v32 = (size_t *)&v6;
                  v33 = (size_t *)&v6;
                  v34 = &v6;
                  v35 = (char *)&v6;
                  v36 = (unsigned __int8 *)(&v6 - 2);
                  s = v25;
                  v6 = v24;
                  v27 = 1926711538;
                }
                v16 = v23 - 541252275;
                if ( v23 != 541252275 )
                  break;
                v47 = *v33;
                v27 = 795171278;
              }
              v15 = v23 - 746586984;
              if ( v23 != 746586984 )
                break;
              *v31 = v37;
              v4 = strlen(*v29);
              *v32 = v4;
              *v33 = 0LL;
              v27 = -1005509852;
            }
            v14 = v23 - 795171278;
            if ( v23 != 795171278 )
              break;
            v48 = v47 + 1;
            v27 = -290148803;
          }
          v13 = v23 - 1110970360;
          if ( v23 != 1110970360 )
            break;
          v39 = *v31;
          v27 = -911004694;
        }
        v12 = v23 - 1117683297;
        if ( v23 != 1117683297 )
          break;
        *v34 = v41[v42];
        v43 = *v29;
        v44 = *v32 - 1;
        v27 = 1422522285;
      }
      v11 = v23 - 1422522285;
      if ( v23 != 1422522285 )
        break;
      *v35 = v43[v44 - *v33 % *v32];
      v45 = (unsigned __int8)*v34;
      v46 = *v35;
      v27 = -1132146882;
    }
    result = (unsigned int)(v23 - 1712900817);
    v10 = v23 - 1712900817;
    if ( v23 == 1712900817 )
      break;
    v9 = v23 - 1761996910;
    if ( v23 == 1761996910 )
    {
      v41 = s;
      v42 = *v33;
      v27 = 1117683297;
    }
    else
    {
      v8 = v23 - 1926711538;
      if ( v23 == 1926711538 )
      {
        v37 = strlen(s);
        v27 = 746586984;
      }
      else
      {
        v7 = v23 - 2049158165;
        if ( v23 == 2049158165 )
          v27 = -1005509852;
      }
    }
  }
  return result;
}
```

发现encrypt函数也是被混淆的，同样动态调试观察数据的计算变化，发现大概计算过程如下：

```c++
for (int i = 0; i < strlen(Input); i++)
{
    Out[i] = Key[7 - i % strlen(Key)] ^ Input[i];
}
```

将输入的字符串与Key进行XOR计算，Key是从后往前循环取。

由于只是单纯XOR计算，所以解密代码也如上即可。

完整代码如下：

```c++
char Flag[32]{};
// 动态调试导出的两个数据
char Key[] = "BOb0m0oN"
unsigned char Data[] =
{
  0x1D, 0x36, 0x73, 0x16, 0x49, 0x2D, 0x1A, 0x1D, 0x29, 0x06,
  0x42, 0x2C, 0x76, 0x07, 0x10, 0x0E, 0x7E, 0x39, 0x55, 0x32,
  0x75, 0x03, 0x1B, 0x1D, 0x19, 0x5F, 0x52, 0x23, 0x01, 0x03,
  0x1D, 0x3F
};

for (int i = 0; i < 32; i++)
{
	Flag[i] = Key[7 - i % 8] ^ Data[i];
}

std::cout<< Flag <<std::endl;

// SYC{yOU_girAFe_L0Ve_EaT_W0bN1aR}
```

### DH爱喝茶

将文件拖入IDA分析，发现IDA无法分析main函数，大概率是加了花指令导致IDA无法分析。

![QQ_1730907893739]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/DH.png)

这部分便是经典的一种花指令，直接把圈起来的这部分的代码全部nop了，然后把main函数代码块全部选中按P重构函数，便可以直接F5反编译看伪代码了。

伪代码如下：

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int i; // [esp+0h] [ebp-DCh]
  int j; // [esp+4h] [ebp-D8h]
  _DWORD v6[4]; // [esp+Ch] [ebp-D0h] BYREF
  _DWORD v7[8]; // [esp+1Ch] [ebp-C0h]
  int v8; // [esp+3Ch] [ebp-A0h]
  int v9; // [esp+40h] [ebp-9Ch]
  int v10; // [esp+44h] [ebp-98h]
  int v11; // [esp+48h] [ebp-94h]
  int v12; // [esp+4Ch] [ebp-90h]
  int v13; // [esp+50h] [ebp-8Ch]
  int v14; // [esp+54h] [ebp-88h]
  int v15; // [esp+58h] [ebp-84h]
  char s[4]; // [esp+5Ch] [ebp-80h] BYREF
  _BYTE v17[96]; // [esp+60h] [ebp-7Ch] BYREF
  unsigned int v18; // [esp+C0h] [ebp-1Ch]
  int *p_argc; // [esp+CCh] [ebp-10h]

  p_argc = &argc;
  v18 = __readgsdword(0x14u);
  *(_DWORD *)s = 0;
  memset(v17, 0, sizeof(v17));
  v6[0] = 1450744508;
  v6[1] = 1737075661;
  v6[2] = 2023406814;
  v6[3] = -1985229329;
  v8 = 528853349;
  v9 = -289381396;
  v10 = 1542574262;
  v11 = -218241104;
  v12 = -1439137638;
  v13 = 1728541417;
  v14 = 906831033;
  v15 = -376674164;
  puts("plz treat DH with a cup of tea:");
  fgets(s, 33, stdin);
  s[strcspn(s, "\n")] = 0;
  for ( i = 0; i <= 3; ++i )
  {
    v6[i] = __ROL4__(v6[i], 6);
    enc(&s[8 * i], v6);
  }
  v7[0] = v8;
  v7[1] = v9;
  v7[2] = v10;
  v7[3] = v11;
  v7[4] = v12;
  v7[5] = v13;
  v7[6] = v14;
  v7[7] = v15;
  for ( j = 0; j <= 31; ++j )
  {
    if ( s[j] != *((_BYTE *)v7 + j) )
    {
      puts("Maybe DH is a little unhappy");
      puts("Press Enter to exit...");
      getchar();
      return 0;
    }
  }
  puts("Great! DH is happy");
  puts("Press Enter to exit...");
  getchar();
  getchar();
  return 0;
}

unsigned int __cdecl enc(unsigned int *a1, int *a2)
{
  unsigned int result; // eax
  unsigned int v3; // [esp+8h] [ebp-28h]
  unsigned int v4; // [esp+Ch] [ebp-24h]
  int v5; // [esp+10h] [ebp-20h]
  unsigned int i; // [esp+14h] [ebp-1Ch]
  int v7; // [esp+1Ch] [ebp-14h]
  int v8; // [esp+20h] [ebp-10h]

  v3 = *a1;
  v4 = a1[1];
  v5 = 0;
  v7 = *a2;
  v8 = a2[1];
  for ( i = 0; i <= 0x1F; ++i )
  {
    v5 += (unsigned __int8)(v8 ^ v7) - 1737075662;
    v3 += (v4 + v5) ^ (16 * v4 + v7) ^ ((v4 >> 5) + v8);
    v4 += (v3 + v5) ^ (16 * v3 + a2[2]) ^ ((v3 >> 5) + a2[3]);
  }
  *a1 = v3;
  result = v4;
  a1[1] = v4;
  return result;
}
```

可以发现是xtea加密，密钥是v6，v8到v15为32字节长度的加密Flag数据。

加密过程是每8字节加密，每次加密循环将当前下标的Key数据进行ROL4计算，然后再进行加密，所以反过来逆向解密即可。

解密代码如下：

```c++
#include <bit>

#define __ROL__(x, y) std::rotl(x, y)
inline DWORD __ROL4__(DWORD value, int count) { return __ROL__((DWORD)value, count); }

void Decrypt_xtea(uint32_t* v, uint32_t* k) 
{
	uint32_t v0 = v[0], v1 = v[1], i;
	uint32_t k0 = k[0], k1 = k[1], k2 = k[2], k3 = k[3];
	uint32_t delta = ((unsigned __int8)(k0 ^ k1) - 1737075662);
	uint32_t sum = delta * 32;
	for (i = 0; i < 32; i++) 
	{
		v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3);
		v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1);
		sum -= delta;
	}
	v[0] = v0; v[1] = v1;
}

int main()
{
	DWORD v6[4]{ 1450744508 ,1737075661,2023406814 ,-1985229329 };

	DWORD v7[8]{ 528853349,-289381396,1542574262,-218241104,-1439137638,1728541417,906831033,-376674164 };

	DWORD Key1[4]{}, Key2[4]{}, Key3[4]{}, Key4[4]{};

	BYTE EncodeFlag[32]{};

	memcpy_s(EncodeFlag, 32, v7, 32);

	memcpy_s(Key1, 32, v6, 32);
	memcpy_s(Key2, 32, v6, 32);
	memcpy_s(Key3, 32, v6, 32);
	memcpy_s(Key4, 32, v6, 32);

	// 直接存四份不同ROL4数量的Key
	for (int i = 0; i < 4; i++)
		Key1[i] = __ROL4__(v6[i], 6);
	for (int i = 0; i < 3; i++)
		Key2[i] = __ROL4__(v6[i], 6);
	for (int i = 0; i < 2; i++)
		Key3[i] = __ROL4__(v6[i], 6);
	for (int i = 0; i < 1; i++)
		Key4[i] = __ROL4__(v6[i], 6);

    // 分别解密
	Decrypt_xtea((uint32_t*)&EncodeFlag[8 * 3], (uint32_t*)Key1);
	Decrypt_xtea((uint32_t*)&EncodeFlag[8 * 2], (uint32_t*)Key2);
	Decrypt_xtea((uint32_t*)&EncodeFlag[8 * 1], (uint32_t*)Key3);
	Decrypt_xtea((uint32_t*)&EncodeFlag[8 * 0], (uint32_t*)Key4);

	for (int i = 0; i < 32; i++)
		std::cout << EncodeFlag[i];

	// SYC{DH_likes_flower_and_tea!!!!}
}
```

### CPP_flower

这题是花指令去除，拖入IDA分析，在String查看找到关键字串，再看交叉调用跳到主要代码段。

![QQ_1730911358434]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/flower_1.png)

直接将jz和jnz两行nop，然后patch call那一行，将E8改成90，再对下面剩下的字节按c重新分析代码即可还原这部分逻辑。

往下翻看到这个call是错误的，也是花指令导致。

![QQ_1730911571246]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/flower_2.png)

中间插入了一个loc_419DA6的call，从call里面的add dword ptr[esp+4],12h 可以知道其实就是在A1这个地址基础上+12h，使返回地址变到B3偏移，所以从9C到B2的这部分代码直接全部nop，让代码直接执行到B3。

![QQ_1730911944809](https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/flower_4.png)

然后对下面的代码按C重新分析即可还原，然后继续往下还有两处与上面一样的，做一样的处理就行。然后把中间一些非红区域的函数delete掉，在选中全部代码按P重构函数，即可分析伪代码。

伪代码如下：



```c++
__int64 sub_419D10()
{
  int v0; // eax
  __int64 v1; // rax
  _DWORD *v2; // esi
  int v3; // eax
  __int64 v5; // [esp-8h] [ebp-23Ch]
  _DWORD v6[41]; // [esp+2Ch] [ebp-208h] BYREF
  int v7; // [esp+104h] [ebp-130h]
  _DWORD Buf2[52]; // [esp+110h] [ebp-124h] BYREF
  int i; // [esp+1E0h] [ebp-54h]
  _BYTE v10[36]; // [esp+1ECh] [ebp-48h] BYREF
  _BYTE v11[20]; // [esp+210h] [ebp-24h] BYREF
  int v12; // [esp+230h] [ebp-4h]
  int savedregs; // [esp+234h] [ebp+0h] BYREF

  sub_411127(0x10u);
  sub_4111C2(v11);
  v12 = 0;
  srand(0x7DE9u);
  sub_411519();
  sub_4114B0(v10);
  LOBYTE(v12) = 1;
  v0 = sub_41138E(std::cout, "give your input:");
  std::ostream::operator<<(v0, sub_411073);
  sub_411519();
  sub_4113F7(std::cin, v10);
  if ( sub_41181B(v10) == dword_426004 )
  {
    for ( i = 0; i < dword_426004; ++i )
    {
      rand();
      v6[0] = sub_411519() % 255;
      sub_4112E4(v6);
    }
    for ( i = 0; i < dword_426004; ++i )
    {
      v2 = (_DWORD *)sub_41128A(i);
      v7 = *v2 ^ *(char *)sub_411113(i);
      Buf2[i] = v7;
    }
    if ( !j_memcmp(&unk_422C30, Buf2, 4 * dword_426004) )
      v3 = sub_41138E(std::cout, "you get it");
    else
      v3 = sub_41138E(std::cout, "Wrong");
    std::ostream::operator<<(v3, sub_411073);
    sub_411519();
    LOBYTE(v12) = 0;
    sub_411438(v10);
    v12 = -1;
    sub_411726(v11);
    LODWORD(v1) = 0;
  }
  else
  {
    v6[3] = 0;
    LOBYTE(v12) = 0;
    sub_411438(v10);
    v12 = -1;
    sub_411726(v11);
    LODWORD(v1) = 0;
  }
  v5 = v1;
  sub_411456(&savedregs, &dword_41A008);
  return v5;
}
```

分析逻辑如下：

srand(0x7DE9)置一个固定种子，然后输入字符串

字符串长度要求符合dword_426004长度，即50

第一部分用随机数生成一个50长度的Vector数组

第二部分用sub_41128A和sub_411113取到随机数列表和字符串下标为i的指针，将两个指针的数据进行XOR计算

所以解密也用完全同样的逻辑进行再次计算将unk_422C30的数据解密就行。

解密代码如下：

```c++
int main()
{
	byte unk_422C30[]
	{ 0x3E, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0xEB, 0x00,
	  0x00, 0x00, 0x26, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00,
	  0x8E, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00, 0xE5, 0x00,
	  0x00, 0x00, 0x86, 0x00, 0x00, 0x00, 0xC8, 0x00, 0x00, 0x00,
	  0x3F, 0x00, 0x00, 0x00, 0x98, 0x00, 0x00, 0x00, 0xC8, 0x00,
	  0x00, 0x00, 0xDE, 0x00, 0x00, 0x00, 0x52, 0x00, 0x00, 0x00,
	  0x44, 0x00, 0x00, 0x00, 0xA0, 0x00, 0x00, 0x00, 0xCB, 0x00,
	  0x00, 0x00, 0x2B, 0x00, 0x00, 0x00, 0x2A, 0x00, 0x00, 0x00,
	  0x3C, 0x00, 0x00, 0x00, 0xAA, 0x00, 0x00, 0x00, 0xBE, 0x00,
	  0x00, 0x00, 0xCB, 0x00, 0x00, 0x00, 0x88, 0x00, 0x00, 0x00,
	  0x55, 0x00, 0x00, 0x00, 0x9E, 0x00, 0x00, 0x00, 0x6D, 0x00,
	  0x00, 0x00, 0xD9, 0x00, 0x00, 0x00, 0x94, 0x00, 0x00, 0x00,
	  0x97, 0x00, 0x00, 0x00, 0x1C, 0x00, 0x00, 0x00, 0x52, 0x00,
	  0x00, 0x00, 0x31, 0x00, 0x00, 0x00, 0x59, 0x00, 0x00, 0x00,
	  0xFE, 0x00, 0x00, 0x00, 0x1A, 0x00, 0x00, 0x00, 0x1A, 0x00,
	  0x00, 0x00, 0xE8, 0x00, 0x00, 0x00, 0xD0, 0x00, 0x00, 0x00,
	  0x3A, 0x00, 0x00, 0x00, 0x9C, 0x00, 0x00, 0x00, 0x06, 0x00,
	  0x00, 0x00, 0x5E, 0x00, 0x00, 0x00, 0x25, 0x00, 0x00, 0x00,
	  0x5A, 0x00, 0x00, 0x00, 0xE4, 0x00, 0x00, 0x00, 0x22, 0x00,
	  0x00, 0x00, 0xA1, 0x00, 0x00, 0x00, 0xC5, 0x00, 0x00, 0x00 };

	std::vector<DWORD> EncodeFlag;
	for (int i = 0; i < 50; i++)
	{
		DWORD Temp{};
		memcpy_s(&Temp, 4, unk_422C30 + i * 4, 4);
		EncodeFlag.push_back(Temp);
	}
	// 固定种子
	srand(0x7DE9);

	// 获取Key列表
	std::vector<DWORD> KeyList;
	for (int i = 0; i < 50; i++)
	{
		DWORD Temp = rand() % 255;
		KeyList.push_back(Temp);
	}
	// 进行XOR计算解密
	for (int i = 0; i < 50; i++)
	{
		EncodeFlag[i] ^= KeyList[i];
		std::cout << (char)EncodeFlag[i];
	}

	//SYC{Y0u_c@n_3nJoy_yhe_Flow3r_anytime_and_anywhere}
}
```

## Week3

### ez_hook

拖入IDA分析，得到main伪函数

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  BOOL pbDebuggerPresent; // [rsp+2Ch] [rbp-54h] BYREF
  char Str[64]; // [rsp+30h] [rbp-50h] BYREF
  char v6[32]; // [rsp+70h] [rbp-10h] BYREF
  HANDLE hProcess; // [rsp+90h] [rbp+10h]
  int v8; // [rsp+98h] [rbp+18h]
  int i; // [rsp+9Ch] [rbp+1Ch]

  sub_401B90(argc, argv, envp);
  v8 = 3;
  puts("plz input the flag:");
  scanf("%s", Str);
  ReverseStr(Str);
  pbDebuggerPresent = 0;
  hProcess = GetCurrentProcess();
  if ( CheckRemoteDebuggerPresent(hProcess, &pbDebuggerPresent) && pbDebuggerPresent )
    return 0;
  sub_4016E4(Str, v8, (__int64)v6);
  sub_4017E0(v6);
  for ( i = 0; i < strlen(Str); ++i )
  {
    // zoXpih^lhX6soX7lr~DTHtGpX|
    if ( v6[i] != aZoxpihLhx6sox7[i] )
    {
      puts("Failed!");
      getchar();
      getchar();
      exit(0);
    }
  }
  puts("Success!");
  getchar();
  getchar();
  return 0;
}
```

可以看到主要的两个函数就是sub_4016E4和sub_4017E0

sub_4016E4 : 

```c++
BOOL __fastcall sub_4016E4(const char *a1, int a2, __int64 a3)
{
  int v3; // eax
  int v4; // eax
  int j; // [rsp+28h] [rbp-18h]
  int v7; // [rsp+2Ch] [rbp-14h]
  int v8; // [rsp+30h] [rbp-10h]
  int v9; // [rsp+34h] [rbp-Ch]
  int v10; // [rsp+34h] [rbp-Ch]
  int i; // [rsp+38h] [rbp-8h]
  int v12; // [rsp+3Ch] [rbp-4h]

  v8 = strlen(a1);
  v12 = 0;
  for ( i = 0; i < a2; ++i )
  {
    v9 = i;
    v7 = 2 * (a2 - i - 1);
    for ( j = 2 * i; v9 < v8; v9 = j + v10 )
    {
      if ( v7 )
      {
        v3 = v12++;
        *(_BYTE *)(v3 + a3) = a1[v9];
      }
      v10 = v7 + v9;
      if ( v10 >= v8 )
        break;
      if ( j )
      {
        v4 = v12++;
        *(_BYTE *)(v4 + a3) = a1[v10];
      }
    }
  }
  *(_BYTE *)(a3 + v12) = 0;
  return sub_401911(sub_4017E0, (int)sub_4018B4);
}
```

最后这边返回的时候调用了一个sub_401911

sub_401911:

```c++
BOOL __fastcall sub_401911(_BYTE *a1, int a2)
{
  __int64 v3; // [rsp+2Bh] [rbp-15h]
  DWORD flOldProtect; // [rsp+34h] [rbp-Ch] BYREF
  SIZE_T dwSize; // [rsp+38h] [rbp-8h]

  dwSize = 5LL;
  // 修改内存属性
  VirtualProtect(a1, 5uLL, 0x40u, &flOldProtect);
  // E9硬编码 Jmp
  LOBYTE(v3) = -23;
  // 计算相对偏移
  *(_DWORD *)((char *)&v3 + 1) = a2 - (_DWORD)a1 - 5;
  *(_DWORD *)a1 = v3;
  a1[4] = BYTE4(v3);
  // 还原内存属性
  return VirtualProtect(a1, dwSize, flOldProtect, &flOldProtect);
}
```

观察到给sub_401911传的两个参数是两个函数地址，通过代码可以知道这个函数就是实现一个简单的Hook，将a1函数hook，跳转到a2函数，所以这边是把sub_4017E0函数hook了，让他执行的时候会跳转到sub_4018B4，所以main函数里面调用sub_4017E0的时候不会执行sub_4017E0，而是会执行sub_4018B4函数。

sub_4018B4:

```c++
size_t __fastcall sub_4018B4(const char *a1)
{
  size_t result; // rax
  int i; // [rsp+2Ch] [rbp-54h]

  for ( i = 0; ; ++i )
  {
    result = strlen(a1);
    if ( i >= result )
      break;
    a1[i] ^= 7u;
  }
  return result;
}
```

这个实际执行的函数就是将传入字符串 xor 7

所以将密文xor 7 就能第一步解密。

第一步解密出字符串为"}h_wnoYko_1th_0kuyCSOs@w_{"

能观察出其实已经是存在SYC和一些符合Flag特征的字符串，分析sub_4016E4，能够知道其实就是栅栏密码加密。

直接用CyberChef即可解密出字符串，发现是倒置的文本，手动给他反转一下就能拿到Flag

![QQ_1730942778847]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/ezhook.png)

这边还是给一下c++的解密代码：

```c++
std::string railFenceDecrypt(const std::string& ciphertext) 
{
	const int numRails = 3;
	if (numRails <= 1)
	{
		return ciphertext; 
	}

	int length = ciphertext.length();
	std::vector<std::string> rails(numRails);
	int cycleLen = 2 * numRails - 2;
	int index = 0;

	std::vector<int> railLengths(numRails, 0);
	for (int i = 0; i < length; ++i) 
	{
		int railIndex = i % cycleLen;
		railIndex = railIndex < numRails ? railIndex : 2 * numRails - railIndex - 2;
		railLengths[railIndex]++;
	}

	for (int r = 0; r < numRails; ++r) 
	{
		rails[r] = ciphertext.substr(index, railLengths[r]);
		index += railLengths[r];
	}

	std::string plaintext;
	int railPos[numRails] = { 0 }; 

	for (int i = 0; i < length; ++i)
	{
		int railIndex = i % cycleLen;
		railIndex = railIndex < numRails ? railIndex : 2 * numRails - railIndex - 2;
		plaintext += rails[railIndex][railPos[railIndex]++];
	}

	return plaintext;
}

int main()
{
	std::string s = "zoXpih^lhX6soX7lr~DTHtGpX|";
	// XOR
	for (auto& c : s)
		c ^= 7;
	// 解密字符串
	auto Flag = railFenceDecrypt(s);
	// 反转字符串
	std::reverse(Flag.begin(), Flag.end());

	std::cout << Flag;

	//SYC{you_kn0w_wh@t_1s_hoOk}

	return 0;
}
```

### AES

拖入IDA分析，以下是我重命名过的伪代码

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD FrontHalfFlag[2]; // [rsp+30h] [rbp-90h] BYREF
  _QWORD BackHalfFlag[2]; // [rsp+40h] [rbp-80h] BYREF
  _QWORD v6[2]; // [rsp+50h] [rbp-70h] BYREF
  _QWORD v7[10]; // [rsp+60h] [rbp-60h] BYREF
  int v8; // [rsp+B0h] [rbp-10h]
  int i; // [rsp+B8h] [rbp-8h]
  int v10; // [rsp+BCh] [rbp-4h]

  sub_7FF7A51A213E();
  v10 = 0;
  v6[0] = 0LL;
  v6[1] = 0LL;
  memset(v7, 0, sizeof(v7));
  v8 = 0;
  FrontHalfFlag[0] = 0LL;
  FrontHalfFlag[1] = 0LL;
  BackHalfFlag[0] = 0LL;
  BackHalfFlag[1] = 0LL;
  sub_7FF7A51A1360("%s", (const char *)v6);
  CheckLength((const char *)v6);
  if ( byte_7FF7A51B1030 )
  {
    sub_7FF7A51A13B4("something wrong\n");
    return 0;
  }
  else
  {
    // Key "SYCLOVERSYCLOVER"
    AES(Key, 0x10u, v6, FrontHalfFlag, 0x10u);
    AES(Key, 0x10u, v7, BackHalfFlag, 0x10u);
    for ( i = 0; i < FlagLength; ++i )
    {
      if ( *((_BYTE *)FrontHalfFlag + i) != EncodeFlag[i] )
      {
        sub_7FF7A51A13B4("something wrong\n");
        return 0;
      }
      if ( ++v10 == FlagLength )
      {
        sub_7FF7A51A13B4("right\n");
        return 0;
      }
    }
    return 0;
  }
}
```

可以看到就是将输入的字符串分成16字节为一组，共两组，然后进行AES加密再对比密文，这边AES肯定和原始的AES算法有所区别。

AES:

```c++
__int64 __fastcall AES(const void *Key, unsigned int KeyLength, _BYTE *Input, _BYTE *Out, unsigned int InputLength)
{
  __int64 v6; // [rsp+0h] [rbp-80h] BYREF
  _QWORD v7[2]; // [rsp+20h] [rbp-60h] BYREF
  _QWORD Temp_Key[4]; // [rsp+30h] [rbp-50h] BYREF
  _DWORD v9[90]; // [rsp+50h] [rbp-30h] BYREF
  int j; // [rsp+1B8h] [rbp+138h]
  unsigned int i; // [rsp+1BCh] [rbp+13Ch]
  _QWORD *v12; // [rsp+1C0h] [rbp+140h]
  _BYTE *T_Out; // [rsp+1C8h] [rbp+148h]
  _BYTE *T_Input; // [rsp+1F0h] [rbp+170h]

  T_Input = Input;
  T_Out = Out;
  v12 = &v6 + 10;
  memset(Temp_Key, 0, sizeof(Temp_Key));
  v7[0] = 0LL;
  v7[1] = 0LL;
  if ( Key && Input && Out )
  {
    if ( KeyLength <= 16 )
    {
      if ( (InputLength & 15) != 0 )
      {
        sub_7FF7A51A13B4("input is wrong!\n");
        return 0xFFFFFFFFLL;
      }
      else
      {
        memcpy(Temp_Key, Key, KeyLength);
        KeyExpand((__int64)Temp_Key, 16, v9);
        for ( i = 0; i < InputLength; i += 16 )
        {
          sub_7FF7A51A16DC((__int64)v7, T_Input);
          AddRoundKey((__int64)v7, (__int64)v12);
          for ( j = 1; j <= 9; ++j )
          {
            v12 += 2;
            SubBytes((__int64)v7);
            ShiftRows((__int64)v7);
            MixColumns((__int64)v7);
            AddRoundKey((__int64)v7, (__int64)v12);
          }
          SubBytes((__int64)v7);
          ShiftRows((__int64)v7);
          AddRoundKey((__int64)v7, (__int64)(v12 + 2));
          sub_7FF7A51A1749((__int64)v7, T_Out);
          T_Out += 16;
          T_Input += 16;
          v12 = v9;
        }
        return 0LL;
      }
    }
    else
    {
      sub_7FF7A51A13B4("keylen is wrong!\n");
      return 0xFFFFFFFFLL;
    }
  }
  else
  {
    sub_7FF7A51A13B4("input wrong!\n");
    return 0xFFFFFFFFLL;
  }
}
```

这边经过分析完重命名后的代码，发现基本和AES加密流程一致，但是加密前和加密后多了sub_7FF7A51A16DC和sub_7FF7A51A1749两个函数

```c++
__int64 __fastcall sub_7FF7A51A16DC(__int64 a1, _BYTE *a2)
{
  _BYTE *v2; // rax
  int j; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 3; ++i )
  {
    for ( j = 0; j <= 3; ++j )
    {
      v2 = a2++;
      *(_BYTE *)(a1 + 4LL * j + i) = *v2;
    }
  }
  return 0LL;
}

__int64 __fastcall sub_7FF7A51A1749(__int64 a1, _BYTE *a2)
{
  _BYTE *v2; // rax
  int j; // [rsp+8h] [rbp-8h]
  int i; // [rsp+Ch] [rbp-4h]

  for ( i = 0; i <= 3; ++i )
  {
    for ( j = 0; j <= 3; ++j )
    {
      v2 = a2++;
      *v2 = *(_BYTE *)(4LL * j + a1 + i);
    }
  }
  return 0LL;
}
```

可以发现两个是互逆的过程，都可以互为对方的解密函数，这两个函数都是对字符串的顺序排列进行变化，所以我们解密的时候可以反过来，先调用sub_7FF7A51A16DC处理加密的数据，然后进行AES解密，再调用sub_7FF7A51A1749处理字符串得到最后明文。

然后在AES加密过程中有两个重要的数据需要看，Sbox和Rcon，这两个常数数据可能会被魔改。

在KeyExpand函数中可以找到这两个数据

![QQ_1730943929134]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/aes1.png)

发现Rcon和正常AES的相同的

![QQ_1730943980056]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/aes2.png)

而Sbox似乎前面的部分字节被修改，与正常的Sbox不相同

![QQ_1730944022204]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/aes3.png)

![QQ_1730944118332]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/aes4.png)

解密的时候要用到逆Sbox，所以要用题目的Sbox计算出逆Sbox

```c++
uint8_t Te_InvSBox[16][16] = { 0 };
uint8_t Te_InVSAdd[2] = { 0 };
uint8_t S_BOX[]
{
	0x7C, 0xCA, 0x7B, 0x77, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01,
	0x67, 0x2B, 0xFE, 0xD7, 0x47, 0xAB, 0x76, 0x63, 0x82, 0xC9,
	0x7D, 0xFA, 0x59, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
	0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
	0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7,
	0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
	0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E,
	0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
	0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
	0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB,
	0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
	0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
	0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0x97, 0xCD,
	0x0C, 0x13, 0xEC, 0x5F, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
	0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
	0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
	0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3,
	0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
	0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A,
	0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
	0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
	0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9,
	0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9,
	0x8E, 0x94, 0x9B, 0x1E, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C,
	0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D,
	0x0F, 0xB0, 0x54, 0xBB, 0x16, 0x87
};

for (uint8_t i = 0; i < 16; i++)
{
	for (uint8_t n = 0; n < 16; n++)
	{
		Te_InVSAdd[0] = (S_BOX[i*16 + n] >> 4) & 0x0f;
		Te_InVSAdd[1] = (S_BOX[i*16 + n] >> 0) & 0x0f;
		Te_InvSBox[Te_InVSAdd[0]][Te_InVSAdd[1]] = i * 16 + n;
	}
}

for (int i = 0; i < 16; i++)
{
	for (int j = 0; j < 16; j++)
	{
		printf("0x%02X,", Te_InvSBox[i][j]);
	}
	printf("\n");
}
```

得到逆SBox如下

```c++
uint8_t inv_SBox[256] = {
	0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x82,0xF2,0xD7,0xFA,
	0x7C,0xE3,0x39,0x83,0x9B,0x2F,0xFE,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
	0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xED,0x4C,0x95,0x0B,0x42,0xF9,0xC3,0x4E,
	0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
	0x72,0xF7,0xF5,0x64,0x86,0x68,0x98,0x0E,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
	0x6C,0x70,0x48,0x50,0xFC,0xEC,0xB9,0xDA,0x5E,0x16,0x46,0x57,0xA7,0x8D,0x9D,0x85,
	0x90,0xD8,0xAB,0x11,0x8C,0xBC,0xD3,0x0A,0xF6,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
	0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x10,0x03,0xC1,0xAF,0xBD,0x02,0x00,0x14,0x8A,0x6B,
	0x3A,0x91,0x12,0x41,0x4F,0x67,0xDC,0xFF,0x97,0xF1,0xCF,0xCE,0xEF,0xB4,0xE6,0x73,
	0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x80,0xE2,0xF8,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
	0x47,0xF0,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0F,0xAA,0x18,0xBE,0x1B,
	0xFB,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFD,0x78,0xCD,0x5A,0xF3,
	0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x13,0x01,0x59,0x27,0x81,0xEB,0x5F,
	0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEE,
	0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF4,0xB0,0xC8,0xEA,0xBB,0x3C,0x84,0x53,0x99,0x61,
	0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x15,0x63,0x55,0x21,0x0C,0x7D
};
```

然后就用正常的AES解密，替换Sbox和逆Sbox进行解密即可，先从IDA导出EncodeFlag和密钥，然后进行解密。

完整解密代码如下：

```c++
#include <iostream>
#include <bitset>
#include <string>

typedef std::bitset<8> byte_;
typedef std::bitset<32> word;

const int Nr = 10;
const int Nk = 4;

byte_ S_Box[16][16] = {
      0x7C, 0xCA, 0x7B, 0x77, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01,
      0x67, 0x2B, 0xFE, 0xD7, 0x47, 0xAB, 0x76, 0x63, 0x82, 0xC9,
      0x7D, 0xFA, 0x59, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4,
      0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC,
      0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7,
      0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2,
      0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E,
      0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
      0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB,
      0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB,
      0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C,
      0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5,
      0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0x97, 0xCD,
      0x0C, 0x13, 0xEC, 0x5F, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D,
      0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A,
      0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
      0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3,
      0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D,
      0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A,
      0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6,
      0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E,
      0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9,
      0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9,
      0x8E, 0x94, 0x9B, 0x1E, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C,
      0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D,
      0x0F, 0xB0, 0x54, 0xBB, 0x16, 0x87
};

byte_ Inv_S_Box[16][16] = {
    0x52,0x09,0x6A,0xD5,0x30,0x36,0xA5,0x38,0xBF,0x40,0xA3,0x9E,0x82,0xF2,0xD7,0xFA,
    0x7C,0xE3,0x39,0x83,0x9B,0x2F,0xFE,0x87,0x34,0x8E,0x43,0x44,0xC4,0xDE,0xE9,0xCB,
    0x54,0x7B,0x94,0x32,0xA6,0xC2,0x23,0x3D,0xED,0x4C,0x95,0x0B,0x42,0xF9,0xC3,0x4E,
    0x08,0x2E,0xA1,0x66,0x28,0xD9,0x24,0xB2,0x76,0x5B,0xA2,0x49,0x6D,0x8B,0xD1,0x25,
    0x72,0xF7,0xF5,0x64,0x86,0x68,0x98,0x0E,0xD4,0xA4,0x5C,0xCC,0x5D,0x65,0xB6,0x92,
    0x6C,0x70,0x48,0x50,0xFC,0xEC,0xB9,0xDA,0x5E,0x16,0x46,0x57,0xA7,0x8D,0x9D,0x85,
    0x90,0xD8,0xAB,0x11,0x8C,0xBC,0xD3,0x0A,0xF6,0xE4,0x58,0x05,0xB8,0xB3,0x45,0x06,
    0xD0,0x2C,0x1E,0x8F,0xCA,0x3F,0x10,0x03,0xC1,0xAF,0xBD,0x02,0x00,0x14,0x8A,0x6B,
    0x3A,0x91,0x12,0x41,0x4F,0x67,0xDC,0xFF,0x97,0xF1,0xCF,0xCE,0xEF,0xB4,0xE6,0x73,
    0x96,0xAC,0x74,0x22,0xE7,0xAD,0x35,0x80,0xE2,0xF8,0x37,0xE8,0x1C,0x75,0xDF,0x6E,
    0x47,0xF0,0x1A,0x71,0x1D,0x29,0xC5,0x89,0x6F,0xB7,0x62,0x0F,0xAA,0x18,0xBE,0x1B,
    0xFB,0x56,0x3E,0x4B,0xC6,0xD2,0x79,0x20,0x9A,0xDB,0xC0,0xFD,0x78,0xCD,0x5A,0xF3,
    0x1F,0xDD,0xA8,0x33,0x88,0x07,0xC7,0x31,0xB1,0x13,0x01,0x59,0x27,0x81,0xEB,0x5F,
    0x60,0x51,0x7F,0xA9,0x19,0xB5,0x4A,0x0D,0x2D,0xE5,0x7A,0x9F,0x93,0xC9,0x9C,0xEE,
    0xA0,0xE0,0x3B,0x4D,0xAE,0x2A,0xF4,0xB0,0xC8,0xEA,0xBB,0x3C,0x84,0x53,0x99,0x61,
    0x17,0x2B,0x04,0x7E,0xBA,0x77,0xD6,0x26,0xE1,0x69,0x15,0x63,0x55,0x21,0x0C,0x7D
};

word Rcon[10] = { 0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000,
                 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000 };

byte_ GFMul(byte_ a, byte_ b) {
    byte_ p = 0;
    byte_ hi_bit_set;
    for (int counter = 0; counter < 8; counter++) {
        if ((b & byte_(1)) != 0) {
            p ^= a;
        }
        hi_bit_set = (byte_)(a & byte_(0x80));
        a <<= 1;
        if (hi_bit_set != 0) {
            a ^= 0x1b;
        }
        b >>= 1;
    }
    return p;
}

void AddRoundKey(byte_ mtx[4 * 4], word k[4])
{
    for (int i = 0; i < 4; ++i)
    {
        word k1 = k[i] >> 24;
        word k2 = (k[i] << 8) >> 24;
        word k3 = (k[i] << 16) >> 24;
        word k4 = (k[i] << 24) >> 24;

        mtx[i] = mtx[i] ^ byte_(k1.to_ulong());
        mtx[i + 4] = mtx[i + 4] ^ byte_(k2.to_ulong());
        mtx[i + 8] = mtx[i + 8] ^ byte_(k3.to_ulong());
        mtx[i + 12] = mtx[i + 12] ^ byte_(k4.to_ulong());
    }
}

void InvSubbyte_s(byte_ mtx[4 * 4])
{
    for (int i = 0; i < 16; ++i)
    {
        int row = mtx[i][7] * 8 + mtx[i][6] * 4 + mtx[i][5] * 2 + mtx[i][4];
        int col = mtx[i][3] * 8 + mtx[i][2] * 4 + mtx[i][1] * 2 + mtx[i][0];
        mtx[i] = Inv_S_Box[row][col];
    }
}

void InvShiftRows(byte_ mtx[4 * 4])
{
    byte_ temp = mtx[7];
    for (int i = 3; i > 0; --i)
        mtx[i + 4] = mtx[i + 3];
    mtx[4] = temp;
    for (int i = 0; i < 2; ++i)
    {
        temp = mtx[i + 8];
        mtx[i + 8] = mtx[i + 10];
        mtx[i + 10] = temp;
    }
    temp = mtx[12];
    for (int i = 0; i < 3; ++i)
        mtx[i + 12] = mtx[i + 13];
    mtx[15] = temp;
}

void InvMixColumns(byte_ mtx[4 * 4])
{
    byte_ arr[4];
    for (int i = 0; i < 4; ++i)
    {
        for (int j = 0; j < 4; ++j)
            arr[j] = mtx[i + j * 4];

        mtx[i] = GFMul(0x0e, arr[0]) ^ GFMul(0x0b, arr[1]) ^ GFMul(0x0d, arr[2]) ^ GFMul(0x09, arr[3]);
        mtx[i + 4] = GFMul(0x09, arr[0]) ^ GFMul(0x0e, arr[1]) ^ GFMul(0x0b, arr[2]) ^ GFMul(0x0d, arr[3]);
        mtx[i + 8] = GFMul(0x0d, arr[0]) ^ GFMul(0x09, arr[1]) ^ GFMul(0x0e, arr[2]) ^ GFMul(0x0b, arr[3]);
        mtx[i + 12] = GFMul(0x0b, arr[0]) ^ GFMul(0x0d, arr[1]) ^ GFMul(0x09, arr[2]) ^ GFMul(0x0e, arr[3]);
    }
}

word Word(byte_& k1, byte_& k2, byte_& k3, byte_& k4)
{
    word result(0x00000000);
    word temp;
    temp = k1.to_ulong();
    temp <<= 24;
    result |= temp;
    temp = k2.to_ulong();
    temp <<= 16;
    result |= temp;
    temp = k3.to_ulong();
    temp <<= 8;
    result |= temp;
    temp = k4.to_ulong();
    result |= temp;
    return result;
}

word RotWord(const word& rw)
{
    word high = rw << 8;
    word low = rw >> 24;
    return high | low;
}

word SubWord(const word& sw)
{
    word temp;
    for (int i = 0; i < 32; i += 8)
    {
        int row = sw[i + 7] * 8 + sw[i + 6] * 4 + sw[i + 5] * 2 + sw[i + 4];
        int col = sw[i + 3] * 8 + sw[i + 2] * 4 + sw[i + 1] * 2 + sw[i];
        byte_ val = S_Box[row][col];
        for (int j = 0; j < 8; ++j)
            temp[i + j] = val[j];
    }
    return temp;
}

void KeyExpansion(byte_ key[4 * Nk], word w[4 * (Nr + 1)])
{
    word temp;
    int i = 0;
    while (i < Nk)
    {
        w[i] = Word(key[4 * i], key[4 * i + 1], key[4 * i + 2], key[4 * i + 3]);
        ++i;
    }

    i = Nk;

    while (i < 4 * (Nr + 1))
    {
        temp = w[i - 1];
        if (i % Nk == 0)
            w[i] = w[i - Nk] ^ SubWord(RotWord(temp)) ^ Rcon[i / Nk - 1];
        else
            w[i] = w[i - Nk] ^ temp;
        ++i;
    }
}

void Decrypt(byte_ in[4 * 4], word w[4 * (Nr + 1)])
{
    word key[4];

    for (int i = 0; i < 4; ++i)
        key[i] = w[4 * Nr + i];

    AddRoundKey(in, key);

    for (int round = Nr - 1; round > 0; --round)
    {
        InvShiftRows(in);
        InvSubbyte_s(in);
        for (int i = 0; i < 4; ++i)
            key[i] = w[4 * round + i];
        AddRoundKey(in, key);
        InvMixColumns(in);
    }

    InvShiftRows(in);
    InvSubbyte_s(in);

    for (int i = 0; i < 4; ++i)
        key[i] = w[i];

    AddRoundKey(in, key);
}


unsigned long long sub_7FF7A51A16DC(byte_* a1, byte_* a2)
{
    byte_* v2; // rax
    int j; // [rsp+8h] [rbp-8h]
    int i; // [rsp+Ch] [rbp-4h]

    for (i = 0; i <= 3; ++i)
    {
        for (j = 0; j <= 3; ++j)
        {
            v2 = a2++;
            a1[4LL * j + i] = *v2;
        }
    }
    return 0LL;
}

unsigned long long sub_7FF7A51A1749(byte_* a1, byte_* a2)
{
    byte_* v2; // rax
    int j; // [rsp+8h] [rbp-8h]
    int i; // [rsp+Ch] [rbp-4h]

    for (i = 0; i <= 3; ++i)
    {
        for (j = 0; j <= 3; ++j)
        {
            v2 = a2++;
            *v2 = a1[4LL * j + i];
        }
    }
    return 0LL;
}

int main()
{
    byte_ EncodeFlag1[] =
    {
      0x99, 0xE8, 0xB8, 0x01, 0xC8, 0x82, 0x51, 0x93, 0x12, 0xEE,
      0x89, 0x64, 0xE7, 0xEF, 0x63, 0x8D
    };
    byte_ EncodeFlag2[] =
    {
      0x51, 0xDF, 0x5D, 0x78, 0x39, 0xAA, 0x39, 0x62, 0xA0, 0xB4,
      0x50, 0x30, 0x47, 0x30, 0x21, 0x06
    };

    byte_ EncodeFlag_Change1[16];
    byte_ EncodeFlag_Change2[16];
    byte_ DecodeFlag1[16];
    byte_ DecodeFlag2[16];

    sub_7FF7A51A16DC(EncodeFlag_Change1, EncodeFlag1);
    sub_7FF7A51A16DC(EncodeFlag_Change2, EncodeFlag2);

    byte_ Key[]{ 'S','Y','C','L','O','V','E','R','S','Y','C','L','O','V','E','R' };

    word w[44]{};
    KeyExpansion(Key, w);

    // AES解密代码来源: https://www.acwing.com/blog/content/38719/
    Decrypt(EncodeFlag_Change1, w);
    Decrypt(EncodeFlag_Change2, w);

    sub_7FF7A51A1749(EncodeFlag_Change1, DecodeFlag1);
    sub_7FF7A51A1749(EncodeFlag_Change2, DecodeFlag2);

    for (int i = 0; i < 16; i++)
        std::cout << (unsigned char)DecodeFlag1[i].to_ulong();
    for (int i = 0; i < 16; i++)
        std::cout << (unsigned char)DecodeFlag2[i].to_ulong();

    // SYC{B3l1eue_Th@t_y0u__l3aRn_Aes}
}
```

### 致我的星星

(非预期解)

下载打开index.js查看代码

发现要求输入字符构成的字符串的MD5需要等于某个MD5

![QQ_1730946396348]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/star1.png)

接着往下看，能看得出来这题大概率是一个迷宫路线解题，而且起始点和终点要通过z3约束求解得到坐标。

![QQ_1730946484229]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/star2.png)

![QQ_1730946523081]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/star3.png)

可以看到是用STAR四个字符当作方向键，最终走到终点，路径构成的字符串就是最后的Key。

![QQ_1730946562196]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/star4.png)

由于我观察到这题路径仅由四个字符构成，而且已经给出了Key的MD5，就直接用hashcat进行MD5爆破，而不走迷宫，

由于不知道字符串个数，所以从6长度开始尝试，尝试到18长度，Crack成功。

hashcat命令行:

```c++
INPUT:
.\hashcat.exe -a 3 -m 0 5c50152daeee511f32db7bf8a5502c69 -1 STAR ?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1
    
OUTPUT:

5c50152daeee511f32db7bf8a5502c69:STTAAARRRRAAATTTTS

Session..........: hashcat
Status...........: Cracked
Hash.Mode........: 0 (MD5)
Hash.Target......: 5c50152daeee511f32db7bf8a5502c69
Time.Started.....: Thu Nov 07 10:31:50 2024 (4 secs)
Time.Estimated...: Thu Nov 07 10:31:54 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1?1 [18]
Guess.Charset....: -1 STAR, -2 Undefined, -3 Undefined, -4 Undefined
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  9199.0 MH/s (8.85ms) @ Accel:128 Loops:128 Thr:256 Vec:1
Recovered........: 1/1 (100.00%) Digests (total), 1/1 (100.00%) Digests (new)
Progress.........: 41573941248/68719476736 (60.50%)
Rejected.........: 0/41573941248 (0.00%)
Restore.Point....: 162004992/268435456 (60.35%)
Restore.Sub.#1...: Salt:0 Amplifier:0-128 Iteration:0-128
Candidate.Engine.: Device Generator
Candidates.#1....: SARAARARARARATTTTS -> RTTATSRRSRRRRAATTS
Hardware.Mon.#1..: Temp: 62c Util: 98% Core:2565MHz Mem:8000MHz Bus:8
```

所以即可得到Flag

**SYC{STTAAARRRRAAATTTTS}**

### 你干嘛

(非预期解)

拖入IDA分析，发现main函数分析错误，熟悉的花指令，不过这题多了try catch

![QQ_1730947149840]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/youganma1.png)

先nop掉框起来的这部分代码，然后将出现的红色的call第一个E8字节patch掉，改成90，在对下面代码按C重新分析

![QQ_1730948026641]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/youganma2.png)

后面发现这部分还原的代码也对ida重构函数有影响，直接nop掉这部分。

![QQ_1730948097741]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/youganma3.png)

![QQ_1730948135630]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/youganma4.png)

往下翻，会找到两处的异常捕捉处理的函数，直接都nop掉，然后Edit->Function->Delete function，将main函数删除，然后选中main所有代码，按P重构函数，即可按F5分析得到还原的伪代码。

还原的伪代码：

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  _DWORD *v3; // eax
  int v4; // eax
  int v5; // eax
  bool v6; // cf
  int v8; // [esp-4h] [ebp-110h]
  char v9; // [esp+0h] [ebp-10Ch] BYREF
  int v10; // [esp+18h] [ebp-F4h]
  int v11; // [esp+1Ch] [ebp-F0h]
  _BYTE *v12; // [esp+20h] [ebp-ECh]
  int v13; // [esp+24h] [ebp-E8h]
  char *FileName; // [esp+28h] [ebp-E4h]
  void *Block; // [esp+2Ch] [ebp-E0h]
  char v16; // [esp+32h] [ebp-DAh] BYREF
  char v17; // [esp+33h] [ebp-D9h] BYREF
  _BYTE v18[16]; // [esp+34h] [ebp-D8h] BYREF
  char v19[4]; // [esp+44h] [ebp-C8h] BYREF
  const char *v20; // [esp+48h] [ebp-C4h]
  unsigned __int8 *v21; // [esp+4Ch] [ebp-C0h]
  size_t Size; // [esp+50h] [ebp-BCh]
  char *p_Arglist; // [esp+54h] [ebp-B8h]
  unsigned __int8 v24; // [esp+58h] [ebp-B4h]
  unsigned __int8 v25; // [esp+59h] [ebp-B3h]
  char v26; // [esp+5Ah] [ebp-B2h] BYREF
  _BYTE v27[12]; // [esp+5Ch] [ebp-B0h] BYREF
  char v28[12]; // [esp+68h] [ebp-A4h] BYREF
  char Arglist; // [esp+74h] [ebp-98h] BYREF
  _BYTE v30[99]; // [esp+75h] [ebp-97h] BYREF
  _BYTE v31[32]; // [esp+D8h] [ebp-34h] BYREF
  char *v32; // [esp+FCh] [ebp-10h]
  int v33; // [esp+108h] [ebp-4h]

  v32 = &v9;
  if ( IsDebuggerPresent() )
    exit(1);
  FileName = "Dusk_witnesses_devout_believers.gif";
  sub_401020("  ____   __   __   ____   _        ___   __     __  _____   ____  \n", v9);
  sub_401020(" / ___|  \\ \\ / /  / ___| | |      / _ \\  \\ \\   / / | ____| |  _ \\ \n", v9);
  sub_401020(" \\___ \\   \\ V /  | |     | |     | | | |  \\ \\ / /  |  _|   | |_) |\n", v9);
  sub_401020("  ___) |   | |   | |___  | |___  | |_| |   \\ V /   | |___  |  _ < \n", v9);
  sub_401020(" |____/    |_|    \\____| |_____|  \\___/     \\_/    |_____| |_| \\_\\\n", v9);
  sub_401020(aWhatAreYouDoin, v9);
  sub_401050("%s", (char)&Arglist);
  p_Arglist = &Arglist;
  v12 = v30;
  p_Arglist += strlen(p_Arglist);
  v11 = ++p_Arglist - v30;
  Size = p_Arglist - v30;
  while ( 1 )
  {
    qmemcpy(v31, "0O00O0O00OO0O0O01III1II111I1I1I1", sizeof(v31));
    sub_402010(v27, 0xCu);
    qmemcpy(v18, "!l", 2);
    v18[2] = -3;
    v18[3] = -90;
    v18[4] = -74;
    v18[5] = -126;
    v18[6] = -81;
    v18[7] = -52;
    v18[8] = 81;
    v18[9] = 106;
    v18[10] = -47;
    v18[11] = -30;
    v18[12] = -87;
    v18[13] = 62;
    v18[14] = -90;
    v18[15] = -112;
    v8 = sub_402170(&v17);
    v3 = (_DWORD *)unknown_libname_1(v18, v19);
    sub_4020B0(*v3, v3[1], v8);
    LOBYTE(v33) = 2;
    sub_402010(v28, 0xCu);
    v26 = 0;
    v4 = sub_402170(&v16);
    sub_402110(Size, (int)&v26, v4);
    v5 = sub_402050(v28);
    sub_401A50(v31, &v31[16], v5);
    if ( Size % 0x10 || !(unsigned __int8)sub_402180(v28, v27) )
    {
      if ( Block )
      {
        v20 = "ZmFrZXthcmVfeW08X6JlYWx4X6JpZ7h9fQ==";
        v21 = (unsigned __int8 *)Block;
        while ( 1 )
        {
          v25 = *v21;
          v6 = v25 < (unsigned int)*v20;
          if ( v25 != *v20 )
            break;
          if ( !v25 )
            goto LABEL_13;
          v24 = v21[1];
          v6 = v24 < (unsigned int)v20[1];
          if ( v24 != v20[1] )
            break;
          v21 += 2;
          v20 += 2;
          if ( !v24 )
          {
LABEL_13:
            v13 = 0;
            goto LABEL_15;
          }
        }
        v13 = v6 ? -1 : 1;
LABEL_15:
        v10 = v13;
        if ( v13 )
          sub_401020(aBase, v9);
        else
          sub_401020((char *)&byte_4043F8, v9);
        free(Block);
      }
    }
    else
    {
      sub_401020("wow\n", v9);
      sub_4013B0(FileName, &Arglist);
      sub_401530(FileName);
    }
    LOBYTE(v33) = 2;
    sub_402060(v28);
    v33 = -1;
  }
}
```

由于题目有给一个Dusk_witnesses_devout_believers.gif，但是似乎不能直接打开，猜测应该是输入Key然后程序会解包被加密的Gif文件，伪代码也能观察到最底下，两个有传入FileName的两个函数，sub_4013B0和sub_401530

```c++
void __usercall sub_4013B0(char *FileName@<ecx>, char *Source@<edx>, char a3@<dil>)
{
  signed int v4; // ebx
  _BYTE *v5; // eax
  _BYTE *v6; // edi
  signed int v7; // esi
  unsigned int v8; // kr00_4
  char v10; // [esp+0h] [ebp-78h]
  FILE *v12; // [esp+8h] [ebp-70h] BYREF
  FILE *Stream; // [esp+Ch] [ebp-6Ch] BYREF
  char Destination[100]; // [esp+10h] [ebp-68h] BYREF

  strncpy(Destination, Source, 0x63u);
  Destination[99] = 0;
  Stream = 0;
  fopen_s(&Stream, FileName, "rb");
  if ( Stream )
  {
    fseek(Stream, 0, 2);
    v4 = ftell(Stream);
    fseek(Stream, 0, 0);
    v5 = malloc(v4);
    v6 = v5;
    if ( v5 )
    {
      fread(v5, 1u, v4, Stream);
      fclose(Stream);
      v7 = 0;
      if ( v4 > 0 )
      {
        v8 = strlen(Destination);
        do
        {
          v6[v7] ^= Destination[v7 % v8];
          ++v7;
        }
        while ( v7 < v4 );
      }
      v12 = 0;
      fopen_s(&v12, FileName, "wb");
      if ( v12 )
      {
        fwrite(v6, 1u, v4, v12);
        fclose(v12);
        free(v6);
      }
      else
      {
        sub_401020("error\n", a3);
        free(v6);
      }
    }
    else
    {
      sub_401020("error\n", a3);
      fclose(Stream);
    }
  }
  else
  {
    sub_401020("dec error!\n", v10);
  }
}

int __thiscall sub_401530(char *FileName)
{
  char *v1; // eax
  FILE *Stream; // [esp+0h] [ebp-8h] BYREF

  Stream = 0;
  fopen_s(&Stream, FileName, "rb");
  if ( Stream )
  {
    fclose(Stream);
    v1 = (char *)&unk_4041E4;
  }
  else
  {
    v1 = "open error!\n";
  }
  return sub_401020(v1, (char)Stream);
}
```

很清晰的能看出来，sub_4013B0是将文件读入内存中，然后与我们输入的Key进行Xor计算，然后再调用sub_401530写出解密后的文件。

由于只是简单的Xor计算，所以这里我是用Misc的思想解题

标准GIF字节格式如下，开头6字节和结尾2字节是固定的

```
---------------------------------
47 49 46 38 39 61
....
00 3B
---------------------------------
```

而被加密的Gif文件数据如下

```
---------------------------------
36 3E 23 4A 4D 18
....
64 5D
---------------------------------
```

将两组字节进行Xor计算即可还原得到部分Key

```
---------------------------------
71 77 65 72 74 79
....
64 66
---------------------------------

ASCII:

qwerty
...
df
```

通过伪代码中的这一行可以判断出输入的Key长度是16的倍数

> if ( Size % 0x10 || !(unsigned __int8)sub_402180(v29, v28) )

再结合上面解密出的部分Key，可以初步猜测Key就是键盘上的"qwertyuiopasdfgh"

被加密的Gif文件字节数量为0xC3DD，将他模16算出结果为13，符合最后两个字节解密出来的"df"再Key中的位置，印证了猜想。

运行exe直接输入Key，即可解密出Gif，再用StegSolve分解Gif即可拿到Flag。

![youganma_flag]( https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/youganma_flag.png)

**SYC{111_YOU_WIN_THE_FLAG}**

### LinkedListModular

拖入IDA分析得到伪代码

```c+=
unsigned __int64 __fastcall check(__int64 a1)
{
  time_t v1; // rax
  unsigned int v2; // eax
  void *v3; // rax
  void *v4; // rax
  void *v5; // rax
  int i; // [rsp+14h] [rbp-17Ch]
  int v8; // [rsp+18h] [rbp-178h]
  int j; // [rsp+1Ch] [rbp-174h]
  int v10; // [rsp+28h] [rbp-168h]
  int v11; // [rsp+2Ch] [rbp-164h]
  _QWORD *v12; // [rsp+30h] [rbp-160h]
  _QWORD *v13; // [rsp+38h] [rbp-158h]
  __int64 v14; // [rsp+40h] [rbp-150h]
  _QWORD *v15; // [rsp+48h] [rbp-148h]
  _QWORD *v16; // [rsp+50h] [rbp-140h]
  char *v17; // [rsp+60h] [rbp-130h]
  _QWORD *v18; // [rsp+68h] [rbp-128h]
  void *s; // [rsp+78h] [rbp-118h]
  void *str; // [rsp+80h] [rbp-110h]
  void *v21; // [rsp+88h] [rbp-108h]
  _BYTE v22[16]; // [rsp+90h] [rbp-100h] BYREF
  _BYTE v23[16]; // [rsp+A0h] [rbp-F0h] BYREF
  _BYTE v24[16]; // [rsp+B0h] [rbp-E0h] BYREF
  _BYTE v25[16]; // [rsp+C0h] [rbp-D0h] BYREF
  _BYTE v26[16]; // [rsp+D0h] [rbp-C0h] BYREF
  _BYTE v27[16]; // [rsp+E0h] [rbp-B0h] BYREF
  _BYTE v28[16]; // [rsp+F0h] [rbp-A0h] BYREF
  _BYTE v29[16]; // [rsp+100h] [rbp-90h] BYREF
  _BYTE v30[16]; // [rsp+110h] [rbp-80h] BYREF
  _BYTE v31[16]; // [rsp+120h] [rbp-70h] BYREF
  _BYTE v32[16]; // [rsp+130h] [rbp-60h] BYREF
  _BYTE v33[16]; // [rsp+140h] [rbp-50h] BYREF
  _BYTE v34[32]; // [rsp+150h] [rbp-40h] BYREF
  _QWORD v35[3]; // [rsp+170h] [rbp-20h] BYREF
  unsigned __int64 v36; // [rsp+188h] [rbp-8h]

  v36 = __readfsqword(0x28u);
  v15 = malloc(0x10uLL);
  saveinp(v15, a1);
  __gmp_randinit_default(v34);
  v1 = time(0LL);
  __gmp_randseed_ui(v34, v1);
  v2 = time(0LL);
  srand(v2);
  v12 = (_QWORD *)v15[1];
  v16 = malloc(0x28uLL);
  v13 = v16;
  for ( i = 0; i <= 3; ++i )
  {
    v18 = malloc(0x28uLL);
    v18[4] = 0LL;
    v13[4] = v18;
    v13 = v18;
    while ( 1 )
    {
      v11 = rand() % 65281 + 256;
      __gmpz_init_set_ui(v22, v11);
      __gmpz_init();
      __gmpz_init();
      __gmpz_urandomb(v23, v34, 1024LL);
      __gmpz_urandomb(v24, v34, 1024LL);
      __gmpz_nextprime(v23, v23);
      __gmpz_nextprime(v24, v24);
      __gmpz_init();
      __gmpz_init();
      __gmpz_init();
      __gmpz_sub_ui(v26, v23, 1LL);
      __gmpz_sub_ui(v27, v24, 1LL);
      __gmpz_mul(v25, v26, v27);
      __gmpz_init();
      __gmpz_gcd(v28, v22, v25);
      __gmpz_init();
      __gmpz_divexact(v29, v22, v28);
      __gmpz_init();
      if ( (unsigned int)__gmpz_invert(v30, v29, v25) )
      {
        if ( __gmpz_get_ui() != 1 )
          break;
      }
      __gmpz_clear(v23);
      __gmpz_clear(v24);
      __gmpz_clear(v25);
      __gmpz_clear(v26);
      __gmpz_clear(v27);
      __gmpz_clear(v28);
      __gmpz_clear(v29);
      __gmpz_clear(v30);
    }
    __gmpz_init_set_str(v31, *v12, 16LL);
    __gmpz_init();
    __gmpz_mul(v32, v23, v24);
    __gmpz_init();
    __gmpz_powm(v33, v31, v22, v32);
    v3 = malloc(0x208uLL);
    memset(v3, 0, 0x208uLL);
    s = (void *)__gmpz_get_str(0LL, 16LL, v33);
    v4 = malloc(0x101uLL);
    memset(v4, 0, 0x101uLL);
    str = (void *)__gmpz_get_str(0LL, 16LL, v23);
    v5 = malloc(0x101uLL);
    memset(v5, 0, 0x101uLL);
    v21 = (void *)__gmpz_get_str(0LL, 16LL, v24);
    *v18 = s;
    v18[1] = str;
    v18[2] = v21;
    *((_DWORD *)v18 + 6) = __gmpz_get_ui();
    __gmpz_clear(v31);
    __gmpz_clear(v32);
    __gmpz_clear(v33);
    v12 = (_QWORD *)v12[1];
  }
  v14 = v16[4];
  qmemcpy(v35, "IKnowYouLikeCrypto", 18);
  v8 = 0;
  while ( v14 )
  {
    v17 = (char *)malloc(0x800uLL);
    if ( !v17 )
    {
      puts("malloc failed");
      exit(0);
    }
    memset(v17, 0, 0x800uLL);
    sprintf(
      v17,
      "p:0x%s q:0x%s e:%#x c:0x%s",
      *(_QWORD *)(v14 + 8),
      *(_QWORD *)(v14 + 16),
      *(unsigned int *)(v14 + 24),
      *(_QWORD *)v14);
    v10 = strlen(v17);
    for ( j = 0; j < v10; ++j )
      v17[j] ^= *((_BYTE *)v35 + j % 18);
    write_enc_cmp_to_file(v8, (__int64)v17, v10);
    v14 = *(_QWORD *)(v14 + 32);
    ++v8;
  }
  return __readfsqword(0x28u) ^ v36;
}
```

前半部分gmp计算过程逻辑：

1. 随机生成e、p、q，计算出phi
2. v29 = e//gcd(e,phi)
3. 计算v29和phi是否有逆元，如果有逆元并且gcd(e,phi)不等于1，就符合条件跳出循环

后半部分文件输出逻辑：

1. 将p、q、e、c进行字符串格式化
2. 然后再将格式化后的字符串与"IKnowYouLikeCrypto"进行Xor计算
3. 输出到文件

所以解题第一步是将output文件夹下的四个enc文件与Key进行Xor计算得到p、q、e、c数据

解密第一步代码：

```c++
int main()
{
	std::string XorKey = "IKnowYouLikeCrypto";
	std::string EncFilePath = "..\\output\\";

	for (int i = 0; i < 4; i++)
	{
		auto FileName = EncFilePath + "cmp" + std::to_string(i) + ".enc";
		auto OutFileName = EncFilePath + "Dec_cmp" + std::to_string(i) + ".txt";
		std::ifstream File(FileName, std::ios::in);
		std::ofstream OutFile(OutFileName, std::ios::out);

		std::string Buffer;
		std::string Buffer2;
		while (std::getline(File, Buffer))
		{
             // 取enc文件里面的每个字节文本再转换到整数进行xor计算
			for (int i = 2, j = 0; i < Buffer.length(); i+=5, j++)
			{
				Buffer2 += (char)(std::stoi(Buffer.substr(i, 2), nullptr, 16) ^ XorKey[j % XorKey.length()]);
			}
			OutFile << Buffer2;
		}
		File.close();
		OutFile.close();
	}
}
```

运行即可得到4个解密后的txt数据。

直接用python进行解密，由于是e和phi不互质且phi与e//gcd(e,phi)有逆元，所以得换种方法进行RSA解密。

后续解密过程发现2文件与其他三个不同，并且计算发现2文件的gcd(e,q-1)为1，所以直接计算e与q-1的逆元进行解密即可。

0，1，3文件的解密代码如下：

```python
from Crypto.Util.number import *
import gmpy2

p = ...
q = ...
e = ...
c = ...
n = p * q

t = gmpy2.gcd(phi, e)
d = gmpy2.invert(e // t, phi)
M = gmpy2.powmod(c, d, n)
m = gmpy2.iroot(M, 2)[0]
print(long_to_bytes(m).hex())
```

2文件的解密代码如下：

```python
from Crypto.Util.number import *
import gmpy2

p = ...
q = ...
e = ...
c = ...
n = p * q

phi = (p-1*(q-1))
d = gmpy2.invert(e,q-1)
m = gmpy2.powmod(c,d,q)
print(long_to_bytes(m).hex())
```

最后解密得到以下四个64字节长度的数据

```
688682bc45a043f2e139153780fdd54af8517dd885464bdfa3dbcf776169255c
9304306d542508c59abf30f99b98fefcd2951df2effc81fca8e5aa26414819cb
144576b4302a8c5262d7d4d9b2ebb3468835c709cc88fc0b8b38b52a6f31d3ab
6b25edeccfcf74f0dfc77abc90d757a49c1d0fb1c90e67db7918c61be80ad59c
```

进行拼接然后MD5计算即可得到Flag

**flag{d3f06717efc6c0daf454ffeac9764687}**

### blasting_master

这题考的是爆破能力，同样直接IDA分析得到伪代码，以下代码是我动态调试后的代码，所以部分函数名和变量名和原始不一致。

```c++
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char s[8]; // [rsp+0h] [rbp-70h] BYREF
  __int64 v5; // [rsp+8h] [rbp-68h]
  __int64 v6; // [rsp+10h] [rbp-60h]
  __int64 v7; // [rsp+18h] [rbp-58h]
  __int64 v8; // [rsp+20h] [rbp-50h]
  __int64 v9; // [rsp+28h] [rbp-48h]
  __int64 v10; // [rsp+30h] [rbp-40h]
  __int64 v11; // [rsp+38h] [rbp-38h]
  __int64 v12; // [rsp+40h] [rbp-30h]
  __int64 v13; // [rsp+48h] [rbp-28h]
  __int64 v14; // [rsp+50h] [rbp-20h]
  __int64 v15; // [rsp+58h] [rbp-18h]
  int v16; // [rsp+60h] [rbp-10h]
  unsigned __int64 v17; // [rsp+68h] [rbp-8h]

  v17 = __readfsqword(40u);
  *(_QWORD *)s = 0LL;
  v5 = 0LL;
  v6 = 0LL;
  v7 = 0LL;
  v8 = 0LL;
  v9 = 0LL;
  v10 = 0LL;
  v11 = 0LL;
  v12 = 0LL;
  v13 = 0LL;
  v14 = 0LL;
  v15 = 0LL;
  v16 = 0;
  if ( fgets(s, 100, stdin) )
    s[strcspn(s, "\n")] = 0;
  while ( !byte_5555555582DE )
    sub_555555555464((__int64)s);
  if ( !memcmp(&unk_555555556020, s2, 16 * dword_555555558040) )
    puts("\nCongratulations!");
  else
    puts("\nSomething Wrong.");
  return 0LL;
}
```

可以看到就一个关键函数，sub_555555555464

```c++
unsigned __int64 __fastcall sub_555555555464(__int64 a1)
{
  int i; // [rsp+14h] [rbp-1Ch]
  int j; // [rsp+18h] [rbp-18h]
  __int64 v4; // [rsp+1Eh] [rbp-12h] BYREF
  __int16 v5; // [rsp+26h] [rbp-Ah]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(40u);
  v4 = 0LL;
  v5 = 0;
  for ( i = 0; i <= 3; ++i )
    *((_BYTE *)&v4 + i) = *(_BYTE *)(Count + i + a1);
  BYTE4(v4) = 0;
  MD5((const char *)&v4, (__int64)&s2[16 * Count]);
  for ( j = 0; j <= 15; ++j )
    s2[16 * Count + j] = 7 * ((j + 42) ^ s2[16 * Count + j]) + 82 * (j % 15);
  ++Count;
  return v6 - __readfsqword(0x28u);
}
```

主加密流程：

1. 输入100长度字符串
2. 下标递增，取下标开始往后4个字节进行MD5加密计算。如字符串"12345" ，第一次加密"1234"，第二次就是加密"2345"
3. 对加密后的16个字节再次进行XOR加密

因为是递增式四字节MD5加密，所以100长度字符串会有40组MD5，那么从memcmp第一个参数导出40组MD5数据，进行XOR计算还原，然后爆破MD5。

该XOR计算没办法直接逆向计算，因为是在255范围下的计算，所以直接爆破就可以。

由于是递增式四字节加密，所以只需要取出间隔四个的MD5进行爆破然后组合就可以得到完整Flag。

完整代码如下: 

```c++
#include "md5.h"

// Hex数据转字符串
std::string toHexString(const BYTE* data, size_t length) 
{
	std::ostringstream ss;
	for (size_t i = 0; i < length; ++i) 
	{
		ss << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(data[i]);
	}
	return ss.str();
}

// 爆破Xor值
void CrackEncode(BYTE* data)
{
	for (int j = 0; j <= 15; ++j) 
	{
		for (int k = 0; k < 256; ++k) 
		{
			int v = (7 * ((j + 42) ^ k) + 82 * (j % 15)) % 256;
			if (v == data[j])
			{
				data[j] = k;
				break;
			}
		}
	}
}

int main()
{
	BYTE md5_encode[] =
	{
	  0xB2, 0x50, 0xA0, 0xBC, 0x3A, 0x7F, 0x54, 0x6D, 0x96, 0x07,
	  0x0F, 0x71, 0x9A, 0x72, 0xEB, 0xA5, 0xA0, 0xB5, 0x71, 0xA4,
	  0x6A, 0xB8, 0xBA, 0xFA, 0xE4, 0x31, 0xC3, 0x71, 0x54, 0x29,
	  0xA7, 0x59, 0x20, 0x2B, 0x13, 0x21, 0xBD, 0x67, 0x5F, 0x8D,
	  0x65, 0x3A, 0x02, 0x27, 0x08, 0x4F, 0x92, 0x9C, 0xB5, 0x7C,
	  0xDF, 0x69, 0x34, 0xB8, 0x82, 0x2D, 0xF6, 0xCA, 0x7A, 0x65,
	  0x98, 0x63, 0xDC, 0x51, 0x2A, 0x34, 0x97, 0x4F, 0xF8, 0xBC,
	  0x23, 0x1F, 0x38, 0xA8, 0xA6, 0x2F, 0xA9, 0x0D, 0x64, 0x4C,
	  0xAC, 0x2F, 0xF9, 0xF5, 0x2D, 0xB1, 0x91, 0xA8, 0xD5, 0x76,
	  0xD9, 0x2D, 0xC6, 0xAC, 0x2E, 0x69, 0x32, 0xD5, 0x64, 0x1D,
	  0xC1, 0x3C, 0xEC, 0xF5, 0x2C, 0x90, 0xED, 0xF4, 0x17, 0x8B,
	  0x55, 0x4C, 0xE4, 0x6C, 0x3B, 0xB3, 0xDA, 0x29, 0xC0, 0x7B,
	  0x39, 0xDF, 0x92, 0x73, 0xFC, 0xC9, 0xC2, 0xA8, 0x68, 0x11,
	  0x22, 0x2B, 0x64, 0x3F, 0x12, 0x9B, 0x95, 0x73, 0x2A, 0x05,
	  0xD3, 0x3F, 0x2E, 0x33, 0xF1, 0x85, 0xED, 0x07, 0x7B, 0x86,
	  0x8F, 0x62, 0x2D, 0x79, 0x03, 0xAC, 0x80, 0xCE, 0xF5, 0xB2,
	  0xA0, 0x0C, 0xF7, 0xE1, 0xC5, 0x0E, 0x63, 0x27, 0xD1, 0x65,
	  0x23, 0xEA, 0x5A, 0x1C, 0x02, 0x0B, 0x32, 0xBA, 0x1F, 0xE5,
	  0xC7, 0x22, 0xA5, 0x66, 0x77, 0xEA, 0x5B, 0xE4, 0x64, 0xAB,
	  0x8B, 0x60, 0xB6, 0xDF, 0x00, 0xDC, 0xF7, 0x6D, 0x93, 0xEC,
	  0x2F, 0x2F, 0x68, 0x07, 0x50, 0xE0, 0xD1, 0x1A, 0x3F, 0xC6,
	  0x4E, 0x2E, 0xC6, 0xBB, 0xAE, 0x08, 0x40, 0xD8, 0x5B, 0x11,
	  0xB5, 0xDC, 0x15, 0x35, 0x7F, 0x63, 0x49, 0x3E, 0x5B, 0x9C,
	  0x0D, 0xFC, 0x0D, 0xB6, 0x80, 0xB7, 0x2B, 0x00, 0xEF, 0x3C,
	  0x0C, 0x2F, 0xEB, 0x86, 0x44, 0x57, 0x74, 0x9E, 0x5F, 0x1F,
	  0x8B, 0xA1, 0xC9, 0x01, 0xF1, 0xD8, 0xF4, 0x92, 0x82, 0x95,
	  0x6F, 0x85, 0xD2, 0x15, 0x22, 0x1F, 0xF0, 0x9F, 0xD1, 0xAB,
	  0x51, 0x39, 0x9A, 0xB6, 0xC4, 0xDA, 0xFB, 0x38, 0x8D, 0xE6,
	  0x8C, 0x57, 0x19, 0x5E, 0x94, 0xDA, 0x57, 0xCC, 0xF0, 0xB9,
	  0x0A, 0x4A, 0x17, 0x82, 0xFC, 0xC5, 0x4F, 0x4B, 0x5A, 0xA5,
	  0xF4, 0xE5, 0x3E, 0xFA, 0x3A, 0x0A, 0xF4, 0xB4, 0x8E, 0x7F,
	  0x25, 0x84, 0x75, 0x90, 0xCD, 0x35, 0x87, 0xEB, 0xC3, 0xCE,
	  0x81, 0x2B, 0x86, 0xC9, 0x16, 0x7E, 0x85, 0x68, 0x2D, 0xF1,
	  0xDB, 0x8E, 0x74, 0x15, 0xCF, 0x95, 0x51, 0x07, 0x88, 0x5E,
	  0x1B, 0xE9, 0x37, 0xC9, 0x5B, 0xBA, 0x61, 0xEB, 0x9F, 0x7B,
	  0xE4, 0x89, 0x10, 0xF0, 0x6E, 0xCD, 0x75, 0x71, 0xAD, 0x09,
	  0x74, 0x58, 0x49, 0xA3, 0xF5, 0x33, 0x83, 0x75, 0x22, 0x95,
	  0x1B, 0xE3, 0x3C, 0x48, 0x05, 0x5C, 0xAD, 0xA8, 0x6B, 0xFD,
	  0x41, 0xEB, 0xAF, 0xC6, 0x02, 0x28, 0xC6, 0x5E, 0xCF, 0x36,
	  0xAE, 0x50, 0xCE, 0x93, 0xF2, 0x70, 0x88, 0x9D, 0x3F, 0x4A,
	  0x9F, 0x86, 0xE7, 0x67, 0x64, 0xB0, 0x02, 0x96, 0x0C, 0xAB,
	  0x9F, 0xEB, 0x4B, 0x03, 0x44, 0x92, 0xDE, 0x6C, 0xF4, 0xCE,
	  0x32, 0x4F, 0x4F, 0x38, 0xE2, 0x52, 0x59, 0xCA, 0x95, 0x4A,
	  0x11, 0xD8, 0x30, 0xA2, 0x7B, 0xD5, 0x3A, 0xE6, 0x11, 0xDA,
	  0x3A, 0x4A, 0x33, 0x61, 0x39, 0x65, 0x26, 0xD2, 0x78, 0xBC,
	  0xED, 0xBD, 0xA5, 0x8B, 0x2B, 0x87, 0x4C, 0x95, 0x47, 0x25,
	  0x02, 0xBA, 0x83, 0x3D, 0xDC, 0xE4, 0x6A, 0xAD, 0x67, 0xDD,
	  0x22, 0xB1, 0xBD, 0x2B, 0x7C, 0x53, 0x11, 0x3C, 0xD9, 0x23,
	  0x06, 0x3D, 0x20, 0xBA, 0x28, 0xC8, 0x2D, 0x89, 0x51, 0x57,
	  0x63, 0x82, 0xA0, 0xC8, 0xA8, 0xDE, 0x29, 0x61, 0xC1, 0x53,
	  0x51, 0xB0, 0xBC, 0x37, 0x04, 0xEE, 0xC9, 0x35, 0x8A, 0xA8,
	  0xA2, 0x66, 0xBA, 0x6F, 0x24, 0xB6, 0x3F, 0x62, 0x41, 0x6D,
	  0x10, 0x46, 0xCB, 0x06, 0x12, 0x39, 0xD9, 0x0E, 0xF9, 0xDC,
	  0x19, 0xA7, 0x65, 0xB8, 0xC0, 0x40, 0xBE, 0xF6, 0x99, 0x9A,
	  0xAF, 0x02, 0x16, 0x37, 0x4D, 0xA5, 0x75, 0x4C, 0x42, 0x4B,
	  0x1A, 0xF0, 0x52, 0xDA, 0x38, 0xF3, 0x6B, 0xA9, 0x1A, 0xDC,
	  0xFA, 0x80, 0xB0, 0x60, 0xB1, 0xFD, 0x73, 0x7B, 0x78, 0xD9,
	  0x62, 0x83, 0x26, 0xBF, 0x16, 0x33, 0x71, 0x79, 0x6F, 0x11,
	  0x2F, 0xE9, 0xA7, 0xBB, 0x46, 0x46, 0xD6, 0x8F, 0xF6, 0x21,
	  0x7E, 0xFC, 0x68, 0x12, 0x86, 0x6B, 0xFC, 0x51, 0xC9, 0x70,
	  0x7A, 0x74, 0xBC, 0x8F, 0x6E, 0x0B, 0x86, 0x42, 0x6F, 0x5C,
	  0xFD, 0xF7, 0x4E, 0x27, 0x71, 0xFE, 0x37, 0xE6, 0xC8, 0x62,
	  0x47, 0xFC, 0xD5, 0x6C, 0xBA, 0x5C, 0xD9, 0x29, 0x5A, 0x73,
	  0xAE, 0xC3, 0x8F, 0xF0, 0x46, 0x95, 0x32, 0x42, 0x2D, 0xD0
	};

	// Decode
	for (int i = 0; i <= 40; i += 4)
	{
		CrackEncode(md5_encode + (i * 16));
		auto MD5 = toHexString(md5_encode + (i * 16), 16);
		printf("%s\n", MD5.c_str());
	}
    
	/*
	OUTPUT:
		14b908a7d09c68a87840b9c8984f61ca
		2ca599b2fe6161e62ab94afa5172e06d
		72a23ece2adc1a4aa194eefc5b34064c
		30e0e84737fa51539b381802fe2dfbaf
		46eb9e84cfd25a806ca850eac9007b86
		1d34a2f86cd36f37098a558db2ca6dba
		44d16275afab9eef60b4e673e6025ddf
		e2ed036c5568391e56c6a19c30c739a2
		dc90ac6dbfd7f3a8b24fc5b5408e433b
		edca31600f569d6a284ffa5a44a6561d
		fe1db4d7729110b3d6759c3f5af908ed
	*/
}
```

得到十一组MD5，将这些MD5存入a.txt放到hashcat文件夹下，然后直接进行四字节爆破。

hashcat命令行:

```
INPUT:
./hashcat.exe -m 0 a.txt -a 3 ?a?a?a?a

OUTPUT:
e2ed036c5568391e56c6a19c30c739a2:stin
44d16275afab9eef60b4e673e6025ddf:_bla
edca31600f569d6a284ffa5a44a6561d:p3rt
1d34a2f86cd36f37098a558db2ca6dba:BeSt
30e0e84737fa51539b381802fe2dfbaf:@re_
72a23ece2adc1a4aa194eefc5b34064c:y0u_
46eb9e84cfd25a806ca850eac9007b86:th3_
2ca599b2fe6161e62ab94afa5172e06d:W0w!
dc90ac6dbfd7f3a8b24fc5b5408e433b:g_Ex
14b908a7d09c68a87840b9c8984f61ca:SYC{

Session..........: hashcat
Status...........: Exhausted
Hash.Mode........: 0 (MD5)
Hash.Target......: a.txt
Time.Started.....: Thu Nov 07 11:54:56 2024 (0 secs)
Time.Estimated...: Thu Nov 07 11:54:56 2024 (0 secs)
Kernel.Feature...: Pure Kernel
Guess.Mask.......: ?a?a?a?a [4]
Guess.Queue......: 1/1 (100.00%)
Speed.#1.........:  3012.1 MH/s (1.54ms) @ Accel:128 Loops:95 Thr:256 Vec:1
Recovered........: 10/11 (90.91%) Digests (total), 10/11 (90.91%) Digests (new)
Progress.........: 81450625/81450625 (100.00%)
Rejected.........: 0/81450625 (0.00%)
Restore.Point....: 857375/857375 (100.00%)
Restore.Sub.#1...: Salt:0 Amplifier:0-95 Iteration:0-95
Candidate.Engine.: Device Generator
Candidates.#1....: sOV} ->   ~}
Hardware.Mon.#1..: Temp: 51c Util: 50% Core:2655MHz Mem:8000MHz Bus:8

```

解密出十一组字符串，按顺序进行拼接即可得到Flag

```
14b908a7d09c68a87840b9c8984f61ca:SYC{
2ca599b2fe6161e62ab94afa5172e06d:W0w!
72a23ece2adc1a4aa194eefc5b34064c:y0u_
30e0e84737fa51539b381802fe2dfbaf:@re_
46eb9e84cfd25a806ca850eac9007b86:th3_
1d34a2f86cd36f37098a558db2ca6dba:BeSt
44d16275afab9eef60b4e673e6025ddf:_bla
e2ed036c5568391e56c6a19c30c739a2:stin
dc90ac6dbfd7f3a8b24fc5b5408e433b:g_Ex
edca31600f569d6a284ffa5a44a6561d:p3rt
```

**SYC{W0w!y0u_@re_th3_BeSt_blasting_Exp3rt!!}**

## Week4

### ez_re

拖入IDA的分析，发现main函数无法直接F5，并且代码段爆红，往下看到经典的一个花指令。

![QQ_1731548663825](https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/ez_re1.png)

直接把call的第一个E8字节改成90

![QQ_1731548727588](https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/ez_re2.png)

然后对剩下多出的数据字节按C分析还原成代码即可完成代码还原，然后选中main函数部分代码按P重构成函数即可F5分析。

得到main函数伪代码如下：

```c++
int __cdecl main(int argc, const char **argv, const char **envp)
{
  size_t v3; // kr00_4
  NTSTATUS v4; // eax
  int v5; // eax
  int v6; // eax
  int v7; // ecx
  char v9; // [esp+0h] [ebp-1FCh]
  char v10; // [esp+0h] [ebp-1FCh]
  _DWORD v11[12]; // [esp+Ch] [ebp-1F0h]
  __m128 v12; // [esp+3Ch] [ebp-1C0h]
  BCRYPT_KEY_HANDLE phKey; // [esp+4Ch] [ebp-1B0h] BYREF
  BCRYPT_ALG_HANDLE phAlgorithm; // [esp+50h] [ebp-1ACh] BYREF
  ULONG pcbResult; // [esp+54h] [ebp-1A8h] BYREF
  UCHAR pbOutput[128]; // [esp+58h] [ebp-1A4h] BYREF
  UCHAR pbInput[128]; // [esp+D8h] [ebp-124h] BYREF
  char Arglist[128]; // [esp+158h] [ebp-A4h] BYREF
  UCHAR pbSecret[16]; // [esp+1D8h] [ebp-24h] BYREF
  UCHAR pbIV[16]; // [esp+1E8h] [ebp-14h] BYREF

  if ( IsDebuggerPresent() )
    exit(1);
  phAlgorithm = 0;
  phKey = 0;
  BCryptOpenAlgorithmProvider(&phAlgorithm, L"AES", 0, 0);
  BCryptSetProperty(phAlgorithm, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", 0x20u, 0);
  sub_401090(pbSecret);
  BCryptGenerateSymmetricKey(phAlgorithm, &phKey, 0, 0, pbSecret, 0x10u, 0);
  *(_DWORD *)pbIV = -1809944383;
  *(_DWORD *)&pbIV[4] = 20005620;
  *(_DWORD *)&pbIV[8] = 1426735024;
  *(_DWORD *)&pbIV[12] = -744882271;
  v12.m128_u64[0] = 0xFEF76ECE6FA34BA2uLL;
  v12.m128_u64[1] = 0x67735D6CF76837ECLL;
  v11[0] = 1967972573;
  v11[1] = -1206635625;
  *(__m128 *)pbIV = _mm_xor_ps(v12, *(__m128 *)pbIV);
  v11[2] = 286897687;
  v11[3] = 593529441;
  v11[4] = 451024454;
  v11[5] = 643548005;
  v11[6] = 816706920;
  v11[7] = -968102223;
  v11[8] = -1147226709;
  v11[9] = -1035299469;
  v11[10] = -1446252680;
  v11[11] = -1595838018;
  sub_401020("please input your flag:", v9);
  sub_401050("%s", (char)Arglist);
  memset(pbInput, 0, sizeof(pbInput));
  v3 = strlen(Arglist);
  memcpy(pbInput, Arglist, v3);
  pcbResult = 0;
  v4 = BCryptEncrypt(phKey, pbInput, v3, 0, pbIV, 0x10u, pbOutput, 0x80u, &pcbResult, 1u);
  if ( v4 )
  {
    v5 = sub_4014E0(v4, sub_4016F0);
    v6 = std::ostream::operator<<(v5);
    std::ostream::operator<<(v6);
  }
  else
  {
    v7 = 0;
    while ( pbOutput[v7] == *((_BYTE *)v11 + v7) )
    {
      if ( (unsigned int)++v7 >= 0x30 )
      {
        sub_401020("you are right\n", v10);
        goto LABEL_10;
      }
    }
    sub_401020("not equal\n", v10);
  }
LABEL_10:
  BCryptDestroyKey(phKey);
  BCryptCloseAlgorithmProvider(phAlgorithm, 0);
  system("pause");
  return 0;
}
```

可以看到是用BCrypt库进行的AES加密代码，密钥是用pbSecret进行初始化，pbSecret是从sub_401090取出，但是发现sub_401090也是插入了花指令。

![QQ_1731549192101](https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/ez_re3.png)

首先还是将这个E8改成90，然后按C分析剩下字节为代码，最后将一下矩形框起来部分代码全部Nop然后全选函数按P重构为函数即可还原代码。

得到sub_401090伪代码：

```c++
int __cdecl sub_401090(int a1)
{
  int result; // eax
  _BYTE v2[15]; // [esp+Ch] [ebp-24h]
  _BYTE v3[17]; // [esp+1Bh] [ebp-15h] BYREF
  int i; // [esp+2Ch] [ebp-4h]

  v3[4] = -96;
  v3[5] = 62;
  v3[6] = 111;
  v3[7] = 38;
  v3[8] = -110;
  v3[9] = -44;
  v3[10] = 112;
  v3[11] = -100;
  v3[12] = -87;
  v3[13] = 13;
  v3[14] = 16;
  v3[15] = 37;
  v3[16] = -127;
  v2[0] = -126;
  v2[1] = -101;
  v2[2] = -75;
  v2[3] = -88;
  v2[4] = 19;
  v2[5] = -74;
  v2[6] = 107;
  v2[7] = 88;
  v2[8] = 110;
  v2[9] = -91;
  v2[10] = 75;
  v2[11] = -1;
  v2[12] = 52;
  v2[13] = -6;
  v2[14] = -20;
  qmemcpy(v3, "[/Fn", 4);
  for ( i = 0; i < 16; ++i )
  {
    *(_BYTE *)(i + a1) = v2[i] ^ v3[i + 1];
    result = i + 1;
  }
  return result;
}
```

可以看到是用一堆数据进行计算得到的pbSecret，直接将代码复制到c++项目运行即可得到pbSecret字节。

>0xAD, 0xDD, 0xDB, 0x08, 0x2D, 0xD9, 0x4D, 0xCA, 0xBA, 0xD5, 0xD7, 0x56, 0x39, 0xEA, 0xC9, 0xDA

从main函数伪代码可以分析出，IV是已经给出，然后密文Flag是v11的数据，所以直接用BCrypt库配合拿到的pbSecret、IV和密文数据即可解密出Flag。

解密代码：

```c++
#include <iostream>
#include <Windows.h>
#include <bcrypt.h>
#pragma comment(lib,"Bcrypt.lib")

int main_ezRe()
{
    UCHAR pbSecret[16]
    { 0xAD, 0xDD, 0xDB, 0x08, 0x2D, 0xD9, 0x4D, 0xCA, 0xBA, 0xD5, 0xD7, 0x56, 0x39, 0xEA, 0xC9, 0xDA };
    UCHAR pbIV[16]
    { 0x63 , 0x3B , 0xBD , 0xFB , 0x3A , 0x2C , 0xC6 , 0xFF , 0x5C , 0x08 , 0x62 , 0xA2 , 0xCD , 0xA2 , 0xEA , 0xB4};

    DWORD EncodeData[12]{};
    EncodeData[0] = 1967972573;
    EncodeData[1] = -1206635625;
    EncodeData[2] = 286897687;
    EncodeData[3] = 593529441;
    EncodeData[4] = 451024454;
    EncodeData[5] = 643548005;
    EncodeData[6] = 816706920;
    EncodeData[7] = -968102223;
    EncodeData[8] = -1147226709;
    EncodeData[9] = -1035299469;
    EncodeData[10] = -1446252680;
    EncodeData[11] = -1595838018;
   
    BCRYPT_KEY_HANDLE phKey;
    BCRYPT_ALG_HANDLE phAlgorithm;
    ULONG pcbResult;
    UCHAR pbOutput[128];
    UCHAR pbInput[128];

    BCryptOpenAlgorithmProvider(&phAlgorithm, L"AES", NULL, NULL);
    BCryptSetProperty(phAlgorithm, L"ChainingMode", (PUCHAR)L"ChainingModeCBC", 0x20u, 0);
    BCryptGenerateSymmetricKey(phAlgorithm, &phKey, 0, 0, pbSecret, 0x10u, 0);

    BCryptDecrypt(phKey, (PUCHAR)(EncodeData), 48, 0, pbIV, 0x10u, pbOutput, 0x80u, &pcbResult, 1u);
    
    std::cout << pbOutput << std::endl;

    BCryptDestroyKey(phKey);
    BCryptCloseAlgorithmProvider(phAlgorithm, 0);

    // SYC{W0w_Y0U_fOUNdDD_TLS_AND_AeS}

	return 0;
}
```

### ez_raw

这是一题硬盘取证+逆向综合题，下载拿到.raw文件，直接用volatility3进行分析，扫描硬盘文件。

扫描命令:

>python .\vol.py -f ..\Forensics.raw windows.filescan

扫描得到所有的文件夹和文件，尝试搜索关键字符串，如"flag" "Key" "Secret"等等。

发现直接搜flag就有文件，会搜到一个flag.kdbx，是一个密码管理器的文件格式，并且他的上一个文件是program.elf，应该就是需要逆向的目标程序。

>0xc16a2d80      \Users\win10\program.elf
>0xc16a2e58      \Users\win10\flag.kdbx

得到两个文件的虚拟地址后，用windows.dumpfiles来dump出文件。

dump命令:

> python .\vol.py -o .\Out -f ..\Forensics.raw windows.dumpfiles --virtaddr 0xc16a2d80
>
> python .\vol.py -o .\Out -f ..\Forensics.raw windows.dumpfiles --virtaddr 0xc16a2e58

![QQ_1731550277522](https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/ez_raw1.png)

得到两个文件，然后改后缀名即可。

直接用KeePass2打开flag.kdbx文件，发现里面是有Notes的。

![QQ_1731550402527](https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/ez_raw2.png)

然后在History中发现有两次历史版本。

![QQ_1731550432878](https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/ez_raw3.png)

15:47:04那个版本里面存放的是假Flag，15:46:34版本里面存放着一个18长度密钥，先存起来，目前不知道用处。

![QQ_1731550478610](https://github.com/TKazer/Geek-Challenge-2024-Reverse-WP/blob/main/Pic/ez_raw4.png)

接下来是逆向分析，将program.elf直接拖入IDA分析。

main函数伪代码：

```C++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rbx
  const char *v4; // rbp

  if ( argc <= 1 )
  {
    printf("Usage: %s <key>\n", *argv);
  }
  else
  {
    v3 = argv[1];
    v4 = argv[2];
    if ( strlen(v3) == 18 )
    {
      sub_11D0(v4, v3);
      if ( !memcmp(v4, &unk_4040, 0x20uLL) )
        printf("right");
    }
  }
  return 0;
}
```

发现main函数很简单清晰，就是输入一个Key，一个密文，然后用sub_11D0进行加密，与unk_4040的密文进行对比。

发现他加密前有个初步的判断，strlen(v3) == 18，判断密钥是否为18长度，而我们刚刚在.kdbx文件中拿到的一个uoi也是18长度，初步可以猜测那个即为密钥，所以接下来主要分析sub_11D0的加密流程。

sub_11D0:

```c++
__int64 __fastcall sub_11D0(__m128i *a1, __int64 a2)
{
  __m128i v2; // xmm1
  __int64 result; // rax
  __m128i v4; // xmm0
  __m128i v5; // xmm0
  __m128i v6; // xmm0

  v2 = _mm_loadu_si128(a1);
  result = 0LL;
  v4 = _mm_add_epi8(_mm_add_epi8(v2, v2), v2);
  v5 = _mm_add_epi8(v4, v4);
  v6 = _mm_add_epi8(v5, v5);
  *a1 = _mm_sub_epi8(_mm_add_epi8(v6, v6), v2);
  do
  {
    a1->m128i_i8[result] ^= *(_BYTE *)(a2 + (unsigned int)result % 0x12) ^ 0x33;
    ++result;
  }
  while ( result != 32 );
  return result;
}
```

发现加密流程也不复杂，就是将明文转成__m128i结构进行了一系列字节上的计算。

总流程如下：

m128i_Data = load(明文)

r = m128i_Data + m128i_Data + m128i_Data // 3倍

r = r + r	// 6倍

r = r + r	// 12倍

r = (r + r) - m128i_Data // 23倍

所以综上，一系列计算，就是为了将字节在有限域内进行*23。

但是__m128i是16字节大小的结构体，而我们输入的明文在memcmp处可以看到应该是32字节长度，所以只有明文前半部分进行了字节的翻倍计算。

然后循环部分就是将翻倍后的明文字节异或上密钥再异或0x33。

所以最终解密流程如下：

密文 ^= 密钥[ i % 18] ^ 0x33 得到翻倍后的前半密文，而后半密文解密完毕

最后在0-256范围内进行翻23倍计算，遍历到对应的明文字节，解密出前半密文，拼接得到Flag。

解密代码如下：

```c++
int main()
{
    std::vector<unsigned char> EncodeData =
    {
      0x24, 0xA5, 0x58, 0x59, 0x0B, 0x45, 0xEC, 0x94, 0x7A, 0xA6,
      0xCE, 0x11, 0x10, 0x65, 0x8E, 0xA6, 0x6C, 0x31, 0x23, 0x05,
      0x3E, 0x64, 0x3A, 0x26, 0x6E, 0x26, 0x25, 0x2E, 0x76, 0x34,
      0x2E, 0x26
    };

    std::string Key = "lsxqpoxqgsdrcr4n0g";
   
    // 第一步解密，后半部分直接解密出明文
    std::vector<int> Decode_Step1;
    for (int i = 0; i < 32; i++)
        Decode_Step1.push_back(EncodeData[i] ^ 0x33 ^ Key[i % 18]);

    // 解密前半部分，遍历符合条件的字节
    std::vector<int> FrontHalf;
    for (int i = 0; i < 16; i++)
    {
        for (int x = 0; x < 256; x++)
        {
            if ((x * 23) % 256 == Decode_Step1[i])
            {
                FrontHalf.push_back(x);
                break;
            }
        }
    }
    
    for (auto c : FrontHalf)
        std::cout << (BYTE)c;
    
    for (int i = 16; i < 32; i++)
        std::cout << (BYTE)Decode_Step1[i];
    
    return 0;

}
```

发现以上代码没办法正常解密，而解密代码和加密代码对应的没问题，考虑是不是密钥出现了问题，一般题目密钥不会是乱七八糟，而可能是一串可读的文本，密钥中只有字母和数字，考虑尝试凯撒解密。

用在线平台进行凯撒解密枚举，得到以下密钥：

```c++
lsxqpoxqgsdrcr4n0g
krwponwpfrcqbq4m0f
jqvonmvoeqbpap4l0e
ipunmlundpaozo4k0d
hotmlktmcoznyn4j0c
gnslkjslbnymxm4i0b
fmrkjirkamxlwl4h0a
elqjihqjzlwkvk4g0z
dkpihgpiykvjuj4f0y
cjohgfohxjuiti4e0x
bingfengwithsh4d0w // <-
ahmfedmfvhsgrg4c0v
zgledcleugrfqf4b0u
yfkdcbkdtfqepe4a0t
xejcbajcsepdod4z0s
wdibazibrdocnc4y0r
vchazyhaqcnbmb4x0q
ubgzyxgzpbmala4w0p
tafyxwfyoalzkz4v0o
szexwvexnzkyjy4u0n
rydwvudwmyjxix4t0m
qxcvutcvlxiwhw4s0l
pwbutsbukwhvgv4r0k
ovatsratjvgufu4q0j
nuzsrqzsiuftet4p0i
mtyrqpyrhtesds4o0h
```

发现箭头处很明显是可读字符串 "bingfengwithsh4d0w"。

所以用这个密钥进行解密，即可解密出Flag。

```c++
int main()
{
    std::vector<unsigned char> EncodeData =
    {
      0x24, 0xA5, 0x58, 0x59, 0x0B, 0x45, 0xEC, 0x94, 0x7A, 0xA6,
      0xCE, 0x11, 0x10, 0x65, 0x8E, 0xA6, 0x6C, 0x31, 0x23, 0x05,
      0x3E, 0x64, 0x3A, 0x26, 0x6E, 0x26, 0x25, 0x2E, 0x76, 0x34,
      0x2E, 0x26
    };

    std::string Key = "bingfengwithsh4d0w";
   
    // 第一步解密，后半部分直接解密出明文
    std::vector<int> Decode_Step1;
    for (int i = 0; i < 32; i++)
        Decode_Step1.push_back(EncodeData[i] ^ 0x33 ^ Key[i % 18]);

    // 解密前半部分，遍历符合条件的字节
    std::vector<int> FrontHalf;
    for (int i = 0; i < 16; i++)
    {
        for (int x = 0; x < 256; x++)
        {
            if ((x * 23) % 256 == Decode_Step1[i])
            {
                FrontHalf.push_back(x);
                break;
            }
        }
    }
    
    for (auto c : FrontHalf)
        std::cout << (BYTE)c;
    
    for (int i = 16; i < 32; i++)
        std::cout << (BYTE)Decode_Step1[i];
    
    // SYC{Rew@rd_F0r_7our_c0op3rat1on}
  
    return 0;

}
```

### 贝斯_贝斯_

拖入IDA分析代码，得到main函数伪代码

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *v3; // rax
  int v4; // eax
  int v5; // eax
  int v6; // eax
  int v7; // eax
  int v8; // eax
  int v9; // eax
  int v10; // eax
  char v11; // al
  int v12; // edx
  char v13; // al
  int v14; // edx
  _BYTE v16[32]; // [rsp+20h] [rbp-60h]
  char Str2[52]; // [rsp+40h] [rbp-40h] BYREF
  char Str[12]; // [rsp+74h] [rbp-Ch] BYREF
  char Buffer[32]; // [rsp+80h] [rbp+0h] BYREF
  char v20[144]; // [rsp+A0h] [rbp+20h] BYREF
  char *Str1; // [rsp+130h] [rbp+B0h]
  unsigned int v22; // [rsp+138h] [rbp+B8h]
  int v23; // [rsp+13Ch] [rbp+BCh]
  int v24; // [rsp+140h] [rbp+C0h]
  int v25; // [rsp+144h] [rbp+C4h]
  const char *v26; // [rsp+148h] [rbp+C8h]
  _BYTE *v27; // [rsp+150h] [rbp+D0h]
  int v28; // [rsp+158h] [rbp+D8h]
  int v29; // [rsp+15Ch] [rbp+DCh]
  char *v30; // [rsp+160h] [rbp+E0h]
  void *Block; // [rsp+168h] [rbp+E8h]
  unsigned int v32; // [rsp+174h] [rbp+F4h]
  int i; // [rsp+178h] [rbp+F8h]
  int v34; // [rsp+17Ch] [rbp+FCh]

  sub_4022F0(argc, argv, envp);
  strcpy(Buffer, "Welcome to the last week");
  puts(Buffer);
  printf("please input flag: ");
  v3 = (FILE *)off_404080();
  fgets(v20, 24, v3);
  strcpy(Str, "happy_happy");
  v32 = strlen(Str);
  qmemcpy(Str2, "RjB6Myu#,>Bgoq&u.H(nBgdIaOKJbgEYj1GR4S.w", 40);
  Block = (void *)sub_401723(v20);
  v30 = Buffer;
  v29 = strlen(Buffer);
  v28 = 0;
  v27 = malloc(2 * v29 + 1);
  v34 = 0;
  v26 = "0123456789ABCDEF";
  // ---------------------标记处开头---------------------
  while ( v34 < v29 )
  {
    v4 = v34++;
    v25 = (unsigned __int8)v30[v4];
    if ( v34 >= v29 )
    {
      v6 = 0;
    }
    else
    {
      v5 = v34++;
      v6 = (unsigned __int8)v30[v5];
    }
    v24 = v6;
    if ( v34 >= v29 )
    {
      v8 = 0;
    }
    else
    {
      v7 = v34++;
      v8 = (unsigned __int8)v30[v7];
    }
    v23 = v8;
    v22 = v8 | (v25 << 16) | (v24 << 8);
    v9 = v34++;
    v27[v9] = off_404010[(v22 >> 18) & 0x3F];
    v10 = v34++;
    v27[v10] = off_404010[(v22 >> 12) & 0x3F];
    if ( v34 > v29 + 1 )
      v11 = 61;
    else
      v11 = off_404010[(v22 >> 6) & 0x3F];
    v12 = v34++;
    v27[v12] = v11;
    if ( v34 > v29 )
      v13 = 61;
    else
      v13 = off_404010[v22 & 0x3F];
    v14 = v34++;
    v27[v14] = v13;
  }
  for ( i = 0; i <= 23; ++i )
  {
    v16[i] = v30[i];
    if ( v30[i] == 99 )
      v16[i] ^= v30[i + 1];
  }
  // ---------------------标记处结尾---------------------
  Str1 = (char *)sub_401C6A(Block, Str, v32);
  if ( !strcmp(Str1, Str2) )
    puts("it's correct!");
  else
    puts("maybe wrong!");
  free(Block);
  free(Str1);
  return 0;
}
```

可以通过上下文分析出标记段的代码部分是没有用到的，可以直接忽略，所以主要分析的函数就是sub_401723和sub_401C6A

sub_401723:

```c++
_BYTE *__fastcall sub_401723(const char *a1)
{
  int v1; // ecx
  int v2; // eax
  _BYTE v4[72]; // [rsp+20h] [rbp-60h] BYREF
  _BYTE *v5; // [rsp+68h] [rbp-18h]
  void *Block; // [rsp+70h] [rbp-10h]
  int v7; // [rsp+7Ch] [rbp-4h]
  int v8; // [rsp+80h] [rbp+0h]
  int v9; // [rsp+84h] [rbp+4h]
  int v10; // [rsp+88h] [rbp+8h]
  int i; // [rsp+8Ch] [rbp+Ch]

  v7 = 138 * strlen(a1) / 0x64 + 1;
  Block = malloc(v7);
  v5 = malloc(v7);
  v10 = 0;
  sub_401550(v4);
  memset(Block, 0, v7);
  while ( v10 < strlen(a1) )
  {
    v9 = a1[v10];
    for ( i = v7 - 1; ; --i )
    {
      v9 += *((char *)Block + i) << 8;
      *((_BYTE *)Block + i) = (char)v9 % 58;
      v9 /= 58;
      if ( !v9 )
        break;
    }
    ++v10;
  }
  for ( i = 0; !*((_BYTE *)Block + i) && i < v7; ++i )
    ;
  v8 = 0;
  while ( i < v7 )
  {
    v1 = *((char *)Block + i);
    v2 = v8++;
    v5[v2] = v4[v1];
    ++i;
  }
  v5[v8] = 0;
  free(Block);
  return v5;
}
```

这部分代码似乎是一个自定义映射表的base58编码，用sub_401550拿到一个映射表，通过映射表将输入的字符串进行编码操作。

sub_401550:

```c++
__int64 __fastcall sub_401550(__int64 a1)
{
  __int64 result; // rax
  tm Tm; // [rsp+20h] [rbp-60h] BYREF
  time_t Time; // [rsp+48h] [rbp-38h] BYREF
  _DWORD v4[60]; // [rsp+50h] [rbp-30h] BYREF
  char Str[68]; // [rsp+140h] [rbp+C0h] BYREF
  int v6; // [rsp+184h] [rbp+104h]
  unsigned int Seed[2]; // [rsp+188h] [rbp+108h]
  struct tm *v8; // [rsp+190h] [rbp+110h]
  int v9; // [rsp+198h] [rbp+118h]
  int i; // [rsp+19Ch] [rbp+11Ch]

  strcpy(Str, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
  v9 = strlen(Str);
  memset(v4, 0, 0xE8uLL);
  Time = time64(0LL);
  v8 = localtime(&Time);
  memset(&Tm, 0, sizeof(Tm));
  Tm.tm_year = v8->tm_year;
  Tm.tm_mon = v8->tm_mon;
  Tm.tm_mday = v8->tm_mday;
  *(_QWORD *)Seed = mktime(&Tm);
  srand(Seed[0]);
  for ( i = 0; i <= 57; ++i )
  {
    do
      v6 = rand() % v9;
    while ( v4[v6] );
    *(_BYTE *)(i + a1) = Str[v6];
    v4[v6] = 1;
  }
  result = a1 + 58;
  *(_BYTE *)(a1 + 58) = 0;
  return result;
}
```

sub_401550初始化映射表是取出当前时间戳，然后用Seed[0]当作种子通过rand处理原始映射表，拿到一个随机的映射表，这里涉及到随机种子的问题，由于只传入了year、mon、day，年月日三个数据，所以种子只和年月日有关，这个映射表的年月日数据之后解密可以通过遍历来找到对应的年月日。

所以sub_401723解密只需要拿到自定义的映射表进行Base58解密即可。

sub_401C6A传入了Base58编码后的明文、Str、Str长度，Str "happy_happy" 大概率是作为一个密钥参与计算。

sub_401C6A：

```c++
_BYTE *__fastcall sub_401C6A(const char *a1, __int64 a2, unsigned int a3)
{
  int v3; // eax
  int v4; // eax
  _BYTE v6[88]; // [rsp+20h] [rbp-80h] BYREF
  _BYTE *v7; // [rsp+78h] [rbp-28h]
  int v8; // [rsp+84h] [rbp-1Ch]
  int v9; // [rsp+88h] [rbp-18h]
  int j; // [rsp+8Ch] [rbp-14h]
  int i; // [rsp+90h] [rbp-10h]
  int v12; // [rsp+94h] [rbp-Ch]
  int v13; // [rsp+98h] [rbp-8h]
  unsigned int v14; // [rsp+9Ch] [rbp-4h]

  v9 = strlen(a1);
  if ( (v9 & 3) != 0 )
    v3 = v9 + 4 - v9 % 4;
  else
    v3 = v9;
  v8 = v3;
  v7 = malloc(5 * (v3 / 4) + 1);
  v13 = 0;
  v12 = 0;
  sub_401AF6(v6, a2, a3);
  while ( v13 < v9 )
  {
    v14 = 0;
    for ( i = 0; i <= 3; ++i )
    {
      v14 <<= 8;
      if ( v13 < v9 )
      {
        v4 = v13++;
        v14 |= (unsigned __int8)a1[v4];
      }
    }
    for ( j = 4; j >= 0; --j )
    {
      v7[v12 + j] = v6[v14 % 0x55];
      v14 /= 0x55u;
    }
    v12 += 5;
  }
  v7[v12] = 0;
  return v7;
}
```

这个函数是进行了Base85编码，通过传入密钥调用sub_401AF6初始化映射表，由于没有特殊数据调用，直接将sub_401AF6伪代码以及里面调用的函数的伪代码全都复制到c++项目，传入密钥即可得到映射表。

解密总流程：

1. 通过密钥拿到映射表1，用映射表1对密文进行Base85解密

2. 通过年月日拿到时间戳进行初始化映射表2，用映射表2对Base85解密完的数据进行Base58解密。

完整解密代码如下：

```c++
char aAbcdefghijklmn[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!#$%&()*+,-./:;<=>?@[]^_`{|}~";

BYTE random_Chars[72]{};

BYTE KeyList[88]{};

unsigned __int64 __fastcall sub_4018FF(__int64 a1, __int64 a2, int a3)
{
    unsigned __int64 result; // rax
    unsigned __int8 v4; // [rsp+7h] [rbp-9h]
    int v5; // [rsp+8h] [rbp-8h]
    int i; // [rsp+Ch] [rbp-4h]
    int j; // [rsp+Ch] [rbp-4h]

    v5 = 0;
    for (i = 0; i <= 255; ++i)
    {
        result = a1 + i;
        *(BYTE*)result = i;
    }
    for (j = 0; j <= 255; ++j)
    {
        v5 = (*(unsigned __int8*)(a1 + j) + v5 + *(unsigned __int8*)(a2 + j % a3)) % 256;
        v4 = *(BYTE*)(a1 + j);
        *(BYTE*)(a1 + j) = *(BYTE*)(a1 + v5);
        result = v4;
        *(BYTE*)(v5 + a1) = v4;
    }
    return result;
}

__int64 __fastcall sub_4019EE(__int64 a1, __int64 a2, int a3)
{
    __int64 result; // rax
    char v4; // [rsp+3h] [rbp-Dh]
    unsigned int i; // [rsp+4h] [rbp-Ch]
    int v6; // [rsp+8h] [rbp-8h]
    int v7; // [rsp+Ch] [rbp-4h]

    v7 = 0;
    v6 = 0;
    for (i = 0; ; ++i)
    {
        result = i;
        if ((int)i >= a3)
            break;
        v7 = (v7 + 1) % 256;
        v6 = (*(unsigned __int8*)(a1 + v7) + v6) % 256;
        v4 = *(BYTE*)(a1 + v7);
        *(BYTE*)(a1 + v7) = *(BYTE*)(a1 + v6);
        *(BYTE*)(v6 + a1) = v4;
        *(BYTE*)(a2 + (int)i) = *(BYTE*)(a1 + (unsigned __int8)(*(BYTE*)(a1 + v7) + *(BYTE*)(a1 + v6)));
    }
    return result;
}

__int64 __fastcall sub_401AF6(__int64 a1, __int64 a2, unsigned int a3)
{
    unsigned int v3; // ecx
    __int64 result; // rax
    DWORD v5[88]; // [rsp+20h] [rbp-60h] BYREF
    BYTE v6[96]; // [rsp+180h] [rbp+100h] BYREF
    BYTE v7[264]; // [rsp+1E0h] [rbp+160h] BYREF
    unsigned int j; // [rsp+2E8h] [rbp+268h]
    int i; // [rsp+2ECh] [rbp+26Ch]

    sub_4018FF((long long)v7, a2, a3);
    sub_4019EE((long long)v7, (long long)v6, 85LL);
    memset(v5, 0, 340);
    for (i = 0; i <= 84; ++i)
    {
        for (j = v6[i] % 0x55u; v5[j]; j = v3 - 85 * j)
        {
            v3 = j + 1;
            j = (int)(j + 1) / 85;
        }
        *(BYTE*)(i + a1) = aAbcdefghijklmn[j];
        v5[j] = 1;
    }
    result = a1 + 85;
    *(BYTE*)(a1 + 85) = 0;
    return result;
}

void Base85Decode(const char* Encoded, char* Output, int OriginalLength) 
{
    int ReverseMapping[256];

    for (int idx = 0; idx < 88; ++idx) 
    {
        ReverseMapping[KeyList[idx]] = idx;
    }

    int EncodedLength = strlen(Encoded);
    int OutputIndex = 0;

    for (int EncodedIndex = 0; EncodedIndex < EncodedLength; EncodedIndex += 5) 
    {
        unsigned int v14 = 0;

        for (int j = 0; j < 5; ++j) 
        {
            v14 = v14 * 85 + ReverseMapping[(unsigned char)Encoded[EncodedIndex + j]];
        }

        for (int i = 3; i >= 0; --i) 
        {
            if (OutputIndex < OriginalLength)
            { 
                Output[OutputIndex + i] = (v14 & 0xFF);
                v14 >>= 8;
            }
        }

        OutputIndex += 4;
    }

    Output[OriginalLength] = '\0';
}

__int64 __fastcall sub_401550(__int64 a1, int month, int day)
{
    __int64 result; // rax
    tm Tm; // [rsp+20h] [rbp-60h] BYREF
    time_t Time; // [rsp+48h] [rbp-38h] BYREF
    DWORD v4[60]; // [rsp+50h] [rbp-30h] BYREF
    char Str[68]; // [rsp+140h] [rbp+C0h] BYREF
    int v6; // [rsp+184h] [rbp+104h]
    unsigned int Seed[2]; // [rsp+188h] [rbp+108h]
    struct tm* v8; // [rsp+190h] [rbp+110h]
    int v9; // [rsp+198h] [rbp+118h]
    int i; // [rsp+19Ch] [rbp+11Ch]

    strcpy(Str, "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz");
    v9 = strlen(Str);
    memset(v4, 0, 0xE8uLL);
    Time = _time64(0LL);
    v8 = localtime(&Time);
    memset(&Tm, 0, sizeof(Tm));
    Tm.tm_year = v8->tm_year;
    Tm.tm_mon = month-1;
    Tm.tm_mday = day;
    *(DWORD64*)Seed = mktime(&Tm);
    srand(Seed[0]);
    for (i = 0; i <= 57; ++i)
    {
        do
            v6 = rand() % v9;
        while (v4[v6]);
        *(BYTE*)(i + a1) = Str[v6];
        v4[v6] = 1;
    }
    result = a1 + 58;
    *(BYTE*)(a1 + 58) = 0;
    return result;
}

std::string Base58Decode(const unsigned char* Block, int blockSize)
{
    std::string result;
    std::vector<unsigned char> temp(blockSize);

    for (int i = 0; i < blockSize; i++) 
    {
        temp[i] = Block[i];
    }

    while (true) 
    {
        bool allZero = true;
        unsigned int remainder = 0;

        for (int i = 0; i < blockSize; i++)
        {
            unsigned int current = remainder * 58 + temp[i];
            temp[i] = current / 256;
            remainder = current % 256;

            if (temp[i] != 0) 
                allZero = false;
        }

        result = (char)remainder + result;

        if (allZero) 
            break;
    }

    return result;
}

int main()
{
    char LastEncodedData[] = "RjB6Myu#,>Bgoq&u.H(nBgdIaOKJbgEYj1GR4S.w";

    // 获取映射表1
    char Key[] = "happy_happy";
    sub_401AF6((long long)KeyList, (long long)Key, strlen(Key));

    // Base85解密
    char DecodeData[33]{};
    Base85Decode(LastEncodedData, DecodeData, 33);

    // 遍历月、日，默认年是2024
    for (int month = 1; month <= 12; month++)
    {
        for (int day = 1; day <= 31; day++)
        {
            // 通过月、日数据初始化时间戳获取随机字符映射表
            sub_401550((long long)random_Chars, month, day);

            char Block_Temp[33]{};

            // 通过映射表反向映射拿到原始数据
            for (int i = 0; i < 32; i++)
            {
                for (int j = 0; j < 58; j++)
                {
                    if (random_Chars[j] == DecodeData[i])
                        Block_Temp[i] = j;
                }
            }

            // Base58解密
            auto Flag = Base58Decode((const unsigned char*)Block_Temp, 32);
		   // 寻找关键Flag字符串
            if (Flag.find("SYC{") != std::string::npos)
                std::cout << Flag << std::endl;
        }
    }

    // SYC{th1s_ls_an_ez_base}

	return 0;
}
```

### baby_vm

萌新也是第一次做vm题，弯弯绕绕才勉强做出来。

拖入IDA拿到以下伪代码。

```c++
int __fastcall main(int argc, const char **argv, const char **envp)
{
  sub_7FF678E719DE();
  Block = malloc(0x10uLL);
  memset(Block, 0, 0x10uLL);
  sub_7FF678E713B4((__int64)&unk_7FF678E77040, (char *)Block);
  free(Block);
  return 0;
}

__int64 __fastcall sub_7FF678E713B4(__int64 a1, char *Registers)
{
  unsigned __int8 v2; // r8
  int v3; // eax
  int v4; // edx
  FILE *STDIN; // rax
  int v7; // [rsp+2Ch] [rbp-4h]

  while ( 2 )
  {
    v7 = *(_DWORD *)(4LL * *((int *)Registers + 2) + a1);
    if ( v7 <= 70 )
    {
      if ( v7 >= 51 )
      {
        switch ( v7 )
        {
          case '3':
            *Registers += Registers[3];
            ++*((_DWORD *)Registers + 2);
            continue;
          case '4':
            *Registers -= Registers[3];
            ++*((_DWORD *)Registers + 2);
            continue;
          case '5':
            *Registers *= Registers[3];
            ++*((_DWORD *)Registers + 2);
            continue;
          case '6':
            *Registers = (unsigned __int8)*Registers / (unsigned __int8)Registers[3];
            ++*((_DWORD *)Registers + 2);
            continue;
          case '7':
            *Registers = ~(*Registers & Registers[3]) & ~(~Registers[3] & ~*Registers);
            ++*((_DWORD *)Registers + 2);
            continue;
          case '8':
            v2 = *Registers;
            v3 = *((_DWORD *)Registers + 3);
            *((_DWORD *)Registers + 3) = v3 + 1;
            dword_7FF678E7B0A0[v3] = v2;
            ++*((_DWORD *)Registers + 2);
            continue;
          case '9':
            *Registers = dword_7FF678E7B0A0[--*((_DWORD *)Registers + 3)];
            ++*((_DWORD *)Registers + 2);
            continue;
          case ':':
            *Registers = Str[(unsigned __int8)Registers[1]];
            ++*((_DWORD *)Registers + 2);
            continue;
          case ';':
            *Registers = Registers[3];
            ++*((_DWORD *)Registers + 2);
            continue;
          case '<':
            Registers[1] = *Registers;
            ++*((_DWORD *)Registers + 2);
            continue;
          case '=':
            Registers[2] = *Registers;
            ++*((_DWORD *)Registers + 2);
            continue;
          case '>':
            Registers[3] = *Registers;
            ++*((_DWORD *)Registers + 2);
            continue;
          case '?':
            *Registers = *(_DWORD *)(4 * (*((int *)Registers + 2) + 1LL) + a1);
            *((_DWORD *)Registers + 2) += 2;
            continue;
          case '@':
            *Registers = Registers[1];
            ++*((_DWORD *)Registers + 2);
            continue;
          case 'A':
            *Registers = EncodeData[(unsigned __int8)Registers[1]];
            ++*((_DWORD *)Registers + 2);
            continue;
          case 'B':
            ++*Registers;
            ++*((_DWORD *)Registers + 2);
            continue;
          case 'C':
            if ( --Registers[2] )
              v4 = *((_DWORD *)Registers + 2) - *(_DWORD *)(4 * (*((int *)Registers + 2) + 1LL) + a1);
            else
              v4 = *((_DWORD *)Registers + 2) + 2;
            *((_DWORD *)Registers + 2) = v4;
            continue;
          case 'D':
            if ( *Registers != Registers[3] )
              Registers[4] = 1;
            --Registers[1];
            ++*((_DWORD *)Registers + 2);
            continue;
          case 'E':
            *Registers = *(_DWORD *)(4 * (*((int *)Registers + 2) + 1LL) + a1);
            *((_DWORD *)Registers + 2) += 2;
            continue;
          case 'F':
            STDIN = (FILE *)off_7FF678E77290();
            fgets(Str, 51, STDIN);
            Str[strcspn(Str, "\n")] = 0;
            ++*((_DWORD *)Registers + 2);
            continue;
          default:
            return sub_7FF678E71360("Unknown opcode: %d\n", v7);
        }
      }
      return sub_7FF678E71360("Unknown opcode: %d\n", v7);
    }
    break;
  }
  if ( v7 != 255 )
    return sub_7FF678E71360("Unknown opcode: %d\n", v7);
  if ( Registers[4] )
    return sub_7FF678E71360("something wrong");
  else
    return sub_7FF678E71360("Good!!!");
}
```

传入的Block空间相当于寄存器空间，a1则是要执行的opcode数组。

寄存器Register[2]相当于当前代码执行位置。Register[4]就是条件数值。

逐opcode分析如下：

```
---------数据计算---------
'3'
R[0] += R[3]

'4' 
R[0] -= R[3]

'5' 
R[0] *= R[3]

'6' 
R[0] /= R[3]

'7' 
R[0] ^= R[3]

---------数据存取---------
'8' 
将当前操作数储存到数组里面，
dword_7FF678E7B0A0[R[3]++] = R[0]

'9'
从数组中取出数据到当前操作数
R[0] = dword_7FF678E7B0A0[R[3]--]

':'
从输入的Str中取出指定下标字符数值
R[0] = Str[R[1]]

---------寄存器数据转移---------
';'
R[0] = R[3]

'<'
R[1] = R[0]

'='
R[2] = R[0]

'>'
R[3] = R[0]

'@'
R[0] = R[1]

'?'
取出下一个命令
R[0] = OpCodes[4 * (R[2] + 1)]

'A'
取出加密后的数据
R[0] = EncodeData[Register[1]]

'B'
R[0]++

'C'
取出操作数，代码跳回指定偏移，如果为第一个命令，则不执行，继续往下
if(--R[2])
   R[2] = R[2] - OpCodes[4 * (R[2] + 1)]
else
   R[2] = R[2] + 2

'D'
判断两个数值是否相等，用R[4]储存判断结果
if(R[0] != R[3])
   R[4] = 1
--R[1]

'E'
同命令'?'，取出下一个命令

'F'
要求用户输入字符串，储存到Str数组

```

从函数结尾的Register[4]判断，可以知道要求Register[4]最后必须是0，也就是输入字符串经过加密后要与密文相等。

通过opcode解释，可以将unk_7FF678E77040里面储存的代码和操作数进行翻译。

翻译伪代码如下：

```c++
unsigned char EncodeData[]{
 0x0E, 0x40, 0x7E, 0x1E, 0x13, 0x34, 0x1A, 0x17, 0x6E, 0x1B,
 0x1C, 0x17, 0x2E, 0x0C, 0x1A, 0x30, 0x69, 0x32, 0x26, 0x16,
 0x1A, 0x15, 0x25, 0x0E, 0x1C, 0x42, 0x30, 0x32, 0x0B, 0x42,
 0x79, 0x17, 0x6E, 0x42, 0x29, 0x17, 0x6E, 0x5A, 0x2D, 0x20,
 0x1A, 0x16, 0x26, 0x10, 0x05, 0x15, 0x6E, 0x0D, 0x58, 0x24 };

char Str[52]{};
fgets(Str, 51, STDIN);
Str[strcspn(Str, '\n')] = 0;

char EncodeStr[504]{};

int Register_4 = 0;

for(int i = 0; i < 50; i++)
{
    if(i % 2 == 0)
    {
    	// 偶数下标字符加密
        int Temp = Str[i];
        Temp -= 0x53;
        Temp += 0x59;
        Temp ^= 0x43;
        EncodeStr[i] = Temp;
    }
    else
    {
     	// 奇数下标字符加密
        int Temp = Str[i];
        Temp -= 0x79;
        Temp += 0x73;
        Temp ^= 0x63;
        EncodeStr[i] = Temp;
    }
    
    if(EncodeData[i] != EncodeStr[i])
        Register_4 = 1;
}
```

所以解密起来很简单，就是分奇偶下标将EncodeData进行解密计算即可拿到Flag.

解密代码如下:

```c++
int main()
{
	unsigned char EncodeData[]{
	 0x0E, 0x40, 0x7E, 0x1E, 0x13, 0x34, 0x1A, 0x17, 0x6E, 0x1B,
	 0x1C, 0x17, 0x2E, 0x0C, 0x1A, 0x30, 0x69, 0x32, 0x26, 0x16,
	 0x1A, 0x15, 0x25, 0x0E, 0x1C, 0x42, 0x30, 0x32, 0x0B, 0x42,
	 0x79, 0x17, 0x6E, 0x42, 0x29, 0x17, 0x6E, 0x5A, 0x2D, 0x20,
	 0x1A, 0x16, 0x26, 0x10, 0x05, 0x15, 0x6E, 0x0D, 0x58, 0x24 };

	std::string Flag;

	for (int i = 0; i < 50; i++)
	{
		if (i % 2 == 0)
		{
			int Temp = EncodeData[i];
			Temp ^= 0x43;
			Temp = Temp + 0x59 - 0x53;
			Flag += (char)Temp;
		}
		else
		{
			int Temp = EncodeData[i];
			Temp = Temp + 0x73 - 0x79;
			Temp ^= 0x63;
			Flag += (char)Temp;
		}
	}

	std::cout << Flag << std::endl;
	
	// SYC{VM_r3verse_I0Oks_llke_yON_@r3_pr37ty_skiLl3d!}

	return 0;
}
```
