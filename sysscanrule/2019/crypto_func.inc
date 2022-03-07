#TRUSTED 83f22119c0e640ffa5fecbf9c70cf77e7e66703851ec81b1454e39e9bb78b308a20aba168b5c71da178128d77214ab43848e21acd82906d52f37cb6bcbf55f640a8cb2e1796c78fae42c3fa55884b261c1fd4c2374b20998307c44e02f154c53365c1a4336b8a3bb12a9c8c6bd267f9501e4fa38e10599c67bf6d9e8ced4b6a15bcf0fe7519c944c585a3422d0b5e0e7d29a132fdbb8be86f1fe20e8fcc6b2fa9ee3b619abe22bca46f88ed5adbefcd06fb959637d330d5a014a32a58f46180c113def790ce8a4568f1dee85e69278180aa5ffdfff1ff3789df0c5072a7adbc96c1667b91988127ff66198157f190e52f67569dbd08511b8dbdda5b7b07116fbe62d1b4fe467b7553bbfd1626333ca8418e27e66c9531077447a05dcbfc83e1d78561666b10ead16e1751651f8471af9de826f93a2ddf5042876ff6dee66c91f2cac22b25c3c00b3a92df5e4c1d23ce5baaebaa13a43ba22cb848fc312aaec063c498f144c5b16f3ce722b360279d8db1139ed498fd90e500c11379ebe0346e1388e29ad880a8581f7fc100478c4b5f8386b579c4e6866780937cb400c5dd391c42063d269ce026031fbe56092c1926ce3bcca0abe5c898d7a456af66d7c2de7aaffff72349975e20e541aa6476c385a12b2710deeeac9bb5cfbbb81432632d754718fefaf55a3473c2ed9150fde7723793d0ef71116c896c90c10d1fd5bce00
# -*- Fundamental -*-
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
#
# @NOGPL@
#
# crypto_func.inc 
#


#---------------------------------------------------------#
# DES encryption code                                     #
#---------------------------------------------------------#



perm1 = make_list (57, 49, 41, 33, 25, 17,  9,
                     1, 58, 50, 42, 34, 26, 18,
                    10,  2, 59, 51, 43, 35, 27,
                    19, 11,  3, 60, 52, 44, 36,
                    63, 55, 47, 39, 31, 23, 15,
                     7, 62, 54, 46, 38, 30, 22,
                    14,  6, 61, 53, 45, 37, 29,
                    21, 13,  5, 28, 20, 12,  4 );


perm2 = make_list (14, 17, 11, 24,  1,  5,
                     3, 28, 15,  6, 21, 10,
                    23, 19, 12,  4, 26,  8,
                    16,  7, 27, 20, 13,  2,
                    41, 52, 31, 37, 47, 55,
                    30, 40, 51, 45, 33, 48,
                    44, 49, 39, 56, 34, 53,
                    46, 42, 50, 36, 29, 32 );

perm3 = make_list (58, 50, 42, 34, 26, 18, 10,  2,
                    60, 52, 44, 36, 28, 20, 12,  4,
                    62, 54, 46, 38, 30, 22, 14,  6,
                    64, 56, 48, 40, 32, 24, 16,  8,
                    57, 49, 41, 33, 25, 17,  9,  1,
                    59, 51, 43, 35, 27, 19, 11,  3,
                    61, 53, 45, 37, 29, 21, 13,  5,
                    63, 55, 47, 39, 31, 23, 15,  7 );

perm4 = make_list (32,  1,  2,  3,  4,  5,
                     4,  5,  6,  7,  8,  9,
                     8,  9, 10, 11, 12, 13,
                    12, 13, 14, 15, 16, 17,
                    16, 17, 18, 19, 20, 21,
                    20, 21, 22, 23, 24, 25,
                    24, 25, 26, 27, 28, 29,
                    28, 29, 30, 31, 32,  1 );

perm5 = make_list (16,  7, 20, 21,
                    29, 12, 28, 17,
                     1, 15, 23, 26,
                     5, 18, 31, 10,
                     2,  8, 24, 14,
                    32, 27,  3,  9,
                    19, 13, 30,  6,
                    22, 11,  4, 25 );

perm6 = make_list (40,  8, 48, 16, 56, 24, 64, 32,
                    39,  7, 47, 15, 55, 23, 63, 31,
                    38,  6, 46, 14, 54, 22, 62, 30,
                    37,  5, 45, 13, 53, 21, 61, 29,
                    36,  4, 44, 12, 52, 20, 60, 28,
                    35,  3, 43, 11, 51, 19, 59, 27,
                    34,  2, 42, 10, 50, 18, 58, 26,
                    33,  1, 41,  9, 49, 17, 57, 25 );

sc = make_list (1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1);

sbox =    make_list (        14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7,
                              0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8,
                              4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0,
                             15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13,
	                  
                             15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10,
		              3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5,
			      0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15,
			     13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9,
	                  
                             10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8,
		             13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1,
			     13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7,
			      1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12,

	                      7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15,
		             13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9,
			     10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4,
			      3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14,

	                      2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9,
		             14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6,
			      4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14,
			     11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3,

		             12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11,
		             10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8,
			      9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6,
			      4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13,

		              4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1,
		             13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6,
			      1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2,
			      6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12,

	                     13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7,
		              1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2,
			      7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8,
			      2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11 );

function permute (in, p)
{
 local_var buf, i;

 buf = NULL;
 for (i = 0; i < strlen(p); i++)
    buf += in[ord(p[i]) - 1];
 
 return buf;
}

function lshift (d, count)
{
 local_var buf, i;

 buf = NULL;
 for (i = 0; i < strlen(d); i++)
   buf += d[(i+count)%strlen(d)];
  
 return buf;
} 

function xor (in1, in2)
{
 local_var buf, i;

 buf = NULL;
 for (i = 0; i < strlen(in2); i++)
   buf += raw_string (ord(in1[i]) ^ ord(in2[i]));
 
 return buf;
}


global_var _b, _er, _erk, _cb, _pcb, _l, _r, _r2, _buf;

_b = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_er = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_erk = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_cb = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_pcb = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_l = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_r = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

_r2 = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

__buf = make_list (
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

function des_encrypt (in, key, type)
{
 local_var i, j, k, c, d, cd, pd1, l, r, rl, pk1;
 local_var cb, pcb, r2, tmp, val, ki;
 local_var m, n;
 local_var cmpt, tmp1, tmp2, count;
 
 pk1 = c = d = cd = NULL;

 for (cmpt = 0; cmpt < 56; cmpt++)
   pk1 += key[perm1[cmpt] - 1];

 c = substr (pk1, 0, 27);
 d = substr (pk1, 28, 55);

 for (i = 0; i < 16; i++)
 {
  tmp1 = tmp2 = NULL;
  count = sc[i];
  for (cmpt = 0; cmpt < 28; cmpt++)
  {
    tmp1 += c[(cmpt+count)%28];
    tmp2 += d[(cmpt+count)%28];
  }

  c = tmp1;
  d = tmp2;

  cd = c + d;

  ki[i] = NULL;
  for (cmpt = 0; cmpt < 48; cmpt++)
    ki[i] += cd[perm2[cmpt] - 1];
 }

 for (cmpt = 0; cmpt < 64; cmpt++)
 {
  if (cmpt < 32)
    _l[cmpt] = in[perm3[cmpt] - 1];
  else
    _r[cmpt-32] = in[perm3[cmpt] - 1];
 }

 
 for (i = 0; i < 16; i++)
 {
  for (cmpt = 0; cmpt < 48; cmpt++)
     _er[cmpt] = _r[perm4[cmpt] - 1];

  if (type == 1)
  { 
    tmp2 = ki[i];
    for (cmpt = 0; cmpt < 48; cmpt++)
      _b[cmpt] = (_er[cmpt] ^ ord(tmp2[cmpt]));
  }
  else
  {
    tmp2 = ki[15-i];
    for (cmpt = 0; cmpt < 48; cmpt++)
      _b[cmpt] = (_er[cmpt] ^ ord(tmp2[cmpt]));
  }

  for (j = 0; j < 8; j++)
  {
   tmp2 = j*6;
   m = (_b[tmp2] << 1);
   m = m | (_b[tmp2 + 5]);

   n = (_b[tmp2 + 1] << 3);
   n = n | (_b[tmp2 + 2] << 2);
   n = n | (_b[tmp2 + 3] << 1);
   n = n | (_b[tmp2 + 4]);

   tmp1 = sbox [j*4*16 + m*16 + n];
   for (k = 0; k < 4; k++)
      if ((tmp1 & (1<<(3-k))) == 0)
        _b[tmp2 + k] = 0;
      else
        _b[tmp2 + k] = 1;
  }
 
  for (j=0; j<8; j++)
  {
   tmp2 = j*6;
   tmp1 = j*4;
   _cb[tmp1] = _b[tmp2];
   _cb[tmp1+1] = _b[tmp2+1];
   _cb[tmp1+2] = _b[tmp2+2];
   _cb[tmp1+3] = _b[tmp2+3];
  }

  for (cmpt = 0; cmpt < 32; cmpt++)
    _pcb[cmpt] = _cb[perm5[cmpt] - 1];
 
  for (cmpt = 0; cmpt < 32; cmpt++)
    _r2[cmpt] = (_l[cmpt] ^ _pcb[cmpt]);

  _l = _r;
  _r = _r2;
 }
 
 for (cmpt = 0; cmpt < 64; cmpt++)
 {
   tmp2 = perm6[cmpt]-1;
   if (tmp2 < 32)
     __buf[cmpt] = _r[tmp2];
   else
     __buf[cmpt] = _l[tmp2-32];
 }

 return __buf;
}


global_var _zero, _one, _inb;

_zero = raw_string(0);
_one = raw_string(1);

_inb = make_list(0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0,
               0,0,0,0,0,0,0,0);

function set_des_key (key)
{
 local_var keyb, i;

 keyb = NULL;

 for (i=0;i<64;i++)
 {

  if ((ord(key[i/8]) & (1<<(7-(i%8)))) == 0)
    keyb += _zero;
  else
    keyb += _one;
 }

 return keyb;
}


function str_to_key (str)
{
 local_var key, i;

 key = raw_string ( ((ord(str[0])>>1) << 1) ,
                    ((((ord(str[0])&0x01)<<6) | (ord(str[1])>>2)) << 1) ,
                    ((((ord(str[1])&0x03)<<5) | (ord(str[2])>>3)) << 1) ,
                    ((((ord(str[2])&0x07)<<4) | (ord(str[3])>>4)) << 1) ,
                    ((((ord(str[3])&0x0F)<<3) | (ord(str[4])>>5)) << 1) ,
                    ((((ord(str[4])&0x1F)<<2) | (ord(str[5])>>6)) << 1) ,
                    ((((ord(str[5])&0x3F)<<1) | (ord(str[6])>>7)) << 1) ,
                    ((ord(str[6])&0x7F) << 1) );

 return set_des_key(key:key);
}


function DES (in, key, _string, type)
{
 local_var inb, keyb, key2, outb, out, buf, i;

 inb = keyb= outb = buf = NULL;;

 if (isnull(_string) || (_string == TRUE))
   key2 = str_to_key (str:key);
 else
   key2 = key;

 for (i=0;i<64;i++)
 {
  if ((ord(in[i/8]) & (1<<(7-(i%8)))) == 0)
    _inb[i] = 0;
  else
    _inb[i] = 1;    
 }

 outb = des_encrypt(in:_inb, key:key2, type:type);

 out = make_list (0,0,0,0,0,0,0,0);

 for (i=0;i<64;i++) 
 {
  if (outb[i] == 1)
    out[i/8] = out[i/8] | (1<<(7-(i%8)));
 }

 for (i=0;i<8;i++)
 {
  buf += raw_string (out[i]);
 }

 return buf;
}





#---------------------------------------------------------#
# RC4 HMAC encryption code                                #
#---------------------------------------------------------#

global_var arcS, arcS2;

function arcfour_setkey (key)
{
 local_var i,j,temp;

 arcS = NULL;
 for (i=0; i < 256; i++)
 {
  arcS[i] = i;
  arcS2[i] = ord(key[i % strlen(key)]);
 }

 j = 0;
 
 for (i=0; i < 256; i++)
 {
  j = (j + arcS[i] + arcS2[i]) % 256;
  temp = arcS[i];
  arcS[i] = arcS[j];
  arcS[j] = temp;
 }
}


function ARCFOUR (data)
{
 local_var i,j,temp,t,k,output,l;

 output = NULL;
 i = j = 0;
 
 for (l=0; l < strlen(data); l++)
 {
  i = (i+1) % 256;
  j = (j + arcS[i]) % 256;
  temp = arcS[i];
  arcS[i] = arcS[j];
  arcS[j] = temp;
  t = (arcS[i] + arcS[j]) % 256;
  k = arcS[t];

  output += raw_string (k ^ ord(data[l]));
 }

 return output;
}


function rc4_hmac_string_to_key (string)
{
 # Must be unicode !!!
 return MD4 (string);
}


function rc4_hmac_checksum (key,type,data,real_key)
{
 local_var hmac, tmp, key2;

 hmac = HMAC_MD5 (key:key, data:"signaturekey"+raw_byte(b:0));
 tmp = MD5 (type+data);
 
 return HMAC_MD5 (key:hmac, data:tmp);
}


function rc4_hmac_encrypt (key,data,type,real_key)
{
 local_var hmac, checksum, conf_data, K3, random, key2, val1, i;

 if (isnull(real_key) || (real_key == FALSE))
 {
   # make sure password is unicode
   local_var pass;
   pass = NULL; for(i = 0; i < strlen(key); i++) pass += key[i] + '\x00';
   key2 = rc4_hmac_string_to_key (string:pass);
 }
 else
   key2 = key;
 
 random = NULL;
 
 hmac = HMAC_MD5 (key:key2, data:type);

 for (i=0; i < 8; i++)
    random += raw_string (rand() % 256);
 conf_data = random + data;

 checksum = HMAC_MD5 (key:hmac, data:conf_data);
 K3 = HMAC_MD5 (key:hmac, data:checksum);

 arcfour_setkey (key:K3);
 val1 = ARCFOUR (data:conf_data);

 return checksum + val1;
}


function rc4_hmac_decrypt (key,data,type,real_key)
{
 local_var hmac, checksum, checksum2, conf_data, K3, key2, val1;

 if (isnull(real_key) || (real_key == FALSE))
 {
   # make sure password is unicode
   local_var i, pass;
   pass = NULL; for(i = 0; i < strlen(key); i++) pass += key[i] + '\x00';
   key2 = rc4_hmac_string_to_key (string:pass);
 }
 else
   key2 = key;
 
 hmac = HMAC_MD5 (key:key2, data:type);

 checksum = substr(data,0,15);
 K3 = HMAC_MD5 (key:hmac, data:checksum);


 conf_data = substr (data,16,strlen(data)-1);
 arcfour_setkey (key:K3);
 val1 = ARCFOUR (data:conf_data);

 checksum2 = HMAC_MD5 (key:hmac, data:val1);

 if (checksum == checksum2)
   return substr(val1,8,strlen(val1)-1);
 else
   return NULL;
}


#function rc4_hmac_checksum (key,data,type)
#{
# ksign = HMAC_MD5;
#}


#---------------------------------------------------------#
# DES-cbc  encryption code                                #
#---------------------------------------------------------#


function xor8 (a,b)
{
 local_var tmp, i;

 tmp = NULL;

 for (i=0; i<strlen(a); i++)
   tmp += raw_byte (b:ord(a[i]) ^ ord(b[i]));

 return tmp;
}


function reverse(i)
{
 local_var tmp, val, j;

 tmp = 0;
 val = 0x80;
 for (j=1; j<8; j++)
 {
  if (ord(i) & val)
    tmp += (1 << j);
  val = val >> 1;
 }

 return raw_byte(b:tmp);
}


function reverse8 (s)
{
 local_var tmp, i;

 tmp = NULL;

 for (i=0; i<strlen(s); i++)
   tmp += reverse(i:s[strlen(s)-1-i]);

 return tmp;
}


function get_parity (i)
{
 local_var tmp, val, j;

 tmp = 0;
 val = 2;
 for (j=0; j<7; j++)
 {
   if (i & val)
     tmp++;
   val = (val << 1) % 256;
 }

 return (tmp%2);
}


function fixparity(s)
{
 local_var tmp, val, i;

 tmp = NULL;
 for (i=0; i<strlen(s);i++)
 {
  val = ord(s[i]);
  if (get_parity(i:val) == 0)
   val = (val & 0xFE) + 1 ;
  else
   val = val & 0xFE;

  tmp += raw_byte(b:val);
 }

 return tmp;
}

function removeMSBits(s)
{
 local_var tmp, i;

 tmp = NULL;
 for (i=0; i<strlen(s); i++)
 {
  tmp += raw_byte(b:ord(s[i]) << 1);
 }

 return tmp;
}


# Need to be done
function is_weak_key (key)
{
 return 0;
}


function des_cbc_checksum (key, data, iv)
{
 local_var tout0, tout1, tin0, tin1, i, tin, keyb, tmp;

 tout0 = get_dword(blob:iv, pos:0);
 tout1 = get_dword(blob:iv, pos:4);

 keyb = set_des_key (key:key);

 for (i=0; i<strlen(data); i+=8)
 {
  if (i+8<=strlen(data))
  {
   tin0 = get_dword(blob:data, pos:i);
   tin1 = get_dword(blob:data, pos:i+4);
  }
  else
  {
   tmp = substr(data,i,strlen(data)-1);
   tmp += crap(data:raw_byte(b:0), length:8-(strlen(tmp)%8));
   tin0 = get_dword(blob:tmp, pos:i);
   tin1 = get_dword(blob:tmp, pos:i+4);   
  }

  tin0 = tin0 ^ tout0;
  tin1 = tin1 ^ tout1;
  
  tin = raw_dword (d:tin0) + raw_dword(d:tin1);
  tin = DES (in:tin, key:keyb, type:1, _string:FALSE);
  tout0 = get_dword(blob:tin, pos:0);
  tout1 = get_dword(blob:tin, pos:4);
 }

 return raw_dword(d:tout0) + raw_dword(d:tout1);
}


function des_cbc_encrypt (data, key, iv, encrypt)
{
 local_var tin, tin0, tin1, tout0, tout1, out, i, xor0, xor1, keyb;

 keyb = set_des_key (key:key);

 out = NULL;
 if (encrypt == 1)
 {
  tout0 = get_dword(blob:iv, pos:0);
  tout1 = get_dword(blob:iv, pos:4);
  for (i=0; i<strlen(data); i+=8)
  {
   tin0 = get_dword(blob:data, pos:i);
   tin1 = get_dword(blob:data, pos:i+4);

   tin0 = tin0 ^ tout0;
   tin1 = tin1 ^ tout1;
  
   tin = raw_dword (d:tin0) + raw_dword(d:tin1);
   tin = DES (in:tin, key:keyb, type:1, _string:FALSE);
   tout0 = get_dword(blob:tin, pos:0);
   tout1 = get_dword(blob:tin, pos:4);
   out += tin;
  }
 }
 else
 {
  xor0 = get_dword(blob:iv, pos:0);
  xor1 = get_dword(blob:iv, pos:4);
  for (i=0; i<strlen(data); i+=8)
  {
   tin0 = get_dword(blob:data, pos:i);
   tin1 = get_dword(blob:data, pos:i+4);
   tin = raw_dword(d:tin0) + raw_dword(d:tin1);
   tin = DES (in:tin, key:keyb, type:0, _string:FALSE);
   tout0 = get_dword(blob:tin, pos:0) ^ xor0;
   tout1 = get_dword(blob:tin, pos:4) ^ xor1;
   out += raw_dword(d:tout0) + raw_dword(d:tout1);
   xor0 = tin0;
   xor1 = tin1;
  }
 }

 return out;
}


function des_cbc_string_to_key (_string,salt)
{
 local_var odd, s, tempkey, byteblock, i, j, key, fix_weak;

 fix_weak = raw_string(0x00,0x00,0x00,0x00,0x00,0x00,0x00,0xF0);

 odd = 1;

 s = _string + salt;
 tempkey = raw_string (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);
 
 # pad on 8 bytes
 if (strlen(s) % 8)
   s = s + crap (data:raw_byte(b:0x00), length:8-(strlen(s)%8));

 for (i=0; i< strlen(s); i+=8)
 {
  byteblock = removeMSBits(s:substr(s,i,i+7));
  if (odd == 0)
  {
   odd = 1;
   byteblock = reverse8(s:byteblock);
  }
  else
   odd = 0;

  tempkey = xor8 (a:tempkey, b:byteblock);
 }

 tempkey = fixparity(s:tempkey);
 if (is_weak_key(key:key))
   key = xor8 (a:key, b:fix_weak);
 key = des_cbc_checksum(key:tempkey,data:s, iv:tempkey);
 key = fixparity(s:key);

 return key;
}


function des_cbc_md5_encrypt (data, key)
{
 local_var iv, confounder, i, hash, cksum, tmp;

 cksum = raw_string (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

 confounder = NULL;

 for (i=0; i<8; i++)
  confounder += raw_byte(b:rand()%256);

 tmp = data;
 if (strlen(data)%8)
   tmp += crap(data:raw_byte(b:0),length:8-(strlen(data)%8));

 hash = MD5 (confounder+cksum+tmp);

 iv = raw_string (0,0,0,0,0,0,0,0);

 return des_cbc_encrypt (data:confounder+hash+tmp, key:key, iv:iv, encrypt:1);
}



function des_cbc_md5_decrypt (data, key)
{
 local_var iv, confounder, cksum, decrypted, hash, msg, tohash;

 cksum = raw_string (0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0);

 iv = raw_string (0,0,0,0,0,0,0,0);

 decrypted = des_cbc_encrypt (data:data, key:key, iv:iv, encrypt:0);
 if (strlen(decrypted) < 24)
   return NULL;
 
 msg = substr(decrypted,24,strlen(decrypted)-1);
 confounder = substr(decrypted, 0, 7);
 tohash = confounder+cksum+msg;

 hash = MD5 (tohash);

 cksum = substr(decrypted, 8, 23);

 if (hexstr(cksum) >!< hexstr(hash))
   return NULL;

 return msg;
}


function des_cbc_md5_checksum (data, key)
{
 local_var confounder, iv, i, enckey, tmp;

 iv = raw_string (0,0,0,0,0,0,0,0);

 enckey = xor8(a:key,b:raw_string(0xF0,0xF0,0xF0,0xF0,0xF0,0xF0,0xF0,0xF0));
 confounder = NULL;

 for (i=0; i<8; i++)
  confounder += raw_byte(b:rand()%256);

 return des_cbc_encrypt (data:confounder+MD5(confounder+data), key:enckey, iv:iv, encrypt:1);
}




#---------------------------------------------------------#
# LANMAN2.1 Challenge/Response                            #
#---------------------------------------------------------#


function LM_Hash (password)
{
 local_var len, pass, K1, K2, hash;

 len = strlen (password);
 if ( len > 14 ) len = 14;
 pass = substr (password, 0, len);

 while (strlen(pass) < 14)
   pass += raw_string (0);

 pass = toupper (pass);

 K1 = substr (pass, 0, 6);
 K2 = substr (pass, 7, 13);

 hash = DES (in:"KGS!@#$%", key:K1, type:1) + DES (in:"KGS!@#$%", key:K2, type:1);

 return hash;
}


function LM_Response (password, hash, challenge)
{
 local_var key1, key2, key3, response;

 response = NULL;

 if (isnull(hash))
   hash = LM_Hash (password:password);

 response[1] = substr (hash, 0, 7) + raw_string (0x00,0x00,0x00,0x00,0x00,0x00,0x00,0x00);

 hash += raw_string (0x00,0x00,0x00,0x00,0x00);

 key1 = substr (hash, 0, 6);
 key2 = substr (hash, 7, 13);
 key3 = substr (hash, 14, 20);

 response[0] = DES (in:challenge, key:key1, type:1) + DES (in:challenge, key:key2, type:1) + DES (in:challenge, key:key3, type:1);

 return response;
}



#---------------------------------------------------------#
# NTLM 0.12 Challenge/Response                            #
#---------------------------------------------------------#


function NTLM_Hash (password)
{
 if (password)
   return MD4 (password);
 else
   return raw_string(0x31, 0xd6, 0xcf, 0xe0, 0xd1, 0x6a, 0xe9, 0x31, 0xb7, 0x3c, 0x59, 0xd7, 0xe0, 0xc0, 0x89, 0xc0);
}

function NTLM_Response (password, hash, challenge)
{
 local_var key1, key2, key3, response;

 response = NULL;

 if (isnull(hash))
   hash = NTLM_Hash (password:password);

 response[1] = MD4 (hash);

 hash += raw_string (0x00,0x00,0x00,0x00,0x00);

 key1 = substr (hash, 0, 6);
 key2 = substr (hash, 7, 13);
 key3 = substr (hash, 14, 20);

 response[0] = DES (in:challenge, key:key1, type:1) + DES (in:challenge, key:key2, type:1) + DES (in:challenge, key:key3, type:1);

 return response;
}


function NTLMv2_Hash (password, login, hash, domain)
{
 local_var user, dest, data;

 if (isnull(hash))
   hash = NTLM_Hash (password:password);

 user = toupper (login);
 dest = domain;
 
 data = user + dest;
 hash = HMAC_MD5 (data:data, key:hash);

 return hash;
}


function unixtime_to_nttime64 (time)
{
 local_var high, low, add, tmp, tmp2, i, j, val, diff;

 tmp = raw_dword(d:time)+raw_dword(d:0);

 for (i=0; i<7; i++)
 {
  val = 0;
  tmp2 = NULL;
  for (j=0; j<8; j++)
  {
   tmp2 = tmp2 + raw_string((ord(tmp[j])*2+val)&0xFF);
   val = ((ord(tmp[j])*2+val)&0xFF00) >> 8;
  }
  tmp = tmp2;
 }

 for (i=0; i<7; i++)
 {
  val = 0;
  tmp2 = NULL;
  for (j=0; j<8; j++)
  {
   tmp2 = tmp2 + raw_string((ord(tmp[j])*5+val)&0xFF);
   val = ((ord(tmp[j])*5+val)&0xFF00) >> 8;
  }
  tmp = tmp2;
 }

 diff = raw_string (0x00,0x80,0x3e,0xd5,0xde,0xb1,0x9d,0x01);

 val = 0;
 tmp2 = NULL;
 for (j=0; j<8; j++)
 {
  tmp2 = tmp2 + raw_string((ord(tmp[j])+ord(diff[j])+val)&0xFF);
  val = ((ord(tmp[j])+ord(diff[j])+val)&0xFF00) >> 8;
 }
 tmp = tmp2;

 return tmp;
}

function _mk_unicode()
{
  local_var data, i, out;

  data = _FCT_ANON_ARGS[0];
  out = NULL;
  for (i = 0; i < strlen(data); i++)
    out += data[i] + '\x00';

  return out;
}
function av_pair_put(id, value)
{
  local_var av, len;

  len = strlen(value);
  av = raw_string((id & 0xff),  (id >> 8)  & 0xff)   +  # attribute id
       raw_string((len & 0xff ), (len >> 8) & 0xff)  +  # attribute length
       value;                                           # attribute value

  return av; 
}
function av_pair_get(data, id, pos)
{
  local_var _id, dlen, len, value;
  
  dlen = strlen(data);

  # Default starting search position
  if(isnull(pos)) pos = 0; 
  repeat
  { 
    if(pos + 2 > dlen) return NULL; 
    _id  = get_word(blob: data, pos: pos); pos += 2;

    if(pos + 2 > dlen) return NULL;
    len = get_word(blob: data, pos: pos); pos += 2;
    if(pos + len > dlen) return NULL;
    
    value = substr(data, pos, pos + len - 1);
    pos += len;
 
    # If id is NULL, return the AV_PAIR @pos, providing a way to enumerate the AV_PAIR list   
    if(isnull(id) || id == _id) 
      return make_array('id', _id, 'value', value, 'next', pos); 
   
  }until(_id == 0); # MsvAvEOL

  # AV_PAIR not found
  return NULL; 
}

function NTLMv2_Response (password, hash, login, domain, challenge, sblob, service, forceip)
{
 local_var data, blob, hmac, resp, TimeStamp, blip, i, spn, av, thost; 

 resp = NULL;
 hash = NTLMv2_Hash (password:password, login:login, hash:hash, domain:domain);

 blip = NULL;

 for (i = 0; i < 8; i++)
    blip += raw_string (rand() % 256);
 
 #TimeStamp = raw_string (0x51,0xf4,0x44,0xb4,0x3a,0x44,0xc7,0x01) ; # To change !!
 TimeStamp = unixtime_to_nttime64(time:unixtime());

 thost = NULL;
 # If server sends CHALLENGE_MESSAGE.TargetInfo, try get to the FQDN or NETBIOS name of the target server 
 if( sblob)
 {
   # MsvAvDnsComputerName, MsvAvNbComputerName 
   foreach i (make_list(3, 1))
   {
      av = av_pair_get(data: sblob, id: i);
      if(av)
      { 
        thost = av['value']; 
        break;
      }
   } 
 } 

 # Use IP address only for smb2
 if (forceip)
 {
   thost = _mk_unicode(get_host_ip());
 }

 # Server didn't send its FQDN or NETBIOS name in the CHALLENGE_MESSAGE, try to resolve it our way. 
 #
 # See if there is a NETBIOS name learned by other plugins 
 if(! thost)
 {
    thost = get_kb_item('SMB/name'); 

    # Try to get FQDN if NETBIOS name not found
    if(! thost || thost == get_host_ip())
    thost = get_host_name();
  
    thost = _mk_unicode(thost);
 }

 # NTLMSSP can be used to authenticate to various network services; not limited to CIFS
 if(! service) service = 'cifs';
 spn = _mk_unicode(service + '/') + thost;

 # Specify target SPN in the AV_PAIRs; MsvAvTargetName
 sblob = av_pair_put(id: 9, value: spn) + sblob;
 
 blob = raw_string ( 0x01,                    # Response Type Identification Number
                     0x01,                    # Maximum Response Type Identification Number
		     0x00, 0x00,              # Reserved
		     0X00, 0x00, 0x00, 0x00 ) # Reserved ?
	+
	TimeStamp
	+
	blip
	+
	raw_string (0x00,0x00,0x00,0x00)  # Unknown value
	+
	sblob
	+
	raw_string (0x00,0x00,0x00,0x00); # Unknown value
	
 data = challenge + blob;
 hmac = HMAC_MD5 (data:data, key:hash);
 resp[0] = hmac + blob;
 resp[1] = HMAC_MD5 (data:hmac, key:hash);

 return resp;
}


function LMv2_Response (password, login, hash, domain, challenge)
{
 local_var data, blob, hmac, resp, TimeStamp, blip, i;
 
 resp = NULL;
 hash = NTLMv2_Hash (password:password, login:login, hash:hash, domain:domain);

 blip = NULL;

 for (i = 0; i < 8; i++)
    blip += raw_string (rand() % 256);
 
 data = challenge + blip;
 hmac = HMAC_MD5 (data:data, key:hash);
 resp[0] = hmac + blip;
 resp[1] = HMAC_MD5 (data:hmac, key:hash);

 return resp;
}


PRF_HMAC_SHA1 = 1;

##
# Converts a password to an intermediate key
#
# @param p password passed to the PBKDF2 function
# @param s salt passed to the PBKDF2 function
# @param c iterations passed to the PBKDF2 function
# @param dklen requested key length in bytes 
# @param prf Identifier of the Pseudo random function used in the PBKDF2 function; if not specfied, default to PRF_HMAC_SHA1
# @return derived key; NULL on error
# @remark
#   - See RFC 2898, section 5.2 for mote details
##
function pbkdf2(p, s, c, dklen, prf)
{
  local_var data,f, hlen, i, j, l, t, u;
  local_var supported_hashes, hmac;

  # Use HAMC_SHA1 as default PRF
  if(isnull(prf))
    prf = "SHA1";

  supported_hashes = {
    "MD2": [16, @HMAC_MD2],
    "MD5": [16, @HMAC_MD5],
    "SHA1": [20, @HMAC_SHA1],
    "SHA224": [28, @HMAC_SHA224],
    "SHA256": [32, @HMAC_SHA256],
    "SHA384": [48, @HMAC_SHA384],
    "SHA512": [64, @HMAC_SHA512],
    "RIPEMD160": [20, @HMAC_RIPEMD160]
  };

  if(!dklen || !c || !p || !s)
    return NULL;

  if(isnull(supported_hashes[prf]))
    return NULL;

  hlen = supported_hashes[prf][0];
  hmac = supported_hashes[prf][1];

  # Number of hLen-octet blocks in the derived key, rounding up
  # CEIL (dkLen / hLen)
  l = dklen / hlen;
  if (dklen % hlen) l++;

  #Less than the standard check because ... signed integers
  if(l > 0x7fffffff)
    return NULL;

  t = NULL;
  for(i = 1; i <= l; i++)
  {
    f = crap(data:'\x00', length: hlen);
    data = s + raw_string((i << 24) & 0xff, (i << 16) & 0xff, (i << 8) & 0xff, i & 0xff);
    for(j = 0; j < c; j++)
    {
      u = hmac(key:p, data:data);
      f = xor(in1:f, in2:u);
      data = u;
    }
   t += f;
  }

  return substr(t, 0, dklen -1);
}


##
# N-folds data  
#
# @param data data to fold
# @paran flen number of bytes to fold to 
# @return folded data
# @remark
#  - The n-fold algorithm is described in http://www.gnu.org/software/shishi/ides.pdf 
#
##
function nfold(data, flen)
{
  local_var buf, chunk, dlen, i, lcm, out;

  if(isnull(data)) return NULL;

  # Fold len not specified, return the original data
  if(isnull(flen)) return data;
  
  dlen = strlen(data);
  
  # Compute the least common multiple
  lcm = lcm(dlen, flen); 
  
  # Replicate input data to lcm length
  buf = NULL;
  for(i = 0; i < lcm /dlen; i++)
  {
    buf += data;
    data = rotr(data:data, step:13);
  }

  # Add chunks of flen
  out = crap(data:'\x00', length:flen);
  for(i = 0; i < lcm / flen; i++)
  {
    chunk = substr(buf, i * flen,  (i + 1) * flen - 1);
    out = ocadd(out, chunk);
  }
 
  return out; 
}

##
# Computes the least common mulitple of two numbers
#
# @anonparam number 1
# @anonparam number 2 
# @return the least common mutiple of two number; or NULL if there is an error.
##
function lcm()
{
  local_var a, b, m, t;
  
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if(isnull(a) || isnull(b)) return NULL;
  
  m = a * b;

  # ensure a >= b
  if(a < b)
  {
    t = a;
    a = b;
    b = t; 
  }
  
  # gcd(a,b)
  while(b !=0 )
  {
    t = b;
    b = a % b;
    a = t;
  }  
 
  # lcm(a,b) = (a * b)/gcd(a,b) 
  return (m / a); 
}

##
# Treats two buffers as big numbers and add them using ones complement arithmetic
# 
# @anonparam number1
# @anonparam number2
# @return sum of number1 and number2
#   
##
function ocadd()
{
  local_var a, alen, b, blen, c, i, out, t;
  
  a = _FCT_ANON_ARGS[0];
  b = _FCT_ANON_ARGS[1];

  if(! a) return b;
  if(! b) return a;

  alen = strlen(a);
  blen = strlen(b);

  # Left-pad the smaller buffer if the two buffers are not of same length
  if(alen > blen)
    b = crap(data:'\x00', length: alen - blen) + b;
  else if (alen < blen)
    a = crap(data:'\x00', length: blen - alen) + a;

  # Add two buffers byte by byte
  out = NULL;
  c = 0;
  for(i = strlen(a) - 1; i >= 0; i--)
  {
    t = ord(a[i]) + ord(b[i]) + c;
    c = (t > 0xff);
    out = raw_string(t) + out;
  }
  # Add back the carry bit
  if(c) out = ocadd(out, raw_string(0x01));

  return out;
}

##
# Gets one bit from a data buffer
#
# @anonparam data buffer
# @anonparam position of the bit 
# @return bit value, or NULL if there is an error.
#
##
function getbit()
{
  local_var byte, data, pos;
 
  data  = _FCT_ANON_ARGS[0];
  pos   = _FCT_ANON_ARGS[1];
  
  if(isnull(data) || isnull(pos)) return NULL;

  if(pos > strlen(data) * 8 - 1)
    return NULL; 

  # Get the byte where the bit is in
  byte = ord(data[pos / 8]);
   
  # Extract the bit
  return (byte >> (7 - pos % 8)) & 0x01;
}

##
# Sets a bit in a data buffer 
#
# @anonparam data buffer
# @anonparam position of the bit 
# @anonparam bit value to set
# @return modified data buffer; or NULL if there is an error
#
##
function setbit()
{
  local_var byte, data, pos, val;
  
  data  = _FCT_ANON_ARGS[0];
  pos   = _FCT_ANON_ARGS[1];
  val   = _FCT_ANON_ARGS[2];

  if(isnull(data) || isnull(pos) || isnull(val)) return NULL;
  
  if(pos > strlen(data) * 8 - 1)
    return NULL; 

  val = val & 0x01;
  
  # Get the byte where the bit should be in 
  byte = ord(data[pos / 8]);

  # Set the bit in the byte
  byte =  byte & (~(0x80 >> (pos % 8)));    # clear the bit
  byte =  byte | (val << (7 - (pos % 8)));  # set the bit according to its value 

  data[pos/8] = raw_string(byte);
 
  return data; 
}

##
# Rotates data to the right
#
# @param data data to rotate
# @param step number of bits to rotate
# @return rotated data
#
##
function rotr(data, step)
{
  local_var bitval, dlen, i, out, pos, t;

  if(isnull(data)) return NULL; 
  if(isnull(step)) step = 1; 
  dlen = strlen(data);
  out = crap(data:'\x00',length:dlen);
  for(i = 0; i < dlen * 8; i++)
  {
    bitval = getbit(data, i);
    pos = (i + step) % (dlen * 8);
    out = setbit(out, pos, bitval);  
  }
  return out; 
}

##
# Encrypts data using AES in CBC Ciphertext Stealing mode
# 
# @param data plaintext
# @param key encryption key
# @param iv initialization vector
# @return ret[0]  - encrypted data
#         ret[1]  - next IV  
#         return NULL on error 
# @remmark
#    - CBC ciphertext stealing is described in http://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
##
function aes_cbc_cts_encrypt(data, key, iv)
{
  local_var blksz, cn, cn1, cn2, crypted, dlen, dn;
  local_var en1, keysize, m, p, pn, pn1, pos, ret, xn1;
  
  # Check params
  if(!data || !key || !iv) return NULL;

  keysize = strlen(key);
  if(keysize != 16 && keysize != 24 && keysize != 32)
    return NULL;

  blksz = 16;
  if(strlen(iv) != blksz) return NULL;

  dlen = strlen(data);

  # Pad plaintext to one block if needed
  if(dlen < blksz)
    data += crap(data:'\x00', length: blksz - dlen); 
  
  # Plain CBC if plaintext is exactly one block
  if(strlen(data) == blksz)
    return aes_cbc_encrypt(data:data, key:key, iv:iv);

  # Number of bytes in last block
  m = dlen % blksz;
  if (m == 0) m = blksz;

  # Last block of the plaintext
  pos = dlen - m;
  pn = substr(data, pos, pos + m - 1);

  # Second to last block of the plaintext
  pos -= blksz;
  pn1 = substr(data, pos, pos + blksz - 1);

  crypted = NULL;
  # Encrypt plaintext except for the last 2 blocks
  if( dlen > blksz + m)
  { 
    ret = aes_cbc_encrypt(data:substr(data, 0, pos - 1) , key:key, iv:iv);
    if(isnull(ret)) return NULL;
    
    cn2 = ret[1];
    crypted = ret[0];
  }
  # Plaintext is 2 blocks; use iv for cn2
  else cn2 = iv;
  
  # Chain and encrypt the second-to-last plaintext block 
  xn1 = xor(in1: pn1, in2: cn2);
  ret = aes_cbc_encrypt(data:xn1, key:key, iv:crap(data:'\x00',length: blksz)); 
  if(isnull(ret))   return NULL;
  en1 = ret[0];
  
  # m bytes of the encrypted second-to-last block is the last ciphertext block 
  cn = substr(en1, 0, m - 1);

  # Steal (blksz - m) bytes from the second-to-last block to form a complete last plaintext block
  p = pn + crap(data:'\x00', length: blksz - m);
  dn = xor(in1: en1, in2: p);

  # Encrypt the now complete, last plaintext block and make the output as the second-to-last ciphertext block
  ret = aes_cbc_encrypt(data:dn, key:key, iv:crap(data:'\x00',length: blksz)); 
  if(isnull(ret))   return NULL;
  cn1 = ret[0];

  # Append the last two, re-arranged ciphertext blocks 
  ret[0] = crypted + cn1 + cn;
  ret[1] = cn1; 

  return ret;

}

##
# Decrypts data using AES in CBC Ciphertext Stealing mode
# 
# @param data ciphertext
# @param key encryption key
# @param iv initialization vector
# @return ret[0]  - decrypted data
#         ret[1]  - next IV  
#         return NULL on error 
# @remmark
#    - CBC ciphertext stealing is described in http://en.wikipedia.org/wiki/Ciphertext_stealing#CBC_ciphertext_stealing
##
function aes_cbc_cts_decrypt(data, key, iv)
{
  local_var blksz, c, cn, cn1, cn2, decrypted, dlen, dn;
  local_var en1, keysize, m, pn, pn1, pos, ret, xn, xn1;

  # Check params
  if(! data || !key || !iv) return NULL;
  
  keysize = strlen(key);
  if(keysize != 16 && keysize != 24 && keysize != 32)
    return NULL; 

  blksz = 16;
  if(strlen(iv) != blksz) return NULL;
 
  dlen = strlen(data);

  # Ciphertext MUST be at least <blksz> bytes
  if(dlen < blksz) return NULL;

  # Plain CBC is used if ciphertext size if exactly one block 
  if(dlen == blksz)
    return aes_cbc_decrypt(data:data, key:key, iv:iv);

  # Number of bytes in last block
  m = dlen % blksz;
  if (m == 0) m = blksz;

  # Last block of the ciphertext
  pos = dlen - m;
  cn = substr(data, pos, pos + m - 1);

  # Second-to-last block of the ciphertext
  pos -= blksz;
  cn1 = substr(data, pos, pos + blksz - 1);


  decrypted = NULL;
  # Decrypt ciphertext except for the last 2 blocks
  if( dlen > blksz + m)
  { 
    ret = aes_cbc_decrypt(data:substr(data, 0, pos - 1) , key:key, iv:iv);
    if(isnull(ret)) return NULL;
    
    cn2 = ret[1];
    decrypted = ret[0];
  }
  # Ciphertext is 2 blocks; use iv for cn2
  else cn2 = iv;

  ret = aes_cbc_decrypt(data:cn1, key:key, iv:crap(data:'\x00',length: blksz)); 
  if(isnull(ret))   return NULL;
  dn = ret[0];
  c = cn + crap(data:'\x00', length: blksz - m);
  xn = xor(in1: dn, in2: c);
  pn = substr(xn, 0, m - 1);
  if(m < blksz ) 
    en1 = cn + substr(xn, m, blksz - 1);
  else
    en1 = cn;
    
  ret = aes_cbc_decrypt(data:en1, key:key, iv:crap(data:'\x00',length: blksz)); 
  if(isnull(ret))   return NULL;
  xn1 = ret[0];
  pn1 = xor(in1: xn1, in2: cn2);
  ret[0] = decrypted + pn1 + pn;
  ret[1] = cn1; 

  return ret;
}

#############################################################
# Functions to support computing UMAC
#   Message Authentication Code using Universal Hashing
#
#  https://tools.ietf.org/html/rfc4418
#############################################################

##
# Compute a MAC using universal hashing with an AES 128 cipher
# to generate pseudorandom keys and pads.
#
# @param <data>       The data to encrypt.
# @param <nonce>      A token unique to each derivation over the life
#                     of a key.
# @param <key>        An encryption key.
# @param <length:int> Length in bits of the tag to generate.
#
# @return A message authentication code
##
function umac_128(data, nonce, key, length)
{
  var tag = umac_uhash(message:data, key:key, taglen:length);
  var pad = umac_pad_derive(key:key, nonce:nonce, length:length);

  if(isnull(tag) || isnull(pad))
    return NULL;

  if(strlen(tag) != strlen(pad) || strlen(tag) != length)
    return NULL;

  var i;
  var result = '';
  for(i = 0; i < length; i+=4)
  {
    result += mkdword(getdword(blob:tag, pos:i) ^ getdword(blob:pad, pos:i));
  }

  return result;
}

##
# Compute the Universal Hash of a message given a key.
#
# @param <message:string> The message to hash.
# @param <key:string>     An encryption key used to generate a unique hash.
# @param <taglen:int>     The length of the desired hash, either 4, 8, 12 or 16 bytes.
#
# @return A universal hash of the message using the supplied key of the desired length.
##
function umac_uhash(message, key, taglen)
{
  local_var l1_iter_key, l2_iter_key, l3_iter_key1, l3_iter_key2;
  local_var i, k64;

  var iters = taglen / 4;
  var l1key = umac_key_derive(in_key:key, index:1, numbytes: 1024 + (16 * (iters - 1)));
  var l2key = umac_key_derive(in_key:key, index:2, numbytes: 24 * iters);
  var l3_key1 = umac_key_derive(in_key:key, index:3, numbytes: 64 * iters);
  var l3_key2 = umac_key_derive(in_key:key, index:4, numbytes: 4 * iters);

  var result = '';

  for(i = 0; i < iters; i++)
  {
    l1_iter_key = substr(l1key, i * 16, i * 16 + 1023);
    l2_iter_key = substr(l2key, i * 24, i * 24 + 23);
    l3_iter_key1 = substr(l3_key1, i * 64, i * 64 + 63);
    l3_iter_key2 = substr(l3_key2, i * 4, i * 4 + 3);

    var tag_segment = umac_l1(key:l1_iter_key, message:message);
    if(strlen(message) <= strlen(l1_iter_key))
    {
      tag_segment = crap(data:'\x00', length:8) + tag_segment;
    }
    else
    {
      k64 = make_int64(low:getdword(blob:l2_iter_key, pos: 4) & 0x01ffffff,
                       high:getdword(blob:l2_iter_key, pos: 0) & 0x01ffffff);

      tag_segment = umac_poly_64(key:k64, m_hash:tag_segment);
      tag_segment = mkdword(tag_segment[1]) + mkdword(tag_segment[0]);
      tag_segment = crap(data:'\x00', length: 16 - strlen(tag_segment)) + tag_segment;
    }

    tag_segment = umac_l3(in_key1:l3_iter_key1, in_key2:l3_iter_key2, l2hash:tag_segment);

    result += mkdword(tag_segment);
  }

  return result;
}

##
# Computes an NH hash over the message using the given key.
# Ref: RFC4418 Sec 5.2.2
# https://tools.ietf.org/html/rfc4418#page-13
#
# @param <message:string>  The message to hash
# @param <key:string>      The hash key
# @return Returns a string
##
function umac_nh(message, key)
{
  local_var t, result, i, m_plus_k, m_plus_k2, m1, m2, k1, k2;

  result = make_int64(low:0x00000000, high:0x00000000);
  t = strlen(message) / 4;
  i = 0;

  while(i < t)
  {
    m1 = getdword(blob:message, pos:i*4, order:BYTE_ORDER_LITTLE_ENDIAN);
    k1 = getdword(blob:key, pos:i*4);
    m2 = getdword(blob:message, pos:(i+4)*4, order:BYTE_ORDER_LITTLE_ENDIAN);
    k2 = getdword(blob:key, pos:(i+4)*4);
    m_plus_k = make_int64(low:m1 + k1, high:0x00000000);
    m_plus_k2 = make_int64(low:m2 + k2, high:0x00000000);
    result = add64(result, mult64(m_plus_k, m_plus_k2));

    m1 = getdword(blob:message, pos:(i+1)*4, order:BYTE_ORDER_LITTLE_ENDIAN);
    k1 = getdword(blob:key, pos:(i+1)*4);
    m2 = getdword(blob:message, pos:(i+5)*4, order:BYTE_ORDER_LITTLE_ENDIAN);
    k2 = getdword(blob:key, pos:(i+5)*4);
    m_plus_k = make_int64(low:m1 + k1, high:0x00000000);
    m_plus_k2 = make_int64(low:m2 + k2, high:0x00000000);
    result = add64(result, mult64(m_plus_k, m_plus_k2));

    m1 = getdword(blob:message, pos:(i+2)*4, order:BYTE_ORDER_LITTLE_ENDIAN);
    k1 = getdword(blob:key, pos:(i+2)*4);
    m2 = getdword(blob:message, pos:(i+6)*4, order:BYTE_ORDER_LITTLE_ENDIAN);
    k2 = getdword(blob:key, pos:(i+6)*4);
    m_plus_k = make_int64(low:m1 + k1, high:0x00000000);
    m_plus_k2 = make_int64(low:m2 + k2, high:0x00000000);
    result = add64(result, mult64(m_plus_k, m_plus_k2));

    m1 = getdword(blob:message, pos:(i+3)*4, order:BYTE_ORDER_LITTLE_ENDIAN);
    k1 = getdword(blob:key, pos:(i+3)*4);
    m2 = getdword(blob:message, pos:(i+7)*4, order:BYTE_ORDER_LITTLE_ENDIAN);
    k2 = getdword(blob:key, pos:(i+7)*4);
    m_plus_k = make_int64(low:m1 + k1, high:0x00000000);
    m_plus_k2 = make_int64(low:m2 + k2, high:0x00000000);
    result = add64(result, mult64(m_plus_k, m_plus_k2));

    i += 8;
  }

  return result;
}

##
# Compute a polynomial hash over a message using the supplied key.
#
# This is in support of umac-128-etm@openssh.com.  SSH packets above 32K should be
# broken up and individually hashed so we should not require the poly_128 variant.
#
# A direct adaptation from  umac.c:
#
#   Version 0.92 of draft-krovetz-umac-07.txt -- 2006 February 21
#
#   For a full description of UMAC message authentication see the UMAC
#   world-wide-web page at http://www.cs.ucdavis.edu/~rogaway/umac
#   Please report bugs and suggestions to the UMAC webpage.
#
#   Copyright (c) 1999-2006 Ted Krovetz
#
#  Permission to use, copy, modify, and distribute this software and
#  its documentation for any purpose and with or without fee, is hereby
#  granted provided that the above copyright notice appears in all copies
#  and in supporting documentation, and that the name of the copyright
#  holder not be used in advertising or publicity pertaining to
#  distribution of the software without specific, written prior permission.
#
#  Comments should be directed to Ted Krovetz (tdk@acm.org)
#
# @param <m_hash:string> A message to be hashed
# @param <key:string>    A key
#
# @return Returns an computed polynomial hash.
##
function umac_poly_64(m_hash, key)
{
  #2 ^ 64 - prime
  var offset = make_int64(low:59, high:0);

  var n = strlen(m_hash);
  var result = make_int64(low:0x00000001, high: 0x00000000);
  var i, x, t, data;
  for(i = 0; i < n; i += 8)
  {
    var key_lo = make_int64(low:key[0]);
    var key_hi = make_int64(low:key[1]);
    var res_lo = make_int64(low:result[0]);
    var res_hi = make_int64(low:result[1]);

    x = add64(mult64(key_hi, res_lo), mult64(key_lo, res_hi));

    result = add64(mult64(key_hi, res_hi), make_int64(low:x[1]));
    result = mult64(result, offset);
    result = add64(result, mult64(key_lo, res_lo));

    t = make_int64(high:x[0], low:0x00000000);
    result = add64(result, t);

    if(unsigned_lt64(result, t))
      result = add64(result, offset);

    data = make_int64(low:getdword(blob:m_hash, pos:i+4), high:getdword(blob:m_hash, pos:i));

    result = add64(result, data);

    if(unsigned_lt64(result, data))
      result = add64(result, offset);
  }

  return result;
}


##
# Compute the modulus of the input relative to P36, the highest
# 36-bit prime number without using division.
#
# @param <val:string> The input value.
# @return Returns the input value modulo P36
##
function mod_p36(val)
{
  var p36 = make_int64(high:0x0000000f, low: 0xfffffffb);
  var rem = rshift64(val, 36);
  val = make_int64(high:val[1] & 0x0000000f, low:val[0]);
  val = add64(val, mult64(rem, make_int64(low:5)));
  if(unsigned_gt64(val, p36))
    val = sub64(val, p36);

  return val;
}


##
# Compute a L3 Hash value for universal hashing.
# 
# @param <in_key1:string> The first key.
# @param <in_key2:string> The second key.
# @param <l2hash:string> The L2 Hash value.
#
# Returns the computed L3 Hash
##
function umac_l3(in_key1, in_key2, l2hash)
{
  var i, m_i, k_i;
  var result = make_int64(low:0);
  for(i = 0; i < 8; i++)
  {
    k_i = make_int64(high:getdword(blob:in_key1, pos:i * 8),
                     low:getdword(blob:in_key1, pos:i*8 + 4));
    m_i = make_int64(low:getword(blob:l2hash, pos:i*2));
    k_i = mod_p36(val:k_i);
    result = add64(result, mult64(m_i, k_i));
  }

  result = mod_p36(val:result);
  return result[0] ^ getdword(blob:in_key2, pos:0);
}


##
# Universal hashing key derivation (stretching).  Takes a hash
# key and generates a pseudo-random number from that hash using
# AES encryption.  Provides sufficient keying material for the
# universal hashing NH algorithm.
#
# @param <in_key:string> The provided key.
# @param <index:int> An additional specifier.
# @param <numbytes:int> The number of key bytes to produce.
# @return A pseudo-random hashing key.
##
function umac_key_derive(in_key, index, numbytes)
{
  local_var i, result, temp, data;

  #Block length for aes-128-ctr
  var block_len = 16;

  var n = numbytes / block_len;
  if(numbytes % block_len > 0)
    n++;

  result = '';
  var iv = crap(data:'\x00', length: block_len);
  data = crap(data:'\x00', length: block_len);

  for(i = 0; i < n; i++)
  {
    data[block_len - 9] = mkbyte(index);
    data[block_len - 1] = mkbyte(i + 1);
    temp = aes_cbc_encrypt(iv:iv, data:data, key:in_key);
    result = result + substr(temp[0], 0, block_len - 1);
  }

  return substr(result, 0, numbytes - 1);
}

##
# This function takes a key and a nonce and returns a pseudorandom pad
# for use with creating UMAC tags.
#
# @param <key:string> The key.
# @param <nonce:string> The nonce.  This should be different for every MAC tag.
# @param <length:int> The length of the desired pad.
# @return Returns a pseudo-random pad of <length> bytes.
##
function umac_pad_derive(key, nonce, length)
{
  local_var index, low_nonce;

  #Block length for aes-128-ctr
  var block_len = 16;
  var key_len = block_len;
  if(length > key_len)
    key_len = length;

  #Extract the low bits from the nonce.  Save and zero them.
  if(length <= 8)
  {
    low_nonce = getdword(blob:nonce, pos:4);
    index = low_nonce % (block_len / length);
    nonce = substr(nonce, 0, 3) + mkdword(low_nonce ^ index);
  }

  nonce = nonce + crap(data:'\x00', length:block_len - (strlen(nonce) % block_len));

  var result = umac_key_derive(in_key:key, index:0, numbytes:key_len);
  var iv = crap(data:'\x00', length: block_len);
  var tag = aes_cbc_encrypt(iv:iv, data:nonce, key:result);
  tag = tag[0];

  if(length <= 8)
    return substr(tag, index * length, index * length + (length - 1));

  return substr(tag, 0, length - 1);
}


##
# Performs a dword-wise big endian version of a big number as described
# in RFC-4418 for UMAC computation.
#
# @param <bignum:string> A big number in little-endian form.
# @return Returns a big-endian version of the input.
##
function umac_endian_swap(bignum)
{
  local_var n, i, w1, w2, w3, w4;

  #Only swap if little-endian
  if(get_byte_order() == BYTE_ORDER_BIG_ENDIAN)
    return bignum;

  #Prereq - bignum length is divisible by 4
  if(strlen(bignum) % 4 > 0)
    return NULL;

  n = strlen(bignum) / 4;

  for(i = 0; i < n; i++)
  {
    w1 = bignum[i * 4];
    w2 = bignum[i * 4 + 1];
    w3 = bignum[i * 4 + 2];
    w4 = bignum[i * 4 + 3];
    bignum[i * 4] = w4;
    bignum[i * 4 + 1] = w3;
    bignum[i * 4 + 2] = w2;
    bignum[i * 4 + 3] = w1;
  }

  return bignum;
}

##
# Computes the L1Hash described in RFC-4418 in support of Universal
# Hashing.
#
# @param <key:string>    A hash key.
# @param <message:string A message to hash.
# @return Returns the L1Hash of the message using the key.
##
function umac_l1(key, message)
{
  local_var t, i, start, end, result, m_i, ulen, mlen, y, pad, padlen;

  #Key must be 1024 bytes
  if(strlen(key) != 1024)
    return NULL;

  t = (strlen(message) + 1023) / 1024;
  mlen = strlen(message);
  padlen = 32 - (mlen % 32);
  pad = crap(data:'\x00', length:padlen);
  if(t == 0)
  {
    y = umac_nh(key:key, message:pad);
    return mkdword(y[1]) + mkdword(y[0]);
  }

  result = '';
  for(i = 0; i < t; i++)
  {
    start = 1024 * i;
    end = start + 1024;
    if(end > mlen)
    {
      end = mlen;
      m_i = substr(message, start, end - 1) + pad;
    }
    else
    {
      m_i = substr(message, start, end - 1);
    }

    ulen = make_int64(low:(end - start) * 8, high:0x00000000);
    m_i = umac_endian_swap(bignum:m_i);
    if(isnull(m_i))
      return NULL;

    y = add64(umac_nh(key:key, message:m_i), ulen);
    result += mkdword(y[1]) + mkdword(y[0]);
  }
  return result;
}

