#TRUSTED 99552fb2059b2fff80ff296e653585d2fbfe8a6820c08a3c245769ac31323232a1d64381633cdb5ba85c9688173ab48beb94e0a8f4c3c3bfcaf317fe09bb532c42a35be2971fef297b5a077a930e8f12edd4fd20acb9893887c12e7f9d3f7959f097218a7cdb978600c2c5b5aa09b72eb9f2bc919f63546597d0465d732f5a2336a3be30c4cd8ba56e9765c368f9e516812790207db12ca4e6d767e5b618f06789129740bdb50d19cacf4f624054ad1461ae3b0bc94f377bb59cfa38525794e28f7d69d18820523d34a122227c6544557a9cecd58faae7f70bd3f0fec4b6fa9b4d5e1bc636f157d8cc0fdfa7336a556d426c274d33cc87de556b15ab7cb0060a3a82b09903d2550931440d2e5447ed97ee6c21510b51e2fa72d5fe0dde48ab6bcc5352eb24ccd3eea03643f6d5e8d74a8f0529b43ba1cf0de7bbae25289fa76e59790dd018371caab9d45cce72cac025cac160e6cdc2e9f36b88ee146d875da5e633abafafb19f4be2f1effb7696435c001aaae99c4d3aae55977240280c98b680bab96665703cc01bbd7e0cedce0ba91cdc78f0abfd211a9a33b10941290a5a9b5d21e60854c09fd26e4f74591f314e623573ad56ea75fe1406d4729406037d4c7a5d21a394052c2b4dc394e671ed463b1d0d21356d20d2ef4b21c595c3053ef7cc5af04cf86bca01f9fd64bb2a792967f29aebf6d60deb15cc9b4d3c29f35e
# -*- Fundamental -*-
#
# (C) WebRAY Network Security, Inc.
#
# uri_func.inc
# Revision: 1.11
#
# @NOGPL@
#


##
# url_hex2raw is identical to hex2raw from misc_func.inc apart from its name.
##
function url_hex2raw(s)
{
 local_var i, j, ret, l;

 s = chomp(s);	# remove trailing blanks, CR, LF...
 l = strlen(s);
 if (l % 2)
 {
  display("url_hex2raw: odd string: ", s, "\n");
  l--;
 }
 s = tolower(s);
 for(i=0;i<l;i+=2)
 {
  if(ord(s[i]) >= ord("0") && ord(s[i]) <= ord("9"))
        j = int(s[i]);
  else
        j = int((ord(s[i]) - ord("a")) + 10);

  j *= 16;
  if(ord(s[i+1]) >= ord("0") && ord(s[i+1]) <= ord("9"))
        j += int(s[i+1]);
  else
        j += int((ord(s[i+1]) - ord("a")) + 10);
  ret += raw_string(j);
 }
 return ret;
}


##
# URL decodes the given string
#
# This function assumes 'estr' is encoded per RFC 2396 / 2732 and decodes it.
#
# @param estr URL encoded string
# @return decoded version of "estr"
##
function urldecode(estr)
{
  local_var ch, len, i, str;

  str = "";
  len = strlen(estr);

  i = 0;
  while (i < len)
  {
    ch = estr[i];
    if (ch == "+") ch = " ";

    if (ch == "%" && substr(estr, i+1, i+2) =~ "^[0-9a-fA-F]{2}$")
    {
      # nb: url_hex2raw() expects only lowercase hex digits!
      str += url_hex2raw(s:tolower(substr(estr, i+1, i+2)));
      i += 2;
    }
    else str += ch;
    i++;
  }

  return str;
}


global_var HEX_LOWERCASE, HEX_UPPERCASE;

HEX_LOWERCASE = 1;
HEX_UPPERCASE = 2;

##
# URL encodes the given string
#
# 'str' is encoded per RFC 2396 / 2732
#
# @param str string to URL encoded
# @param unreserved a string containing characters that should not be encoded. this parameter
#        is optional - if no argument is provided, the default is used (alphanumeric and _.!~*'()-])
# @case_type if HEX_UPPERCASE, specifies hex of encoded characters should be upper case. otherwise, all hex is lowercase
#
# @return URL encoded version of "str"
##
function urlencode(str, unreserved, case_type)
{
  local_var ch, estr, len, i;

  estr = "";
  len = strlen(str);
  if (isnull(unreserved)) unreserved = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]";
  if (isnull(case_type)) case_type = HEX_LOWERCASE;

  for (i=0; i<len; i+=1)
  {
    ch = str[i];

    if (ch >< unreserved) estr += ch;
    # the rest are escaped.
    else
    {
      ch = hexstr(ch);
      if (case_type == HEX_UPPERCASE)
        ch = toupper(ch);
      estr += "%" + ch;
    }
  }

  return estr;
}
