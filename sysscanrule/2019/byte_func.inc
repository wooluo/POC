#TRUSTED 06638e6c86de0aef02d98038c86c64a029bc73cae735daed2632d1795cb381601f48ea821096689e97e8a5a51b50d9c844ef98ac226397aeb5d6fcefb9753c0edc3bfb8618cf8ea54b4edd5ec1495cce091339c9f5e39a52b236ca3d544963cfa0e2ad59c6f1dd0970caf3f2202437ade7f6db66b47b220d91188815afdfd156b24aaad444178ac72a2365c372376051af03c59511e38f06d0526b41c3f72d744e832b59e744ffc5727e446da20355d2005569612dcddcd6ccff82feea113b11704bf24170dfa3affc12e355387030a686382fbe148544ae1eaec02848f18b6606324d394cd1149ac07cd36e387bd3adba1ba008b89ab9f2642554ba3c2773eaca39f368abe6a13a2fbd401fcaa578c85463fe8ba9ef59be3b918d266a453b90a8682824b09e055ab6362ad293ebe67756d0ea92feeff04f1de64a8488319da78da0bff61f9c64d55152d21a44a6a65d4aee97c01a548b1778aa4ceb2a1609586ad28517a3f5eada1620bd6a0636052d5e1f9d5b03eac933ac10940404ba92fd7d13f5a5e1a98d330ca62bcff2eb98062c7c4a504a59aa700bfc5969d912762ebb9a7a043030fda9820a0d608f65122dd9b3fe7934018a91ef1867ba1cbc51edf43df01ec31c226fbe0593985a919c7947486e88270af3600ceabda682361522a2beba1e1aab3220f57d15dc420085be33c0c5e5047f3cc17ccc4b367e1ea7db
###
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security Inc.
#
# @NOGPL@
#
# byte_func.inc
#
# Revision: 1.11
##

#pragma static
include("global_settings_nlib.inc");

######################################################################
# Byte Order Functions
######################################################################

global_var BYTE_ORDER_BIG_ENDIAN, BYTE_ORDER_LITTLE_ENDIAN;
BYTE_ORDER_BIG_ENDIAN = 1;
BYTE_ORDER_LITTLE_ENDIAN = 2;

global_var __byte_order_index, __byte_order_stack;
__byte_order_index = 0;
__byte_order_stack = make_list(BYTE_ORDER_BIG_ENDIAN);

function get_byte_order()
{
  return __byte_order_stack[__byte_order_index];
}

function pop_byte_order()
{
  # Never pop our default byte order.
  if (__byte_order_index == 0)
    return;

  __byte_order_stack[__byte_order_index--] = NULL;
}

function push_byte_order()
{
  __byte_order_stack[++__byte_order_index] = _FCT_ANON_ARGS[0];
}

function set_byte_order()
{
  # Overwrite all byte order settings.
  __byte_order_index = 0;
  __byte_order_stack = make_list(_FCT_ANON_ARGS[0]);
}

######################################################################
# Byte Emission Functions
######################################################################

function mkpad()
{
  local_var l;

  l = _FCT_ANON_ARGS[0];
  if (isnull(l))
    l = 0;

  return crap(data:'\0', length:l);
}

function mkbyte()
{
  return raw_string(0xFF & _FCT_ANON_ARGS[0]);
}

function mkword(order)
{
  local_var l;

  l = _FCT_ANON_ARGS[0];


  if (isnull(order))
    order = get_byte_order();

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return raw_string((l >> 8) & 0xFF, l & 0xFF);
  else
    return raw_string(l & 0xFF, (l >> 8) & 0xFF);
}

function mkdword(order)
{
  local_var l;

  if (isnull(order))
    order = get_byte_order();

  l = _FCT_ANON_ARGS[0];

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return raw_string(
      (l >> 24) & 0xFF,
      (l >> 16) & 0xFF,
      (l >>  8) & 0xFF,
      l & 0xFF
    );
  else
    return raw_string(
      l & 0xFF,
      (l >>  8) & 0xFF,
      (l >> 16) & 0xFF,
      (l >> 24) & 0xFF
    );
}

######################################################################
# Byte Parsing Functions
######################################################################

function getbyte(blob, pos)
{
  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(pos))
    pos = 0;

  if (pos < 0)
    return NULL;

  if (pos + 1 > strlen(blob))
    return NULL;

  return ord(blob[pos]);
}

function getword(blob, order, pos)
{
  local_var s;

  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(order))
    order = get_byte_order();

  if (isnull(pos))
    pos = 0;

  if (pos < 0)
    return NULL;

  if (pos + 2 > strlen(blob))
    return NULL;

  s = substr(blob, pos, pos + 1);

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return ord(s[0]) << 8 | ord(s[1]);
  else
    return ord(s[0]) | ord(s[1]) << 8;
}

function getdword(blob, order, pos)
{
  local_var l, s;

  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(order))
    order = get_byte_order();

  if (isnull(pos))
    pos = 0;

  if (pos < 0)
    return NULL;

  if (pos + 4 > strlen(blob))
    return NULL;

  s = substr(blob, pos, pos + 3);

  if (order == BYTE_ORDER_BIG_ENDIAN)
    return
      ord(s[0]) << 24 |
      ord(s[1]) << 16 |
      ord(s[2]) <<  8 |
      ord(s[3]);
  else
    return
      ord(s[0]) |
      ord(s[1]) <<  8 |
      ord(s[2]) << 16 |
      ord(s[3]) << 24;
}

function getqword_shift(blob, order, pos, shift)
{
  local_var end, i, shift1, shift8, start, xx, yy;

  if (isnull(blob))
    blob = _FCT_ANON_ARGS[0];

  if (isnull(order))
    order = get_byte_order();

  if (isnull(pos))
    pos = 0;

  if (isnull(shift))
    shift = 0;

  if (pos < 0)
    return NULL;

  if (pos + 8 > strlen(blob))
    return NULL;

  if (shift < 0)
    return NULL;

  if (shift >= 64)
    return NULL;

  shift8 = shift / 8;
  shift1 = shift - 8 * shift8;

  yy = 0;
  xx = 0;

  if (order == BYTE_ORDER_BIG_ENDIAN)
  {
    start = 4 - shift8;
    if (start < 0)
      start = 0;

    for (i = start; i <= 7 - shift8; i++)
      xx = (xx << 8) | ord(blob[pos + i]);

    if (shift < 32)
      yy = ord(blob[pos + 3 - shift8]);
  }
  else
  {
    end = shift8 + 3;
    if (end > 7)
      end = 7;

    for (i = end; i >= shift8; i--)
      xx = (xx << 8) | ord(blob[pos + i]);

    if (shift < 32)
      yy = ord(blob[pos + shift8 + 4]);
  }

  if (shift1 > 0)
    yy <<= (8 - shift1) + 24;
  else
    yy = 0;

  xx >>>= shift1;

  return (xx | yy);
}

##
# Extracts printable strings from a buffer.
#
# @param  data   buf        Buffer of data to extract strings from.
# @param  int    len        OPTIONAL Length of buffer to search,
#                           defaults to 1024.
# @param  int    min_len    OPTIONAL Minimum length of printable chars
#                           to be considered a string, defaults to 4.
# @param  bool   null_term  OPTIONAL whether or not a string must be
#                           NULL terminated to be considered a string,
#                           defaults to FALSE.
#
# @return list  of strings
##
function get_strings(buf, len, min_len, null_term)
{
  local_var offset, char, string;
  local_var strings;

  strings = make_list();
  string = '';

  if (isnull(buf)) buf = _FCT_ANON_ARGS[0];
  if (isnull(buf))
  {
    err_print("get_strings(): missing required arg 'buf");
    return strings;
  }

  # Set default values.
  if (isnull(len)) len = 1024;
  if (isnull(min_len)) min_len = 4;
  if (isnull(null_term)) null_term = FALSE;

  # Ensure we don't read past the end of the buffer.
  if (len(buf) < len) len = len(buf);

  # Iterate through the buffer up to the max length.
  for (offset = 0; offset < len; offset++)
  {
    # If the current byte is printable add it to the current string.
    # Otherwise if the current byte is the NULL terminator and the
    # string is above the minimum length, add the string to the list
    # of strings.
    char = getbyte(blob:buf, pos:offset);
    if (is_ascii_printable(raw_string(char))) string += raw_string(char);
    else
    {
      if ((!null_term || char == 0) && len(string) >= min_len) strings = make_list(strings, string);
      string = '';
    }
  }

  # Check if we have a valid string at the end of our buffer.
  if (len(string) >= min_len) strings = make_list(strings, string);

  return strings;
}
