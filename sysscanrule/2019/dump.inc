#TRUSTED 79219ff6fa6546af889c608992054fa827742ae4c65bd4a8792e91ce8ceac35eb76cab3a522b315db0e06184cb67db533d360668a477493b131cb9bd3a6806de5f77678cb9ea7e9256b3dd1ace98ac1f45a117664834fa54f60a2648d3d169fb90fcc7cf21051471f849b14bec68244d7e4d2728d96992074d5a4ebf98c8b36f359339549ae2df5648c8f76efc9b88c419292ce46c571984f68daf8fbd6bdf664ada3a48cb8f645ab641ce52a53a5d9e4004c21133928fc7672b4fea6ed34c06a66601851314bae76eaa7a96bf39e406801f51ecf0f84fd79927692989da6d285206267c64e7048784496dd70360fd687cad873b148116c8787fbf0293c305a8a81185ec0b8fbc11dacae6c224c4e6b0faaf037ff5667277e5dfee3a0c5cf2d3c5b623f4ffc9b0f04aca4e3d5fddd8e52fde4f9077496173af33b31ea0084f3e4db5ed5af0ed24dce1205039a50b979002c42a750e48d5d315bd37bc8dc8ee7a0c0c92c6eaf739c28add5cf5b55c22a69390bc02c813d94eec4d32af6f77c6f3d480f77e84c17958f8b5d93f54fe2c791130a4ad91afd0800f2abf78cec7f968a658ea714cffd9f19214cf65fe3ad02f26ba274d55ae9821b7ef7c74b1c18ba1d3e1ace78caccb2915d0112da6df2c05c124ab673d968c18c1b11014acee94e8a95f7aa4e43d1d689e867a65f4c0a7e19b3a9dd51c5fbedfa5d3ae1ea6b8b89a
###
# -*- Fundamental -*-
#
# (C) WebRAY Network Security, Inc.
# 
#
# An earlier iteration of this file was written by George Dagousset (2002)
#
# This include file is released under the terms of the GPLv2
#
# This include file has functions used to generate a hex dump of data
# 
# dump.inc
# Revision: 1.13
###

##
# Generates the hex line number prefix for line "line" of "linenumber".
#
# This function is used by hexdump() to generate the line numbering for its output
#
# For example, the 0th line of 5 will result in "0x00: "
# The 5th line of 500 will result in "0x0040: "
# The amount of padding each offset receives depends on "linenumber" - numbers
# will be padded out (if necessary) so they are the same length as the largest
# possible number.
#
# @line the number of the current line
# @linenumber the total number of lines
# @return a line number prefix to be used by hexdump()
##
function line2string (line, linenumber)
{
 local_var tmp, pos;

 line = line*16;
 tmp = raw_string (
	(line >> 24) & 0xFF,
	(line >> 16) & 0xFF,
	(line >> 8) & 0xFF,
	(line ) & 0xFF
	);

 if (linenumber < 256)
   pos = 3;
 else if (linenumber < 65536)
   pos = 2;
 else if (linenumber < 16777216)
   pos = 1;
 else
   pos = 0;

 return "0x" + toupper(hexstr(substr (tmp, pos, 3))) + ": ";
}


##
# Determines if the given character is ASCII suitable to be displayed in hexdump()
# output (0x20 through 0x7e inclusive).  This excludes control characters such as
# tab and newline.
#
# @param c character to check
# @return TRUE if "c" is between 0x20 and 0x7e inclusive,
#         FALSE otherwise
##
function isprint (c)
{
 if ( (ord(c) >= 0x20) && (ord(c) <= 0x7E) )
   return TRUE;

 return FALSE;
}


##
# does a hex dump of sixteen bytes of data
#
# @str hex data to dump
# @line the number of the line being dumped
# @totallen the total number of lines in the dump
# @return a hex dump of "hex" with a line number prefix
##
function dump_line_and_data(str, linenb, totallen)
{
  local_var	j, len, c, line, data;

  line = line2string (line: linenb, linenumber: totallen);
  len = strlen(str);

  for (j = 0; j < 16; j++)
  {
   if (j < len )
   {
    line = line + " " + toupper(hexstr(str[j]));
    c = str[j];
    if (isprint (c:c))
      data += c;
    else
      data += ".";
   }
   else
   {
    line += "   ";
    data += " ";
   }
  }
  return line + '    ' + data + '\n';
}

##
# does a hex dump of the given data
#
# @param ddata the data to dump
# @return a hex dump of "ddata"
##
function hexdump (ddata)
{
 local_var tmp, i, linenumber, len;
 local_var	same_str_cnt, prev_str, prev_adr, str;

 len = strlen(ddata);
 linenumber = len / 16;

 prev_str = NULL; same_str_cnt = 0; prev_adr = 0;

 for (i = 0; i <= linenumber; i++)
 {
  str = substr(ddata, i*16, i*16+15);
  if (! isnull(prev_str))
  {
    if (str == prev_str)
    {
      same_str_cnt ++;
      continue;
    }
#    else if (same_str_cnt == 1)
#    {
#      tmp += dump_line_and_data(str: prev_str, linenb: i-1, totallen: len);    
#    }
#    else if (same_str_cnt > 1)
    else if (same_str_cnt >= 1)
      tmp += '*\n';    
  }
  prev_str = str; same_str_cnt = 0;
  tmp += dump_line_and_data(str: str, linenb: i, totallen: len);
 }

 if (same_str_cnt > 0)	# Should not happen!
   tmp += dump_line_and_data(str: prev_str, linenb: i-1, totallen: len);
 return tmp;
}
 

##
# Displays a hex dump of the given data
#
# @dtitle a string title to give to the hex dump
# @ddata the data to dump
##
function dump( dtitle, ddata )
{
 if( ! isnull( dtitle ) )
	display('---[ ' + dtitle + ' ]---\n' );


 display(hexdump(ddata:ddata));
}

##
# A debug function that recursively prints out a table.
#
# @param table The table to print.
# @param indent [optional] Used internally for recursion.
##
function dump_table(table, indent)
{
  local_var key;

  if(!indent)
    indent = 0;

  if(typeof(table) == 'array')
  {
    foreach key(keys(table))
    {
      if(typeof(table[key]) == 'array')
      {
        display(crap(data:'\t', length:indent), key, ':\n');
        dump_table(table:table[key], indent:indent+1);
      }
      else
      {
        display(crap(data:'\t', length:indent), key, ': ', table[key], '\n');
      }
    }
  }
  else
  {
    display(crap(data:' ', length:indent), '\n');
  }
}

