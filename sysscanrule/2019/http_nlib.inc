#TRUSTED 2dc6744689df3153c417c8facfd569eef81c53eb21361f477cad60c4a77237c89d671d2b31a54e79600c3bd4b21c160c36e5acc6a29f58eaf372fd3d75599daaccc7eae8589aca7a09c5dd4fc0d1e26387869e778c837aed1bb3e1a4e60289edccee5670be0914cd1d2f6ef063db141b4406bbf61b2fb45df2474960be31993f155e496bd1976909bb098057360fb7c1cb3fd082a34824003d4eab323399ae1765c21658e4d3c450f16a4079bc2fdb0ca414ac20d6c80abac2f62c485b00b1ddeaa62dc4c1165c43bc0cf1e989456342e2d638a413a0c0cda179f3bd0092808bdd008d3aad72339efee555c4375ee1f0fdf9cc10c34139d35ec64cb3e57c410f5b6d5da8bf981bfc2e161ed37fb710dbff315b910ebcc98ecb0b0b9970fc3bcf23836d9651996ce3c01723d92df4f92500ea7cfcbab51d2ad99650ba0847b83c1fde89fc949dfaf1964078f4e9cc88be89d7d2227e3af883549d0eeaa0197a2ff2d0aa4a28f8c3a4a54b6799fe936c5f271598d1373840a1eec1810d25b028069a0e547bb7c73b6a6826da8b2179ed52e0654f43108006534882d3cf001858b0f2affe2b9ac50f183be806bc89bc8476e898758a4ccc08b06ff4befb859747e0cf261cff5d2621d062bb6860735f6de0b853ba7776c537eebed20940fda65e5a1eb976d6b826d199ed57faa2ce1d26fba078a1eb637e083451722be9984e936a
# -*- Fundamental -*-
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# http_nlib.inc
# Revision: 1.00

#pragma static
include("global_settings_nlib.inc");

function parse_http_headers(status_line, headers, sep)
{
  local_var	v, line, s, k, err;

  if (isnull(headers)) return NULL;

  v = make_array();
  err = 0;
  foreach line (split(headers, keep: 0))
    if (strlen(line) > 0)
    {
      s = pregmatch(string: line, pattern: '^([A-Z_][A-Z0-9_-]*)[ \t]*:[ \t]*(.*)$', icase: 1);
      if (isnull(s))
      {
        debug_print('parse_http_headers: cannot parse HTTP header -> ', line);
        err ++;
        continue;
      }
      k = tolower(s[1]);
      if (isnull(v[k]))
        v[k] = s[2];
      else
      {
        if (isnull(sep))
        {
          debug_print('parse_http_headers: repeated HTTP header ', s[0], '\n');
          sep = ',';
        }
        v[k] += sep + s[2];
      }
      # No use to call chomp(), split(keep: 0) already removed \r\n
    }
  if (status_line)
  {
    v['$status'] = chomp(status_line);
    k = pregmatch(string: status_line, pattern: '^HTTP/[01]\\.[01]+ +([0-9]+) ');
    if (! isnull(k))
      v['$code'] = int(k[1]);
    else
    {
      debug_print('parse_http_headers: cannot parse status line -> ', status_line);
      err ++;
    }
  }
  if (err > 0) v['$errors'] = err;
  return v;
}

