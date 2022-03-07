#TRUSTED 0185eb9ea1084952c845bd23abc3606f9f7a5c1399b29032fa7c10df07fc073358176f6efdbdbeb914ababa33d6b7b88d69a22b57b397b19210d08f6a8f5377c765ecae8a731b8714faa02e09f8afc2a6c8bda5600d69488b309d59da56e64b01e78a4353331800864b29ec5295871800a758c203c3218915651e0b488c77a3e7ea4b771a853ac0a82bb6af20c5e6f9defc7c1e698a8f13ef6817f87cd574ac6190127e3d8f54b41061931af91d212ab46a295fdcb6a7fb67e4c17ff7cff77da9c6f3bcb6476339ecd802b511a766318b662c1deaf547300384b47031b7e498044929af987fbfb9639c7077acddcc7cb27788d83955f85216bab7063d003286e44b9d06fb0b987164c04d52a9cb164f223376f7cbda3d61061a2e87031a355364e2a3b054cecc609a10ad10dab053644306ee7c8a41d96a230002bf3cbc0f505be08378a10a7cd89a8b0a08134696a72821801d5df738ec3fba7674a512d408a2d8b5aa8bca984e696d0cdd90888a52b8e33d016a6981c94640c3bfcc41b92d2b602dedd56f349d838144e67c572df35bc51ee3ad717246620dfdeee05f8aed0c7bce8369516429b7478074fbecd6f0748851d349aca8a82cb41a718f5db6265c22fa7ee04f0d74b5c639cfd25ccbb1340a13d86ddb7905da6154196b2474cbce96d2c21cfe6127ffcda1e2ab95646491802cc701c210c11f2ccb10174f7d9aa
#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
#

include("audit_nlib.inc");
include("global_settings_nlib.inc");
include("misc_func_nlib.inc");

app_name = "OpenSSL";

# compares two OpenSSL versions. each version must be all numeric and
# can end with a letter, optionally with a beta version number
# e.g. 0.9.6e
# or   1.0.0-beta1
#
# Additional text like -fips, -pre, or -rhel5 is erased & ignored currently.
#
# args: ver, fix - versions to compare
#
# returns -1	if ver < fix
#          0	if ver == fix
#          1	if ver > fix
#	   NULL	error, invalid format
#
function openssl_ver_cmp(ver, fix, same_branch, is_min_check)
{
  local_var	pat, vv, ff, i, v, f;

  # Do not anchor on the right, version might be "0.9.8e-fips-rhel5"
  pat = '^([0-9]+)\\.([0-9]+)\\.([0-9]+)([a-z]+)?((-fips)?(-beta([0-9]+))?(-pre([0-9]+))?)?';

  vv = eregmatch(string: ver, pattern: pat, icase: FALSE);
  if (isnull(vv))
  {
    err_print('openssl_ver_cmp: invalid version ver=', ver);
    return NULL;
  }

  ff = eregmatch(string: fix, pattern: pat, icase: FALSE);
  if (isnull(ff))
  {
    err_print('openssl_ver_cmp: invalid version fix=', fix);
    return NULL;
  }

  for (i = 1; i <= 3; i ++)
  {
    v = int(vv[i]);
    f = int(ff[i]);
    if (same_branch)
    {
      if (v != f) return 0;
    }
    else
    {
      if (v < f) return -1;
      if (v > f) return 1;
    }
  }

  # a < z is safe
  # z < za is safe
  # za < zz is safe
  v = vv[4];
  f = ff[4];
  if (v < f) return -1;
  if (v > f) return 1;

  # handles match 8 for -beta, and match 10 for -pre
  if ((! isnull(vv[8]) || ! isnull(ff[8])) || (! isnull(vv[10]) || ! isnull(ff[10])))
  {
    if ((! isnull(vv[8]) || ! isnull(ff[8])))
    {
      v = int(vv[8]);
      f = int(ff[8]);
    }
    else
    {
      v = int(vv[10]);
      f = int(ff[10]);
    }

    if (v != f)
    {
      # No beta or pre is newer than betaXXX or preXXX

      # In a min_check, betas/pres are not vuln
      if (is_min_check)
      {
        if (v == 0) return -1;
        if (f == 0) return 1;
      }
      else
      {
        # In a normal check, betas/pres are vuln
        if (v == 0) return 1;
        if (f == 0) return -1;
      }

      if (v < f) return -1;
      if (v > f) return 1;
    }
  }
  return 0;
}

####

global_var	port, ver;

##
# Checks if server's OpenSSL version is vulnerable.
#
# @param  list   fixed list of fixed versions
# @param  int    severity reporting severity
# @param  string min minimum vulnerable version
#
# @remark This function does not return, it either reports or exits.
##
function openssl_check_version(fixed, severity, min)
{
  local_var port;
  local_var kb_base;
  local_var banner, version, backported;
  local_var fix, same_branch;
  local_var report;

  report = '';

  # Make sure OpenSSL is installed.
  port = get_kb_item("openssl/port");
  if (isnull(port)) audit(AUDIT_NOT_INST, app_name);

  # Get relevant data for installed version.
  kb_base = "openssl/" + port + "/";
  banner = get_kb_item(kb_base + "pristine_banner");
  version = get_kb_item(kb_base + "pristine_version");
  backported = get_kb_item(kb_base + "backported");

  # If the banner is backported, and we're not running a paranoid
  # scan, audit out.
  if (backported && report_paranoia < 2) audit(AUDIT_BACKPORT_SERVICE, port, app_name);

  # Make sure the version is above the min vuln version.
  if (!isnull(min) && openssl_ver_cmp(ver:version, fix:min, same_branch:FALSE, is_min_check:TRUE) < 0)
    audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);

  # Check against list of fixes.
  fixed = make_list(fixed);
  if (len(fixed) > 1) same_branch = TRUE;
  else same_branch = FALSE;

  foreach fix (fixed)
  {
    if (openssl_ver_cmp(ver:version, fix:fix, same_branch:same_branch) < 0)
    {
      report =
        '\n  Banner           : ' + banner +
        '\n  Reported version : ' + version +
        '\n  Fixed version    : ' + fix;

      if (backported) report +=
        '\n\nBased on the banner, security patches may have been backported to' +
        '\nthis install of OpenSSL. A local check is needed to confirm the' +
        '\npresence of this vulnerability.';

      report += '\n';
      security_report_v4(port:port, severity:severity, extra:report);
      exit(0);
    }
  }

  audit(AUDIT_LISTEN_NOT_VULN, app_name, port, version);
}

# Local Variables:
# mode:Fundamental
# End:
