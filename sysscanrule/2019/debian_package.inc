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
# debian_package.inc
# Revision: 1.29


# http://www.debian.org/doc/debian-policy/ch-controlfields.html#s-f-Version
# [epoch:]upstream_version[-debian_revision]

#pragma static
include("global_settings_nlib.inc");
include("obj_nlib.inc");

##
# Internal value for storing report text
##
global_var deb_report;
deb_report = '';

##
# Storage value for package list kb so we only need to fetch once.
##
global_var dpkg_l;

##
# Storage value for if dpkg_l has been fixed up for linux packages.
##
global_var dpkg_fixup_flag;

##
# Array storage of all modified dpkg-l entries to point to their original versions
##
global_var _deb_dpkg_edits;
_deb_dpkg_edits = make_array();

##
# Flag for indicating whether or not the linux package caveat about
# upgrading kernel version needs to be included
##
global_var _linux_package_flag;

##
# Parses numerical and string portions of a version string into a list
#
# @param ver_str version string
#
# @return list of parts of string broken into digit parts and other parts 
##
function deb_parse_ver_str(ver_str)
{
  local_var ret_val, is_num, tmp, i;

  ret_val = make_list();

  tmp = ver_str[0];
  is_num = FALSE;
  if(tmp =~ "[0-9.]") is_num = TRUE;

  for(i=0; i<strlen(ver_str); i++)
  {
    if(ver_str[i] =~ "[0-9.]" && is_num == FALSE)
    {
      is_num = TRUE;
      if(tmp != '') ret_val = make_list(ret_val, tmp);
      tmp = '';
    }
    else if(ver_str[i] !~ "[0-9.]" && is_num == TRUE)
    {
      is_num = FALSE;
      if(tmp != '') ret_val = make_list(ret_val, tmp);
      tmp = '';
    }
    tmp = tmp + ver_str[i];
  }

  if(tmp != '') ret_val = make_list(ret_val, tmp);

  return ret_val;
}

##
# Adds package/reference info to the internal deb_report value 
#
# @param package Installed version of package
# @param reference Non-affected version of package
#
# @remark If this is a package beginning with linux whose package name
#           matches #.#.#-#, it will replace that last -# with -<ANY>.
#
# @return No return
##
function deb_report_add(package, reference)
{
  # Strip out Debian linux package name version ascension if applicable
  local_var dpkg_linux_pattern_check;
  local_var dpkg_linux_pattern = "^(linux-.*)(\d+\.\d+\.\d+)\-\d+(.*)_(.+)$";
  if ( isnull(package) || !strlen(package) || isnull(reference) || !strlen(reference) )
  {
    return NULL;
  }
  if (!isnull(_deb_dpkg_edits[package]) && strlen(_deb_dpkg_edits[package]))
    package = _deb_dpkg_edits[package];
  if (!isnull(_deb_dpkg_edits[reference]) && strlen(_deb_dpkg_edits[reference]))
    reference = _deb_dpkg_edits[reference];

  dpkg_linux_pattern_check = pgrep(string: reference, pattern:dpkg_linux_pattern);
  if (!isnull(dpkg_linux_pattern_check) && strlen(dpkg_linux_pattern_check))
  {
    reference = ereg_replace(string: reference, pattern:dpkg_linux_pattern, replace:"\1\2-<ANY>\3_\4");
    _linux_package_flag = 1;
  }

  deb_report += 'Remote package installed : ' + package + '\n' +
		'Should be : ' + reference + '\n';
}

##
# Returns internal deb_report value 
#
# @remark If the _linux_package_flag is set, this will also include a
#           caveat about potentially needing to update kernel version
#
# @return newline + deb_report if it has a strlen value 
#         NULL otherwise
##
function deb_report_get()
{
  local_var report;
  report = deb_report;
  if (_linux_package_flag && strlen(report))
    report += '\nBecause Debian linux packages increment their package name numbers as\nwell as their version numbers, an update may not be available for the\ncurrent kernel level, but the package will still be vulnerable. You may\nneed to update the kernel level in order to get the latest security\nfixes available.';
  if ( strlen(report) )
    return '\n' + report;
  else
    return NULL;
}

##
# Compares two Debian version string pieces
#
# @param s1 First version string piece
# @param s2 Second version string piece
#
# @remark This function only looks at the first max_len pieces of each
#           for whichever is shorter
#
# @return 1 if s1 > s2 in version parts from left to right
#         -1 if s1 < s2 in version parts from left to right
#         0 if s1 and s2 are equal through lowest max_len
#         NULL if either version is an invalid format
##
function deb_str_cmp(s1, s2)
{
  local_var v1, v2, v1_len, v2_len,
            t1, t2, t1_len, t2_len,
            i,  j;

  v1 = deb_parse_ver_str(ver_str:s1);
  v2 = deb_parse_ver_str(ver_str:s2);
  
  v1_len = max_index(v1);
  v2_len = max_index(v2);

  for(i=0; i < v1_len || i < v2_len; i ++)
  {
    if(v1[i] =~ "^[0-9.]+")
    {
      t1 = split(v1[i], sep:'.', keep:FALSE);
      t2 = split(v2[i], sep:'.', keep:FALSE);
      t1_len = max_index(t1);
      t2_len = max_index(t2);
  
      for (j = 0; j < t1_len || j < t2_len; j++)
      {
        if (int(t1[j]) < int(t2[j]))
          return -1;
        if (int(t1[j]) > int(t2[j]))
          return 1;
      }
    }
    else
    {
      if(v1[i] < v2[i])
        return -1;
      if(v1[i] > v2[i])
        return 1;
    }
  }
  return 0;
}

##
# Compares two complete Debian versions
#
# @param ver1 First version
# @param ver2 Second version
#
# @remark This function will remove RC entries from versions and then consider
#           which is greater if the version (not release) part is equal.
#
# @return 1 or more if ver1 > ver2 in version parts from left to right
#         -1 or less if ver1 < ver2 in version parts from left to right
#         0 if versions are equal
#         NULL if either version is an invalid format
##
function deb_ver_cmp(ver1, ver2)
{
  local_var	v1, v2, e1, e2, uv1, uv2, dr1, dr2, rc1, rc2, x, package_pattern;

  # Parse RCs
  rc1 = pregmatch(string: ver1, pattern: "^(.*)[.~\-+]rc([0-9]+)(.*)$", icase: 1);
  rc2 = pregmatch(string: ver2, pattern: "^(.*)[.~\-+]rc([0-9]+)(.*)$", icase: 1);
  if (! isnull(rc1))
  {
    ver1 = rc1[1] + rc1[3];
    rc1 = rc1[2];
  }
  if (! isnull(rc2))
  {
    ver2 = rc2[1] + rc2[3];
    rc2 = rc2[2];
  }

  package_pattern = "^([0-9]+:)?(.+?)(-([a-z0-9+.~]+))?$";
  v1 = pregmatch(string: ver1, pattern:package_pattern, icase: 1);
  v2 = pregmatch(string: ver2, pattern:package_pattern, icase: 1);
 
  if (isnull(v1) || isnull(v2)) return NULL;
  e1 = int(v1[1]); uv1 = v1[2]; dr1 = v1[4];
  e2 = int(v2[1]); uv2 = v2[2]; dr2 = v2[4];

  if (e1 != e2) return e1 - e2;
  x = deb_str_cmp(s1: uv1, s2: uv2);
  if (x) return x;
  if (! isnull(rc1) && isnull(rc2))
  {
    return -1;
  }
  if (isnull(rc1) && ! isnull(rc2))
  {
    return 1;
  }
  if (! isnull(rc1) && ! isnull(rc2) && rc1 != rc2)
  {
    return int(rc1) - int(rc2);
  }
  x = deb_str_cmp(s1: dr1, s2: dr2);
  return x;
}

##
# Determines shortened name and metapackage name for the dpkg
#
# @param dpkg package name to parse
#
# @return my_dpkg array containing key-values about dpkg
##
function parse_linux_dpkg_name(dpkg)
{
  local_var elems, i, name, version, prefix, name_version, name_version_major, suffix, name_pieces;
  local_var my_dpkg, metapackage;

  if (isnull(dpkg) || !strlen(dpkg)) return NULL;
  my_dpkg["line"]  = dpkg;
  # Trim off character status code and spacing.
  dpkg = ereg_replace(string:dpkg, pattern:"^ii\s+", replace:"");
  dpkg = ereg_replace(string:dpkg, pattern:" {3,}", replace:"  ");
  elems = split(dpkg, sep:"  ", keep:0);
  name = elems[0];
  version = elems[1];

  if ( preg(string:name, pattern:"\d+\.\d+\.\d+-\d+") ) {
    name_pieces = pregmatch(string:name, pattern:"^(.*)-(\d+\.\d+\.\d+-\d+)-?(.*)$");
    if (isnull(name_pieces)) {
      metapackage = "Unable to parse metapackage";
    } else {
      prefix = name_pieces[1];
      name_version = name_pieces[2];
      suffix = name_pieces[3];
      name_version_major = pregmatch(string:name_version, pattern:"^(\d+\.\d+)\.");
      if (isnull(name_version_major)) {
        name_version_major = "Unable to parse name_version_major";
      } else {
        name_version_major = name_version_major[1];
      }
      metapackage = prefix + '-' + name_version_major;
      if (!isnull(suffix) && strlen(suffix)) {
        metapackage += '-' + suffix;
      }
    }
  } else {
    metapackage = name;
  }

  my_dpkg["name"]        = name;
  my_dpkg["version"]     = version;
  my_dpkg["metapackage"] = metapackage;
  my_dpkg["line"]        = str_replace(string:my_dpkg["line"],find:name,replace:metapackage);
  _deb_dpkg_edits[metapackage + "_" + version] = name + "_" + version;

  return my_dpkg;
}

##
# Changes dpkg-l so that only a single copy of each package that
# begins with "linux-", the latest, appears in the dpkg list
#
# @anonparam First List of dpkgs, joined with newlines as in most
#              dpkg-l KB entries
#
# @remark Only applies to linux packages.
#
# @return Revised copy of dpkg-l with only the latest linux package
#
##
function fixup_dpkg_list()
{
  local_var lines, line, arg;
  local_var ret;
  local_var linux_dpkg;
  local_var linux_dpkgs;
  local_var kernel_maj_min;
  local_var maj_min;
  local_var kernel_type;

  kernel_maj_min = split(get_kb_item("Host/uname/major_minor"), sep:'.', keep:FALSE);
  kernel_type = get_kb_item("Host/Debian/kernel-type");
  arg = _FCT_ANON_ARGS[0];
  if (isnull(arg) || !strlen(arg)) return NULL;

  lines = split(arg, keep:FALSE);
  foreach line ( lines )
  {
    if ( line =~ "^ii +linux-" )
    {
      linux_dpkg = parse_linux_dpkg_name(dpkg:line);
      if ( linux_dpkg["name"] =~ "^linux-image" && !isnull(kernel_maj_min) && max_index(kernel_maj_min) > 0)
      {
        maj_min = split(linux_dpkg["version"], sep:'.', keep:FALSE);
        # Let's only reject non-matching kernel versions when there actually are kernel versions
        if ( (maj_min[0] && kernel_maj_min[0] && maj_min[0] != kernel_maj_min[0]) ||
             (maj_min[1] && kernel_maj_min[1] && maj_min[1] != kernel_maj_min[1])) continue;
        # If it doesn't match the kernel-type, ignore it.
        if ( !isnull(kernel_type) && strlen(kernel_type) && kernel_type >!< linux_dpkg["name"] ) continue;
      }
      if ( isnull(linux_dpkgs[linux_dpkg["metapackage"]]) ) linux_dpkgs[linux_dpkg["metapackage"]] = linux_dpkg;
      else
      {
        if ( deb_ver_cmp(ver1: linux_dpkg["version"], ver2: linux_dpkgs[linux_dpkg["metapackage"]]["version"]) > 0) {
          linux_dpkgs[linux_dpkg["metapackage"]] = linux_dpkg;
        }
      }
    }
    else ret += line + '\n';
  }

  foreach linux_dpkg ( sort(keys(linux_dpkgs)) )
  {
    ret += linux_dpkgs[linux_dpkg]["line"] + '\n';
  }
  return ret;
}


##
# Checks if package below a reference version is installed.
#
# @param prefix package name (ie: python)
# @param release Debian release number (optional)
# @param reference version and release number (ie: 2.6.6-3+squeeze7)
# @param min minimum version and release number to check (optional)
#
# @remark This function has the side-effect of modifying deb_report
#
# @return 1 if package installed and min <= package < reference
#              and Host OS release == release
#         0 otherwise
##
function deb_check(prefix, release, reference, min)
{
  local_var debver, pkgver, release_trimmed, prefix_local;
  local_var installed, ver, v;
  local_var name_orig, name_pieces, name_version, name_version_major, suffix;

  if (get_kb_item("Host/uptrack-uname-r") && match(pattern:"kernel*", string:prefix)) return 0;

  debver = chomp(get_kb_item("Host/Debian/release"));
  if ( ! debver ) return 0; # Not debian

  if (!dpkg_l) dpkg_l = get_kb_item("Host/Debian/dpkg-l");
  if ( prefix =~ "^linux-" ) 
  {
    if (!dpkg_fixup_flag) {
      dpkg_l = fixup_dpkg_list(dpkg_l);
      dpkg_fixup_flag = 1;
    }
    # Trim down dpkg_list to match the fixups
    if ( preg(string:prefix, pattern:"\d+\.\d+\.\d+-\d+") ) {
      name_orig = prefix;
      name_pieces = pregmatch(string:prefix, pattern:"^(.*)-(\d+\.\d+\.\d+-\d+)-?(.*)$");
      if (isnull(name_pieces)) {
        prefix = "Unable to parse prefix";
      } else {
        prefix_local = name_pieces[1];
        name_version = name_pieces[2];
        suffix = name_pieces[3];
        name_version_major = pregmatch(string:name_version, pattern:"^(\d+\.\d+)\.");
        if (isnull(name_version_major)) {
          name_version_major = "Unable to parse name_version_major";
        } else {
          name_version_major = name_version_major[1];
        }
        prefix = prefix_local + '-' + name_version_major;
        if (!isnull(suffix) && strlen(suffix)) {
          prefix += '-' + suffix;
        }
      }
      _deb_dpkg_edits[prefix + "_" + reference] = name_orig + "_" + reference;
    }

  }
  
  # Try something smarter but slower below
  # if (debver && release != debver) return 0;

  installed = pgrep(string: dpkg_l, pattern: '^ii +' + prefix + '(:\\w+)? +');
  if (! installed) return 0;
  ver = ereg_replace(	string: installed, replace: "\2",
  pattern: '^ii +' + prefix + '(:\\w+)? +([^ ]+) +.*$');
  if (ver == installed) return 0;	# cannot extract version

  # Here, we try to extract the "branch" from the installed package
  # I don't think that mixing sarge, woody and sid packages on a single
  # system is great, but it is possible.
  # However, the branch is not always included in the package name, and
  # Look at "DSA 865-1" for example. So we fall back to /etc/debian-release
  # and hope that such mix did not occur
  if (preg(string: ver, pattern: '[0-9]$')) pkgver = debver; # or '4.0'?
  else if (preg(string: ver, pattern: 'buster[0-9]$')) pkgver  = '10.0';
  else if (preg(string: ver, pattern: 'stretch[0-9]$')) pkgver  = '9.0';
  else if (preg(string: ver, pattern: 'jessie[0-9]$')) pkgver   = '8.0';
  else if (preg(string: ver, pattern: 'wheezy[0-9]$')) pkgver   = '7.0';
  else if (preg(string: ver, pattern: 'squeeze[0-9]$')) pkgver  = '6.0';
  else if (preg(string: ver, pattern: 'lenny[0-9]$')) pkgver    = '5.0';
  else if (preg(string: ver, pattern: 'etch[0-9]$')) pkgver     = '4.0';
  else if (preg(string: ver, pattern: 'sarge[0-9]$')) pkgver    = '3.1';
  else if (preg(string: ver, pattern: 'woody[0-9]$')) pkgver    = '3.0';
  else if (preg(string: ver, pattern: 'potato[0-9]$')) pkgver   = '2.2';
  else if (preg(string: ver, pattern: 'hamm[0-9]$')) pkgver     = '2.0';
  else pkgver = debver;

  release_trimmed = release;
  if (preg(string: release_trimmed, pattern:"([7-9]|[1-9][0-9])\.[0-9][0-9]?"))
  {
    release_trimmed = pregmatch(string: release_trimmed, pattern:"([7-9]|[1-9][0-9])\.[0-9][0-9]?");
    if (isnull(release_trimmed)) {
      release_trimmed = "Release_trimmed regex broke, which is not possible.";
    } else {
      release_trimmed = release_trimmed[1];
    }
  }
  if (pkgver && release != pkgver && ! match(string: pkgver, pattern: release_trimmed+".*"))
  {
    return 0;
  }
  
  if (deb_ver_cmp(ver1: ver, ver2: reference) < 0)
  {
    # Added a check for a minimum version.
    if (isnull(min) || (deb_ver_cmp(ver1:ver, ver2:min) >= 0))
    {
      deb_report_add(package:prefix + "_" + ver, reference:prefix + "_" + reference);
      debug_print("debian_package[", get_host_ip(), "]: package ", prefix, "_", ver, " is vulnerable in Debian ", release, ". Upgrade to ", prefix, "_", reference, "\n");
      return 1;
    }
  }
  return 0;
}

