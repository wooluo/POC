#
# (C) WebRAY Network Security, Inc.
#
# This script is released under one of the WebRAY Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from WebRAY Network Security, Inc.
#
# @NOGPL@
#
# ksplice.inc
#
# Revision: 1.0
#

include("lists.inc");

##
# Storage value for release kb so we only need to fetch once.
##
global_var _ksplice_kernel_cves = make_array();

##
# Storage value for missing KSplice CVEs.
##
global_var _ksplice_missing_cves = make_list();

##
# Populates and returns _ksplice_kernel_cves
#
# @return _ksplice_kernel_cves if Host/ksplice/kernel-cves has a value
#         NULL if the KB is missing
##
function ksplice_load_cve_list()
{
  local_var kb_value, kb_split, cve;
  kb_value = get_kb_item("Host/ksplice/kernel-cves");
  if (isnull(kb_value)) return NULL;
  kb_split = split(kb_value, sep:",", keep:FALSE);
  foreach cve (kb_split)
  {
    _ksplice_kernel_cves[cve] = 1;
  }
  return _ksplice_kernel_cves;
}

##
# Determines if all CVEs are present in the _ksplice_kernel_cves list
#
# @anonparam list of CVEs to check
#
# @remark Empties and populates _ksplice_missing_cves
#
# @return 1 if all the CVEs exist in the Host/ksplice/kernel-cves list
#         else NULL
##
function ksplice_cves_check ()
{
  local_var cves, cve;
  cves = _FCT_ANON_ARGS[0];
  if (isnull(cves) || max_index(cves) < 1) return NULL;
  if (isnull(max_index(keys(_ksplice_kernel_cves)))) ksplice_load_cve_list();
  _ksplice_missing_cves = make_list();
  foreach cve (cves)
  {
    if (!_ksplice_kernel_cves[cve])
    {
      _ksplice_missing_cves = make_list(_ksplice_missing_cves, cve);

    }
  }
  if (max_index(_ksplice_missing_cves) < 1)
  {
    return 1;
  }
  else
  {
    return NULL;
  }
}

##
# Determines if all CVEs are present in the _ksplice_kernel_cves list
#
# @remark Checks _ksplice_missing_cves for any missing CVEs.
#
# @return string text indicating missing CVEs in ksplice
#         else empty string
##
function ksplice_reporting_text ()
{
  local_var cves, report, i, terminator;
  cves = _ksplice_missing_cves;
  if (isnull(cves) || max_index(cves) < 1) return '';
  cves = collib::cve_sort(cves);
  report = 'KSplice is running, but the following required CVEs remain unpatched:\n  ';
  for (i = 0; i < max_index(cves); i++)
  {
    terminator = '  ';
    if (i == (max_index(cves) - 1))
    {
      terminator = '\n\n';
    }
    else if ((i + 1) % 4 == 0)
    {
      terminator = ',\n  ';
    }
    else
    {
      terminator = ', ';
    }
    report += cves[i] + terminator;
  }
  return report;
}
