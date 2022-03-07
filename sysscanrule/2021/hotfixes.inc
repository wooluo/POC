#
# 
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# hotfixes.inc
#
# Revision: 1.0
#

include("lists.inc");

##
# Storage value for release kb so we only need to fetch once.
##
global_var _hotfix_kernel_cves = make_array();

##
# Storage value for system hotfix type. Can have capital letters. KB access of kernel-cves gets tolower()ed.
##
global_var _hotfix_type;

##
# Storage value for missing hotfix CVEs.
##
global_var _hotfix_missing_cves = make_list();

##
# Check the value of _hotfix_type
#
# @return _hotfix_type
##
function hotfix_type()
{
  return _hotfix_type;
}

##
# Set the value of _hotfix_type
#
# @anonparam hotfix type to set
#
# @return _hotfix_type
##
function set_hotfix_type()
{
  _hotfix_type = _FCT_ANON_ARGS[0];
  return _hotfix_type;
}

##
# Populates and returns _hotfix_kernel_cves
#
# @remark Relies on the _hotfix_type value being populated.
#
# @return _hotfix_kernel_cves if Host/(hotfix-type)/kernel-cves has a value
#         NULL if the KB is missing or _hotfix_type isn't populated
##
function hotfix_load_cve_list()
{
  local_var kb_value, kb_split, cve;
  if(isnull(hotfix_type()) || !strlen(hotfix_type())) return NULL;
  kb_value = get_kb_item("Host/" + tolower(hotfix_type()) + "/kernel-cves");
  if (isnull(kb_value)) return NULL;
  kb_split = split(kb_value, sep:",", keep:FALSE);
  foreach cve (kb_split)
  {
    _hotfix_kernel_cves[cve] = 1;
  }
  return _hotfix_kernel_cves;
}

##
# Determines if all CVEs are present in the _hotfix_kernel_cves list
#
# @anonparam list of CVEs to check
#
# @remark Empties and populates _hotfix_missing_cves
#
# @return 1 if all the CVEs exist in the Host/(_hotfix_type)/kernel-cves list
#         else NULL
##
function hotfix_cves_check()
{
  local_var cves, cve;
  cves = _FCT_ANON_ARGS[0];
  if (isnull(cves) || max_index(cves) < 1) return NULL;
  if (isnull(max_index(keys(_hotfix_kernel_cves)))) hotfix_load_cve_list();
  _hotfix_missing_cves = make_list();
  foreach cve (cves)
  {
    if (!_hotfix_kernel_cves[cve])
    {
      append_element(var:_hotfix_missing_cves, value:cve);
    }
  }
  if (max_index(_hotfix_missing_cves) < 1)
  {
    return 1;
  }
  else
  {
    return NULL;
  }
}

##
# Assembles reporting text for missing CVEs
#
# @remark Checks _hotfix_missing_cves for any missing CVEs.
#
# @return string text indicating missing CVEs in hotfix patches
#         else empty string
##
function hotfix_reporting_text ()
{
  local_var cves, report, i, terminator;
  cves = _hotfix_missing_cves;
  if (isnull(cves) || max_index(cves) < 1) return '';
  cves = collib::cve_sort(cves);
  report = hotfix_type() + ' is running, but the following required CVEs remain unpatched:\n  ';
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
