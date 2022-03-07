##
# 
#
# This script is released under one of the Tenable Script Licenses and may not
# be used from within scripts released under another license without the
# authorization from Tenable Network Security, Inc.
#
# @NOGPL@
#
# rhel.inc
# Revision: 1.4
##

global_var RHEL_REPOS_NO_OVERLAP_MESSAGE = "AUDIT";

global_var RHEL_REPO_AUDIT_PACKAGE_LIST_DETAILS = 'Red Hat repository labels that ' + '\n' +
'can be used for vulnerability checks, or labels are renamed under a ' + '\n' +
'standard not consistent with Red Hat\'s own labeling';

##
# Compare version_a to version_b
#
# @param version_a string containing the first version to compare ('7.6', '8.1')
# @param version_b string containing the second version to compare ('7.6', '8.1')
# @anonparam version_a optional string containing the first version to compare in case version_a and version_b are missing
# @anonparam version_b optional string containing the second version to compare in case version_a and version_b are missing
#
# @return -1 if version_a < version_b
#          0 if version_a == version_b,
#          1 if version_a > version_b,
#          NULL if an error condition is encountered
##
function rhel_os_level_compare(version_a, version_b)
{
  local_var split_rhel_version, split_os_version, rhel_major_version, rhel_minor_version, os_major_version, os_minor_version;
  if (max_index(_FCT_ANON_ARGS) == 2 && isnull(version_a) && isnull(version_b))
  {
    version_a = _FCT_ANON_ARGS[0];
    version_b = _FCT_ANON_ARGS[1];
  }
  split_os_version = split(version_a, sep:'.', keep:FALSE);
  split_rhel_version = split(version_b, sep:'.', keep:FALSE);
  if(isnull(split_rhel_version[0]) || isnull(split_os_version[0])) return NULL;
  rhel_major_version = int(split_rhel_version[0]);
  os_major_version = int(split_os_version[0]);
  rhel_minor_version = 0;
  os_minor_version = 0;
  if (!isnull(split_rhel_version[1])) rhel_minor_version = int(split_rhel_version[1]);
  if (!isnull(split_os_version[1])) os_minor_version = int(split_os_version[1]);

  if(os_major_version == rhel_major_version)
  {
    if (os_minor_version == rhel_minor_version) return 0;
    if (os_minor_version > rhel_minor_version) return 1;
    if (os_minor_version < rhel_minor_version) return -1;
    return NULL;
  }
  if (os_major_version > rhel_major_version) return 1;
  if (os_major_version < rhel_major_version) return -1;
  return NULL;
}

##
# Uses the given operator to compare the os_version to the given rhel_version.
#
# @param operator string to determine what operator to use ('eq', 'ge', 'gt', 'le', 'lt')
# @param os_version string containing the OS version from the host ('7.6', '8.1')
# @param rhel_version string containing the rhel_version to compare os_version against ('7.6', '8.1')
#
# @remark The operators are as follows:
#         eq - equal
#         ge - greater than or equal
#         gt - greater than
#         le - less than or equal
#         lt - less than
#
# @return TRUE if rhel_version and os_version are evaluated to true using the given operator case
#         FALSE otherwise
##
function rhel_check_release(operator, os_version, rhel_version)
{
  local_var comparison;
  comparison = rhel_os_level_compare(version_a:os_version, version_b:rhel_version);
  if (isnull(comparison)) return FALSE;
  switch (operator)
  {
    case 'eq':
      if (comparison == 0) return TRUE;
      return FALSE;
    case 'ge':
      if (comparison >= 0) return TRUE;
      return FALSE;
    case 'gt':
      if (comparison > 0) return TRUE;
      return FALSE;
    case 'le':
      if (comparison <= 0) return TRUE;
      return FALSE;
    case 'lt':
      if (comparison < 0) return TRUE;
      return FALSE;
  }
}

##
# Uses the given operator to compare the os_version to the given list of rhel_versions.
#
# @param operator string to determine what operator to use ('eq', 'ge', 'gt', 'le', 'lt')
# @param os_version string containing the OS version from the host ('7.6', '8.1')
# @param rhel_versions list containing rhel_versions to compare os_version against (['7.6', '8.1'])
#
# @remark The operators are as follows:
#         eq - equal
#         ge - greater than or equal
#         gt - greater than
#         le - less than or equal
#         lt - less than
#
# @return TRUE if any of the rhel_versions and os_version are evaluated to true using the given operator case
#         FALSE otherwise
##
function rhel_check_release_list(operator, os_version, rhel_versions)
{
  local_var rhel_version;
  if (typeof(rhel_versions) != 'array') rhel_versions = make_list(rhel_versions);
  foreach rhel_version (rhel_versions)
  {
    if(rhel_check_release(operator:operator, os_version:os_version, rhel_version:rhel_version)) return TRUE;
  }
  return FALSE;
}

##
# Determines valid repo set labels if any are available
#
# @remark Pulls Host/RedHat/valid-repos entry, checks against repositorites to see what entries overlap
#
# @return {} if there are no valid repos, else
#         RHEL_REPOS_NO_OVERLAP_MESSAGE if there are valid repos and they don't match the repositories array entries at all, else
#         array with keys indicating repo set names containing the installed valid repos which exist in repositories array
##
function rhel_get_valid_repo_sets(repositories)
{
  var valid_repos, repo_split, repo, repo_array, valid_array, repo_set;
  repo_array = {};
  valid_array = {};
  valid_repos = get_kb_item('Host/RedHat/valid-repos');
  if (!isnull(valid_repos) && strlen(valid_repos))
  {
    repo_split = deserialize(valid_repos);
    foreach repo (repo_split)
    {
      repo_array[repo] = 1;
    }
    # Check for repositories entries in repo_array
    if (isnull(repositories) || isnull(max_index(keys(repositories))))
    {
      return valid_array;
    }
    foreach repo_set (keys(repositories))
    {
      foreach repo (repositories[repo_set])
      {
        if (!isnull(repo_array[repo]))
        {
          valid_array[repo_set] = 1;
          break;
        }
      }
    }
    if (isnull(max_index(keys(valid_array))))
    {
      return RHEL_REPOS_NO_OVERLAP_MESSAGE;
    }
  }
  return valid_array;
}

##
# Determine if repos match or should be ignored
#
# @return TRUE if there are no valid repos or RHEL_REPOS_NO_OVERLAP_MESSAGE is found, implying repos should not be considered, else
#         TRUE if a valid repo set was detected matching one of the sets we're currently looking for, else
#         FALSE
##
function rhel_decide_repo_check(repo_list, repo_sets)
{
  var repo;
  if (isnull(repo_sets) || repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE || isnull(max_index(keys(repo_sets))))
  {
    # All the repos are non-official labels or there are none. Pass the repo check and do package checks.
    return TRUE;
  }
  if (isnull(repo_list) || isnull(max_index(keys(repo_list))))
  {
    # The repo-list was passed badly. Pass the repo check and do package checks.
    return TRUE;
  }
  foreach repo (repo_list)
  {
    # A valid repo set was detected matching one of the sets we're currently looking for.
    if (repo_sets[repo])
    {
      return TRUE;
    }
  }
  # A valid matching repo set was not detected.
  return FALSE;
}

##
# Determine if any repo sets begin with "enterprise_linux"
#
# @return TRUE if there are any repo sets starting with "enterprise_linux", else
#         FALSE
##
function rhel_repo_sets_has_enterprise_linux(repo_sets)
{
  var repo;
  if (isnull(repo_sets) || repo_sets == RHEL_REPOS_NO_OVERLAP_MESSAGE || isnull(max_index(keys(repo_sets))))
  {
    # No valid repo sets to check.
    return FALSE;
  }
  foreach repo (keys(repo_sets))
  {
    if (preg(string:repo, pattern:'^enterprise_linux'))
    {
      return TRUE;
    }
  }
  return FALSE;
}
