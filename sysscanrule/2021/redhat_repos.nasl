
#
# 
#



include("compat.inc");

if (description)
{
  script_id(149983);
  script_version("1.1");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/26");

  script_name(english:"Red Hat Enterprise Linux : Enabled Official Repositories");
  script_summary(english:"Checks .repo file output repos against a list of official RHEL repos");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is using one or more official Red Hat repositories to install packages."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is using one or more official Red Hat repositories to install packages.
These repositories will be used in conjunction with Red Hat OS package level assessment security advisories to determine whether or not relevant repositories are installed before checking package versions for vulnerable ranges."
  );
  script_set_attribute(attribute:"see_also", value:"https://www.redhat.com/security/data/metrics/repository-to-cpe.json");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2021/05/26");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("lists.inc");
include("misc_func.inc");
include("rhel.inc");
include("rhel_repos.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Check for repo list data
var host_repo_list = sort(keys(get_kb_list("Host/RedHat/repo-list/*")));
if (empty_or_null(host_repo_list)) audit(AUDIT_NOT_INST, "a RHEL repository");

var repo_block = '';
for (var m=0; m < max_index(host_repo_list); m++)
{
  host_repo_list[m] = ereg_replace(pattern:"Host\/RedHat\/repo-list\/", replace:"", string:host_repo_list[m]);
  repo_block += '  ' + host_repo_list[m] + '\n';
}
var host_repo_list_original = host_repo_list;

var valid_repos = sort(collib::intersection(host_repo_list, RHEL_REPO_LABELS));
if (empty_or_null(valid_repos)) audit(AUDIT_NOT_INST, "a validly labeled RHEL repository");

var repo_join = serialize(valid_repos); 
replace_kb_item(name:"Host/RedHat/valid-repos", value:repo_join);

var valid_block = '';
for (m = 0; m < max_index(valid_repos); m++)
{
  valid_block += '  ' + valid_repos[m] + '\n';
}

var report = 'Red Hat Repo labels found to be enabled:\n' + repo_block + '\nValid Red Hat Repo labels found to be enabled:\n' + valid_block;

security_report_v4(
  port       : 0,
  severity   : SECURITY_NOTE,
  extra      : report
);
