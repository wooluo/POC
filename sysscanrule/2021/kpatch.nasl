#
# 
#

include("compat.inc");

if (description)
{
  script_id(138014);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/05/10");

  script_name(english:"kpatch : Installed Patches");
  script_summary(english:"Checks kpatch output for the hotfixed CVEs");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote host is using kpatch to maintain the OS kernel."
  );
  script_set_attribute(
    attribute:"description",
    value:
"kpatch is being used to maintain the remote host's operating system kernel without requiring reboots."
  );
  script_set_attribute(attribute:"see_also", value:"https://github.com/dynup/kpatch");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_type", value:"local");

  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/01");
  script_set_attribute(attribute:"agent", value:"unix");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2020-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");
  script_family(english:"General");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("hotfixes.inc");
include("misc_func.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

# Check for kpatch list data
var kpatch_list = get_one_kb_item("Host/kpatch/list");
if (empty_or_null(kpatch_list)) audit(AUDIT_NOT_INST, "kpatch");
var kpatch_list_original = kpatch_list;

# We only care about the loaded patches at scan time. Output order goes:
#Optional Cruft
#Loaded patch modules:
#...
#Installed patch modules:
#...
#Available patch modules:
#...
# So remove everything before and after the Loaded patch modules.
kpatch_list = ereg_replace(pattern:"[Ii]nstalled patch modules.*$", replace:"", string:kpatch_list);
kpatch_list = ereg_replace(pattern:"^.*[Ll]oaded patch modules:\s*", replace:"", string:kpatch_list);
var cves = [];
var patch_list = [];
if (!empty_or_null(kpatch_list))
{
  var kpatch_split = split(kpatch_list, sep:'\n', keep:FALSE);
  var line;
  foreach line (kpatch_split)
  {
    # Break down by words with spaces.
    var line_split = split(line, sep:' ', keep:FALSE);
    for (var m=0;m<max_index(line_split);m++)
    {
      var word = line_split[m];
      # Skip [enabled] or [disabled]
      if (preg(string:word, pattern:"^\s*\[(?:en|dis)abled\]\s*$"))
      {
        continue;
      }
      if (!empty_or_null(word) && preg(string:word, pattern:"^[a-zA-Z0-9_-]+$"))
      {
        append_element(var:patch_list, value:word);
      }
      # Break down by CVE-. Can't split on a regex in NASL, so we have to reconstruct the entry afterwards.
      word = ereg_replace(pattern:"_", replace:"-", string:word);
      var cve_split = split(word, sep:"CVE-", keep:FALSE);
      for (var c=0;c<max_index(cve_split);c++)
      {
        var cve_candidate = cve_split[c];
        if (c > 0)
        {
          cve_candidate = "CVE-" + cve_candidate;
        }
        var cve_match = pregmatch(string:cve_candidate, pattern:"(CVE-\d{4}-\d{4,})");
        if (!empty_or_null(cve_match) && !empty_or_null(cve_match[1]))
        {
          append_element(var:cves, value:cve_match[1]);
        }
      }
    }
  }
  # If the kpatch_list exists but no kpatches or kpatches with CVE labels have been loaded,
  # write a dummy patch/CVE to ensure Host/kpatch/patch-list and Host/kpatch/kernel-cves
  # can be written so that kpatch checks execute correctly.
  if (empty_or_null(cves)) {
    cves = ["NONE"];
  }
  if (empty_or_null(patch_list)) {
    patch_list = ["NONE"];
  }
}

var report = '';
if (!empty_or_null(patch_list)) {
  var patch_join = join(patch_list, sep:",");
  replace_kb_item(name:"Host/kpatch/patch-list", value:patch_join);
  report += 'Kernel patches determined to be loaded through kpatch:\n';
  var patch_block = '';
  for (var i = 0; i < max_index(patch_list); i++)
  {
    patch_block += '  ' + patch_list[i] + '\n';
  }
  report += patch_block + '\n';
}

var cve_list;
if (!empty_or_null(cves)) {
  cves = collib::cve_sort(cves);
  cve_list = join(cves, sep:",");
  replace_kb_item(name:"Host/kpatch/kernel-cves", value:cve_list);
}

if (!empty_or_null(cve_list))
{
  report += 'Kernel CVEs determined to be patched through kpatch:\n';
  var cves_block = '  ';
  var terminator;
  for (var i = 0; i < max_index(cves); i++)
  {
    terminator = '  ';
    if (i == (max_index(cves) - 1))
    {
      terminator = '';
    }
    else if ((i + 1) % 4 == 0)
    {
      terminator = ',\n  ';
    }
    else
    {
      terminator = ', ';
    }
    cves_block += cves[i] + terminator;
  }
  report += cves_block;
  # If the kpatch_list contains enough left to get processed, but has no CVEs, we wind up with a "NONE" entry, and here.
  if (cves_block == '  NONE')
  {
    report += '\n\nkpatch is installed, but no loaded patch modules appear to cover any CVEs.\nkpatch list output:\n\n';
    report += kpatch_list_original;
  }
}
else
{
  # This can only occur if the Loaded patch modules section is empty or null.
  # Shouldn't ever happen but let's prepare for the possibility.
  report = 'kpatch is installed, but no loaded patch modules appear to cover any CVEs.\nkpatch list output:\n\n';
  report += kpatch_list_original;
}
if (report != "") report += '\n\n';

security_report_v4(
  port       : 0,
  severity   : SECURITY_NOTE,
  extra      : report
);
