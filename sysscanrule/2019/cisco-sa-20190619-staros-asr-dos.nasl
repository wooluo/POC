#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126340);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/28 15:27:01");

  script_cve_id("CVE-2019-1869");
  script_bugtraq_id(108853);
  script_xref(name: "CISCO-BUG-ID", value: "CSCvn06757");
  script_xref(name: "CISCO-SA", value: "cisco-sa-20190619-staros-asr-dos");
  script_xref(name:"IAVA", value:"2019-A-0214");

  script_name(english:"Cisco StarOS Denial of Service Vulnerability");
  script_summary(english:"Checks the version of Cisco ASR 5000 Series Software");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco ASR 5000 Series Software
is affected by a denial-of-service vulnerability. An unauthenticated,
remote attacker can exploit this, via a series of specially crafted
packets, to prevent the interface from receiving traffic.

Please see the included Cisco BIDs and Cisco Security Advisory for more
information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190619-staros-asr-dos
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvn06757");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID CSCvn06757");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1869");
  script_cwe_id(824);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:asr_5000_series");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/Cisco/ASR/Model", "Host/Cisco/StarOS", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");
include("cisco_kb_cmd_func.inc");

get_kb_item_or_exit("Host/Cisco/StarOS");

version  = get_kb_item_or_exit("Host/Cisco/StarOS/Version");
model   = get_kb_item_or_exit("Host/Cisco/ASR/Model");

major = NULL;
build = NULL;
fix = NULL;
train = NULL;

# only affects ASR 5000 series systems
if (model !~ "^50\d{2}$")
  audit(AUDIT_DEVICE_NOT_VULN, 'The ASR ' + model);

# Normalize train characters
version= toupper(version);

# For newer versions, We may be able to get the build number during detection
build = get_kb_item("Host/Cisco/StarOS/Build");
if (!empty_or_null(build))
  version += "." + build;

# defensive check for the pregmatches below
if (version !~ "^[\d\.]+\([\d\.]+" &&
    version !~ "^[\d\.]+([A-Z]{1,2}\d+)?\.\d+$")
  audit(AUDIT_VER_FORMAT, version);

# only two feature sets are vulnerable
if (report_paranoia < 2) audit(AUDIT_PARANOID);

# old style of versioning 15.0(5439), style change mid 16.1, making
# all of the old style versions fall into the vulnerable range.
if ("(" >< version)
{
  major = pregmatch(pattern:"^([\d\.]+)\(", string:version);

  if(!isnull(major))
  {
    major = major[1];

    if (isnull(build))
    {
      build = pregmatch(pattern:"^[\d\.]+\(([\d\.]+)", string:version);
      if(!isnull(build))
      {
        build = build[1];

        # Set the train to an empty string, or it causes issues when
        # seeing if a patched version exists using NULL as the value
        train = '';
      }
      else
        exit(1, "Unable to extract build number.");
    }
  }
  else
    exit(1, "Unable to extract version number.");
}
else
{
  # extract major, train, and build for new style
  extract = pregmatch(pattern:"^([\d\.]+)\.([A-Z]{1,2}\d+)?\.?(\d+)?", string:version);
  if (!isnull(extract))
  {
    major = extract[1];
    train = extract[2];
    if (isnull(build))
      build = extract[3];
  }
}

# Defensive checking for versions that we haven't yet seen
if(empty_or_null(major) || empty_or_null(build))
  exit(1, "An error occurred during version extraction.");

fix_array = make_array(
  "21.6",  { B16: 70802 },
  "21.12", { CN0: 70901, M0: 70847, RG0:70868 },
  "21.13", { A0:  70850 }
);

maj_checks = [
  {maj:'21.6.13', build:70803},
  {maj:'21.7.11', build:70813},
  {maj:'21.8.10', build:70835},
  {maj:'21.9.7',  build:70905},
  {maj:'21.10.2', build:70893},
  {maj:'21.11.1', build:70889},
  {maj:'21.12.0', build:71155}
];

foreach check (maj_checks)
{
  if (major == check.maj && int(build) < check.build)
  {
    fix = check.maj + '.' + check.build;
    break;
  }
}

if (empty_or_null(fix) &&
    !empty_or_null(fix_array[major]) &&
         !empty_or_null(train) &&
         int(build) < fix_array[major][train])
  fix = major + "." + train + "." + fix_array[major][train];

if (fix)
{
  security_report_cisco(
    port     : 0,
    severity : SECURITY_WARNING,
    version  : version,
    fix      : fix,
    bug_id   : 'CSCvn06757'
  );
}
else audit(AUDIT_DEVICE_NOT_VULN, "ASR " + model, version);
