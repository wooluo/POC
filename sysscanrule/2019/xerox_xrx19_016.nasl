#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127109);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/05  9:28:46");

  script_cve_id(
    "CVE-2019-12255",
    "CVE-2019-12256",
    "CVE-2019-12257",
    "CVE-2019-12258",
    "CVE-2019-12259",
    "CVE-2019-12260",
    "CVE-2019-12261",
    "CVE-2019-12262",
    "CVE-2019-12263",
    "CVE-2019-12264",
    "CVE-2019-12265"
  );
  script_xref(name:"IAVA", value:"2019-A-0274");

  script_name(english:"Xerox WorkCentre Multiple Vulnerabilities (XRX19-016) (URGENT/11)");
  script_summary(english:"Checks system software version of Xerox WorkCentre devices.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, the remote Xerox WorkCentre
is  affected by multiple remote code execution and denial-of-service
vulnerabilities in the IPnet TCP/IP stack. An unauthenticated, remote,
attacker could leverage these vulnerabilities to gain full access to
the affected device or to cause the device to become unresponsive.");
  # https://securitydocs.business.xerox.com/wp-content/uploads/2019/07/cert_XRX19-016.pdf
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://armis.com/urgent11/");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate update as described in the Xerox
security bulletin in the referenced URL.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12255");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/29");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:xerox:workcentre");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("xerox_workcentre_detect.nasl");
  script_require_keys("www/xerox_workcentre", "www/xerox_workcentre/model", "www/xerox_workcentre/ssw");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

# Get model and system software version
model = get_kb_item_or_exit("www/xerox_workcentre/model");
ver = get_kb_item_or_exit("www/xerox_workcentre/ssw");
ctrl = get_kb_item_or_exit("www/xerox_workcentre/ess");
vuln = FALSE;

ctrl_append = "367972v2";

if (model =~ "^58(45|55|65|75|90)$")
{
  less_or_equal = "072.190.165.14201";
  great_or_equal = "073.190.035.24100";
  fix = "072.190.196.34301";
}
else if (model =~ "^78(45|55)$")
{
  less_or_equal = "072.040.165.14201";
  great_or_equal = "073.040.035.24100";
  fix = "072.040.196.34301";
}
else
  audit(AUDIT_HOST_NOT, "an affected Xerox WorkCentre model");

if (
      ver_compare(ver:ver, fix:less_or_equal, strict:FALSE) <= 0 ||
      ver_compare(ver:ver, fix:great_or_equal, strict:FALSE) >= 0
    )
  vuln = TRUE;
else if (ctrl_append >!< ctrl)
{
  if(report_paranoia < 2)
    audit(AUDIT_POTENTIAL_VULN, "Xerox WorkCentre " + model + " System SW", ver);
  else vuln = TRUE;
}

if(!vuln) audit(AUDIT_INST_VER_NOT_VULN, "Xerox WorkCentre " + model + " System SW", ver);

report =
  '\n  Model                             : Xerox WorkCentre ' + model +
  '\n  Installed system software version : ' + ver +
  '\n  Fixed system software version     : ' + fix + ' and the 367972v2.dlm patch.\n';
security_report_v4(severity:SECURITY_HOLE, port:0, extra:report);
