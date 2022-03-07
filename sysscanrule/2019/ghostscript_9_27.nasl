#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125631);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/31 14:07:29");

  script_cve_id("CVE-2019-3839");
  script_bugtraq_id(990682);
  script_xref(name:"IAVB", value:"2019-B-0042");

  script_name(english:"Artifex Ghostscript < 9.27 PostScript Security Bypass Vulnerability");
  script_summary(english:"Checks the Ghostscript version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a library that is affected by a security bypass vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Artifex Ghostscript installed on the remote Windows host is prior to 9.27. It is, therefore, affected by
a security bypass vulnerability due to some privileged operators remained accessible from various places after the
CVE-2019-6116 fix. An authenticated, remote attacker can exploit this, via specially crafted PostScript file, to access
the file system outside of the constrains imposed by -dSAFER.");
  script_set_attribute(attribute:"see_also", value: "https://www.ghostscript.com/Ghostscript_9.27.html");
  script_set_attribute(attribute:"solution", value: "Update to 9.27.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3839");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:ghostscript");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:artifex:gpl_ghostscript");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Windows");

  script_dependencies("ghostscript_detect.nbin");
  script_require_keys("installed_sw/Ghostscript");

  exit(0);
}

include("vcf.inc");

app = "Ghostscript";

constraints = [{"fixed_version" : "9.27"}];

app_info = vcf::get_app_info(app:app, win_local:TRUE);

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
