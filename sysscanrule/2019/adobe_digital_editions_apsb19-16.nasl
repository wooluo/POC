#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122815);
  script_version("1.2");
  script_cvs_date("Date: 2019/03/15 15:35:01");

  script_cve_id("CVE-2019-7095");
  script_xref(name:"IAVB", value:"2019-B-0018");

  script_name(english:"Adobe Digital Editions < 4.5.10.186048 Heap Overflow Vulnerability (APSB19-16)");
  script_summary(english:"Checks the version of Adobe Digital Editions.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by
a buffer overflow vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Digital Editions installed on the remote
Windows host is prior to 4.5.10.186048. It is, therefore, affected by
a buffer overflow vulnerability that can be exploited to execute
arbitrary code the context of the current user.");
  # https://helpx.adobe.com/security/products/Digital-Editions/apsb19-16.html
  script_set_attribute(attribute:"see_also", value:"");
  # http://www.adobe.com/solutions/ebook/digital-editions/release-notes.html
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Digital Editions version 4.5.10.186048 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7095");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:digital_editions");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies('adobe_digital_editions_installed.nbin');
  script_require_keys("installed_sw/Adobe Digital Editions", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Adobe Digital Editions", win_local:TRUE);

constraints = [
  { "fixed_version" : "4.5.10.186048" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
