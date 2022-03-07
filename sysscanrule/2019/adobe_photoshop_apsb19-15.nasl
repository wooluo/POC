#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122817);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/16 15:34:48");

  script_cve_id("CVE-2019-7094");

  script_name(english:"Adobe Photoshop CC 19.x <= 19.1.7 / 20.x <= 20.0.2 Vulnerability (APSB19-15)");
  script_summary(english:"Checks the version of Adobe Photoshop.");

  script_set_attribute(attribute:"synopsis", value:
"Adobe Photoshop installed on remote Windows host is affected by a
vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Adobe Photoshop CC installed on the remote Windows host
is equal or prior to 19.1.7 (2018.1.7), 20.0.2 (2019.0.2). It is, therefore,
affected by a vulnerability as referenced in the apsb19-15 advisory.

  - Heap corruption potentially leading to Arbitrary code
    execution (CVE-2019-7094)

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://helpx.adobe.com/security/products/photoshop/apsb19-15.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Adobe Photoshop CC version 19.1.8 (2018.1.8), 20.0.4
(2019.0.4) or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7094");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adobe:photoshop_cc");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("adobe_photoshop_installed.nasl");
  script_require_keys("installed_sw/Adobe Photoshop", "SMB/Registry/Enumerated");

  exit(0);
}

include("vcf.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

app_info = vcf::get_app_info(app:"Adobe Photoshop", win_local:TRUE);

if ("CC" >!< app_info.Product) vcf::vcf_exit(0, "Only Adobe Photoshop CC is affected.");
vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "19", "max_version" : "19.1.7", "fixed_version" : "19.1.8" },
  { "min_version" : "20", "max_version" : "20.0.2", "fixed_version" : "20.0.4" },
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
