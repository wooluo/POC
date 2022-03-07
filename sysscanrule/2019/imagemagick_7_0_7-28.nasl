#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124775);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/13  8:52:57");

  script_cve_id("CVE-2019-10131");
  script_bugtraq_id(108117);

  script_name(english:"ImageMagick < 7.0.7-28 Denial of service vulnerability");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a denial of service vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host
is 7.x prior to 7.0.7-28. It is, therefore, affected by a denial
of service vulnerability in the formatIPTCfrom Buffer function due
to failure to handle exceptional conditions. An unauthenticated,
local attacker can exploit this to read beyond the end of the
buffer or to cause the application to stop responding.");
  # https://www.cvedetails.com/cve/CVE-2019-10131/
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/ImageMagick/ImageMagick/commit/cb1214c124e1bd61f7dd551b94a794864861592e
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.7-28 or later. Note that you may
also need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-10131");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
app_info = vcf::imagemagick::get_app_info();

constraints = [{'fixed_version' : '7.0.7-28'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
