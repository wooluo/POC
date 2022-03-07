#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124776);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/13  8:52:57");

  script_cve_id(
    "CVE-2018-15607",
    "CVE-2019-9956",
    "CVE-2019-10649",
    "CVE-2019-10650",
    "CVE-2019-11597",
    "CVE-2019-11598"
  );
  script_bugtraq_id(
    105137,
    107546,
    107645,
    107646,
    108102
  );

  script_name(english:"ImageMagick < 7.0.8-44 Multiple vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is
7.x prior to 7.0.8-44. It is, therefore, affected by multiple
vulnerabilities:

  - A denial of service vulnerability exists due to a
    failure to handle exceptional conditions. An unauthenticated,
    remote attacker can exploit this by convincing a user into
    converting a specially crafted file, to cause the system
    to stop responding. (CVE-2018-15607)

  - A stack-based buffer overflow condition exists in the
    PopHexPixel function due to a failure to handle exceptional
    conditions. An unauthenticated,remote attacker can exploit
    this, via convincing a user to open a crafted image file,
    to cause a denial of service condition or the execution of
    arbitrary code. (CVE-2019-9956)

  - A memory leak vulnerability exists in the
    SVGKeyValuePairs function due to a failure to handle
    exceptional conditions. An unauthenticated, remote attacker
    can exploit this via convincing a user to open a crafted
    image file, to cause the application to stop responding.
    (CVE-2019-10649)

Note that the application may also be affected by additional
vulnerabilities. Refer to the vendor for additional information.
");
  # https://www.cvedetails.com/cve/CVE-2018-15607
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.cvedetails.com/cve/CVE-2019-9956
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.cvedetails.com/cve/CVE-2019-10649
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.cvedetails.com/cve/CVE-2019-10650
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.cvedetails.com/cve/CVE-2019-11597
  script_set_attribute(attribute:"see_also", value:"");
  # https://www.cvedetails.com/cve/CVE-2019-11598
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.8-44 or later. Note that you may
also need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-15607");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/08/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2018/08/21");
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

constraints = [{'fixed_version' : '7.0.8-44'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
