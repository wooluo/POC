#
# (C) WebRAY Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(127051);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/13  8:52:57");

  script_cve_id(
    "CVE-2019-13133",
    "CVE-2019-13134",
    "CVE-2019-13135",
    "CVE-2019-13136",
    "CVE-2019-13137",
    "CVE-2019-13295",
    "CVE-2019-13296",
    "CVE-2019-13297",
    "CVE-2019-13298",
    "CVE-2019-13299",
    "CVE-2019-13300",
    "CVE-2019-13301",
    "CVE-2019-13302",
    "CVE-2019-13303",
    "CVE-2019-13304",
    "CVE-2019-13305",
    "CVE-2019-13306",
    "CVE-2019-13307",
    "CVE-2019-13308",
    "CVE-2019-13309",
    "CVE-2019-13310",
    "CVE-2019-13311",
    "CVE-2019-13454"
  );
  script_bugtraq_id(
    109099,
    109308,
    109362
  );
  script_xref(name:"IAVB", value:"2019-B-0062");

  script_name(english:"ImageMagick < 7.0.8-56 Multiple vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is prior to 7.0.8-56. It is, therefore, affected by 
multiple vulnerabilities:

  - An integer overflow condition exists in the TIFFSeekCustomStream function. An unauthenticated, remote attacker can 
    exploit this, by convincing a user to open a crafted image file, to cause a denial of service condition or the 
    execution of arbitrary code (CVE-2019-13136).
  
  - A stack-based buffer overflow condition exists in the WritePNMImage function due to an off-by-one error. An 
    unauthenticated,remote attacker can exploit this, by convincing a user to open a crafted image file, to cause a 
    denial of service condition or the execution of arbitrary code (CVE-2019-13306).

  - A heap-based buffer overflow condition exists in the EvaluateImages function due to a mishandling of rows. An 
    unauthenticated, remote attacker can exploit this, by convincing a user to open a crafted image file, to cause a 
    denial of service condition or the execution of arbitrary code (CVE-2019-13307).

Note that the application may also be affected by additional vulnerabilities. Refer to the vendor for additional 
information.");
  # https://github.com/ImageMagick/ImageMagick/milestone/17?closed=1
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:"Upgrade to ImageMagick version 7.0.8-56 or later. Note that you may
also need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13136");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

constraints = [{'fixed_version' : '7.0.8-56'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
