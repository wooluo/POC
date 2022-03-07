#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122248);
  script_version("1.4");
  script_cvs_date("Date: 2019/08/13  8:52:57");

  script_cve_id(
    "CVE-2018-16749",
    "CVE-2019-7175",
    "CVE-2019-7395",
    "CVE-2019-7396",
    "CVE-2019-7397",
    "CVE-2019-7398"
  );
  script_bugtraq_id(
    106561,
    106847,
    106848,
    106849,
    106850,
    107333
  );

  script_name(english:"ImageMagick < 7.0.8-25 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by a
denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is 7.x
prior to 7.0.8-25. It is, therefore, affected by multiple
vulnerabilities:

  - A denial of service (DoS) vulnerability exists in coders/pcd.c
    due to a memory leak in DecodeImage. An unauthenticated, remote
    attacker can exploit this issue to cause the application to stop
    responding. (CVE-2019-7175)

  - A denial of service (DoS) vulnerability exists in coders/png.c 
    due to a missing null check, a memory leak. An unauthenticated, 
    remote attacker can exploit this issue, via null PNG Images, to 
    cause the application to stop responding. (CVE-2018-16749)
    (CVE-2019-7395)

  - A denial of service (DoS) vulnerability exists in coders/sixel.c
    due to a memory leak in ReadSIXELImage. An unauthenticated,
    remote attacker can exploit this issue to cause the application 
    to stop responding.(CVE-2019-7396)

  - A denial of service (DoS) vulnerability exists in coders/pdf.c
    due to a memory leak in WritePDFImage. An unauthenticated,
    remote attacker can exploit this issue to cause the application
    to stop responding.(CVE-2019-7397)

  - A denial of service (DoS) vulnerability exists in coders/dib.c
    due to a memory leak in WriteDIBImage. An unauthenticated,
    remote attacker can exploit this issue to cause the application
    to stop responding.(CVE-2019-7397)

.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1119");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1450");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1451");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1452");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1453");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1454");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.8-25 or later. Note that you may
also need to manually uninstall the vulnerable version from the
system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-7398"); 

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/15");

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

constraints = [{'fixed_version' : '7.0.8-25'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
