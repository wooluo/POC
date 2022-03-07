#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126638);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/13  8:52:57");

  script_cve_id(
    "CVE-2019-12974",
    "CVE-2019-12975",
    "CVE-2019-12976",
    "CVE-2019-12977",
    "CVE-2019-12978",
    "CVE-2019-12979"
  );
  script_bugtraq_id(108913);

  script_name(english:"ImageMagick < 7.0.8-35 Multiple vulnerabilities");
  script_summary(english:"Checks the version of ImageMagick.");

  script_set_attribute(attribute:"synopsis", value:
"An application installed on the remote Windows host is affected by multiple vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of ImageMagick installed on the remote Windows host is prior to 7.0.8-35. It is, therefore, affected by
multiple vulnerabilities:

  - A 'use of uninitialized value' vulnerability in the WriteJP2Image function in coders/jp2.c. (CVE-2019-12977)

  - A 'use of uninitialized value' vulnerability in the ReadPANGOImage function in coders/pango.c. (CVE-2019-12978)

  - A 'use of uninitialized value' vulnerability in the SyncImageSettings function in MagickCore/image.c. This is
    related to AcquireImage in magick/image.c. (CVE-2019-12979)

Note that the application may also be affected by additional
vulnerabilities. Refer to the vendor for additional information.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1515");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1517");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1520");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1518");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1519");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1522");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.8-35 or later. Note that you may
also need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12977");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/12");

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

constraints = [{'fixed_version' : '7.0.8-35'}];
vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
