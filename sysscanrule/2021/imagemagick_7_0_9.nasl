
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152959);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/09/03");

  script_cve_id("CVE-2020-27768");
  script_xref(name:"IAVB", value:"2020-B-0076-S");

  script_name(english:"ImageMagick 7.0.0 < 7.0.9-0 Denial of Service");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application installed that is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of ImageMagick installed that is prior to 7.0.x prior to 7.0.9-0. It is,
therefore, affected by a denial of service (DoS) vulnerability in magick/quantum-private.h due to improper checking of
values assgined to type of 'unsigned int'. An unauthenticated, local attacker can exploit this issue, to cause the
application to stop responding.");
  script_set_attribute(attribute:"see_also", value:"https://github.com/ImageMagick/ImageMagick/issues/1751");
  # https://github.com/ImageMagick/ImageMagick6/commit/8c6e86f81968fab1710317d87b00c608108e6a2a
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?31f91467");
  script_set_attribute(attribute:"solution", value:
"Upgrade to ImageMagick version 7.0.9-0 or later.

Note that you may need to manually uninstall the vulnerable version from the system.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-27768");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/09/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:imagemagick:imagemagick");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("imagemagick_installed.nasl");
  script_require_keys("installed_sw/ImageMagick");

  exit(0);
}

include('vcf.inc');
include('vcf_extras.inc');

vcf::imagemagick::initialize();
var app_info = vcf::imagemagick::get_app_info();

var constraints = [{'min_version' : '7.0.0',  'fixed_version' : '7.0.9.0'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
