#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126246);
  script_version("1.3");
  script_cvs_date("Date: 2019/08/22 16:57:38");

  script_cve_id("CVE-2019-5439", "CVE-2019-12874");
  script_bugtraq_id(108769,108882);

  script_name(english:"VLC < 3.0.7 Multiple Vulnerabilities");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by a
multiple vulnerabilities."
  );
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote host is earlier
than 3.0.7.  It is, therefore, affected by multiple vulnerabilities:

  - A heap-based buffer overflow condition exists in ReadFrame 
    due to improper parsing of AVI files. A remote attacker can 
    exploit this by tricking a user into opening a specially 
    crafted avi file to cause a denial of service condition 
    or the execution of arbitrary code.(CVE-2019-5439)

  - A double free vulnerability exists in zlib_decompress_extra
    due to improper parsing of MKV files. A remote attacker can 
    exploit this by tricking a user into opening a specially 
    crafted MKV file to cause a denial of service condition 
    or the execution of arbitrary code.(CVE-2019-12874)"
  );
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/developers/vlc-branch/NEWS");
  script_set_attribute(attribute:"see_also", value:"https://www.videolan.org/security/sa1901.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to VLC version 3.0.7 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-12874");
  script_set_attribute(attribute:"cvss_score_rationale", value:"Score based on in depth analysis of the vendor advisory by WebRAY.");
  
  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/25");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}

include("vcf.inc");

app_info = vcf::get_app_info(app:"VLC media player", win_local:TRUE);

constraints = [{"fixed_version":"3.0.7"}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
