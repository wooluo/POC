#
# 
#

include('compat.inc');

if (description)
{
  script_id(138215);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/07/09");

  script_cve_id(
    "CVE-2019-20503",
    "CVE-2020-6422",
    "CVE-2020-6424",
    "CVE-2020-6425",
    "CVE-2020-6426",
    "CVE-2020-6427",
    "CVE-2020-6428",
    "CVE-2020-6429",
    "CVE-2020-6449"
  );

  script_name(english:"Microsoft Edge (Chromium) < 80.0.361.69 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an web browser installed that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Edge (Chromium) installed on the remote Windows host is prior to 80.0.361.69. It is,
therefore, affected by multiple vulnerabilities:

  - A use-after-free error exists in the WebGL component of Microsoft Edge (Chromium). An unauthenticated,
    remote attacker can exploit this, via a crafted HTML page, to potentially exploit heap corruption.
    (CVE-2020-6422)

  - A use-after-free error exists in the media component of Microsoft Edge (Chromium). An unauthenticated,
    remote attacker can exploit this, via a crafted HTML page, to potentially exploit heap corruption.
    (CVE-2020-6424)

  - A use-after-free error exists in the audio component of Microsoft Edge (Chromium). An unauthenticated,
    remote attacker can exploit this, via a crafted HTML page, to potentially exploit heap corruption.
    (CVE-2020-6427)

In addition, Microsoft Edge (Chromium) is also affected by several additional vulnerabilities and errors including
additional use-after-free vulnerabilities, an out-of-bounds read, and an insufficient policy enforcement. Note that
Nessus has not tested for these issues but has instead relied only on the application's self-reported version number.");
  # https://portal.msrc.microsoft.com/en-us/security-guidance/advisory/ADV200002
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b4f0f972");
  # https://docs.microsoft.com/en-us/deployedge/microsoft-edge-relnotes-security
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?2ec7f076");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Microsoft Edge (Chromium) 80.0.361.69 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-6422");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/03/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/07/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:edge");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("microsoft_edge_chromium_installed.nbin");
  script_require_keys("installed_sw/Microsoft Edge (Chromium)", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

app_info = vcf::get_app_info(app:'Microsoft Edge (Chromium)', win_local:TRUE);

constraints = [{ 'fixed_version' : '80.0.361.69' }];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
