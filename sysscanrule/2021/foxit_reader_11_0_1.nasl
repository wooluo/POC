
##
# 
##



include('compat.inc');

if (description)
{
  script_id(152161);
  script_version("1.2");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/02");

  script_cve_id("CVE-2021-21831", "CVE-2021-21870", "CVE-2021-21893");
  script_xref(name:"IAVA", value:"2021-A-0357");

  script_name(english:"Foxit Reader < 11.0.1 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF viewer installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit Reader application installed on the remote Windows host is prior to 11.0.1. It is,
therefore affected by multiple arbitrary code execution vulnerabilities due to a use-after-free flaw in the JavaScript
engine. An authenticated, local attacker can exploit this by persuading a victim to open a specially-crafted PDF file,
to execute arbitrary code on the system.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 11.0.1 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-21870");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/07/30");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app = 'Foxit Reader';
var app_info = vcf::get_app_info(app:app, win_local:TRUE);

var constraints = [
  { 'max_version' : '11.0.0.49893', 'fixed_version' : '11.0.1' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
