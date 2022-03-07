
##
# 
##



include('compat.inc');

if (description)
{
  script_id(150162);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/06/07");

  script_cve_id("CVE-2021-3426");
  script_xref(name:"IAVA", value:"2021-A-0263");

  script_name(english:"Python Information Disclosure (CVE-2021-3426)");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application installed that is affected by an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Python installed on the remote Windows host is potentially affected by an information disclosure
vulnerability due to an issue in Python 3's pydoc. An authenticated local or adjacent attacker can exploit this, by
convincing another local or adjacent user to start a pydoc server could access the server and use it to disclose
sensitive information belonging to the other user that they would not normally be able to access.

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://bugzilla.redhat.com/show_bug.cgi?id=1935913");
  script_set_attribute(attribute:"see_also", value:"https://bugs.python.org/issue42988");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Python 3.8.9, 3.9.3, 3.10.0a7, or later.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:L/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:A/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3426");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/04/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/06/03");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:python:python");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("python_win_installed.nbin");
  script_require_keys("installed_sw/Python Software Foundation Python", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

get_kb_item_or_exit('SMB/Registry/Enumerated');

var app_info = vcf::get_app_info(app:'Python Software Foundation Python', win_local:TRUE);

var constraints = [
  {'min_version':'3.6',   'fixed_version' : '3.8.9150.1013', 'fixed_display':'3.8.9' },
  {'min_version':'3.9',   'fixed_version' : '3.9.3150.1013', 'fixed_display':'3.9.3' },
  {'min_version':'3.10',  'fixed_version' : '3.10.107.1013', 'fixed_display':'3.10.0a7' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_NOTE);
