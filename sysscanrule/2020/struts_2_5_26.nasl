##
# 
##

include('compat.inc');

if (description)
{
  script_id(143599);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/12/11");

  script_cve_id("CVE-2020-17530");
  script_xref(name:"IAVA", value:"2020-A-0565");

  script_name(english:"Apache Struts 2.x < 2.5.26 RCE (S2-061)");

  script_set_attribute(attribute:"synopsis", value:
"Apache Struts installed on the remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Struts installed on the remote host is 2.x prior to 2.5.26. It is, therefore, affected by a 
a remote code execution vulnerability in its OGNL evaluation functionality due to insufficient validation of user 
input. An unauthenticated, remote attacker can exploit this to execute arbitrary commands on an affected host.

Note that Nessus has not tested for these issues but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://cwiki.apache.org/confluence/display/WW/S2-061");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Struts version 2.5.26 or later. Alternatively, apply the workarounds as referenced in the vendor 
  security bulletins.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-17530");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/11/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:struts");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("os_fingerprint.nasl", "struts_detect_win.nbin", "struts_detect_nix.nbin");
  script_require_ports("installed_sw/Apache Struts", "installed_sw/Struts");

  exit(0);
}

include('vcf.inc');

os = get_kb_item_or_exit('Host/OS');
win_local = 'windows' >< tolower(os);

app_info = vcf::get_app_info(app:'Apache Struts', win_local:win_local);
vcf::check_granularity(app_info:app_info, sig_segments:3);

constraints = [{'min_version':'2.0.0', 'fixed_version':'2.5.26'}];

vcf::check_version_and_report(
  app_info:app_info,
  constraints:constraints,
  severity:SECURITY_HOLE
);
