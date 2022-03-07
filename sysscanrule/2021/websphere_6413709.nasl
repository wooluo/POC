##
# 
##

include('compat.inc');

if (description)
{
  script_id(146860);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/02/26");

  script_cve_id("CVE-2021-20353");
  script_xref(name:"IAVA", value:"2021-A-0104");

  script_name(english:"IBM WebSphere Application Server 7.0.0.x <= 7.0.0.45 / 8.0.0.x <= 8.0.0.15 / 8.5.x <= 8.5.5.19 / 9.0.x <= 9.0.5.6 XXE (6413709)");

  script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by a vulnerability");
  script_set_attribute(attribute:"description", value:
"The IBM WebSphere Application Server running on the remote host is version 7.0.0.0 through 7.0.0.45, 8.0.0.0 through
8.0.0.15, 8.5.0.0 through to 8.5.5.19, or 9.0.0.0 through 9.0.5.6. It is, therefore, vulnerable to an XML External 
Entity Injection (XXE) attack when processing XML data. A remote attacker could exploit this vulnerability to expose
sensitive information or consume memory resources. 

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://www.ibm.com/support/pages/node/6413709");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM WebSphere Application Server 8.5.5.20, 9.0.5.7, or later. Alternatively, upgrade to the minimal fix pack
levels required by the interim fix and then apply Interim Fix PH33228.");
  script_set_attribute(attribute:"agent", value:"all");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-20353");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/02/25");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("websphere_detect.nasl", "ibm_enum_products.nbin", "ibm_websphere_application_server_nix_installed.nbin");
  script_require_keys("installed_sw/IBM WebSphere Application Server");

  exit(0);
}

include('vcf.inc');

app = 'IBM WebSphere Application Server';
fix = 'Interim Fix PH33228';

app_info = vcf::combined_get_app_info(app:app);
vcf::check_granularity(app_info:app_info, sig_segments:4);

# If the detection is only remote, Source will be set, and we should require paranoia
if (!empty_or_null(app_info['Source']) && app_info['Source'] != 'unknown' && report_paranoia < 2)
  audit(AUDIT_PARANOID);

if ('PH33228' >< app_info['Fixes'])
  audit(AUDIT_INST_VER_NOT_VULN, app);

constraints = [
  {'min_version' : '7.0.0.0', 'max_version' : '7.0.0.45', 'fixed_display' : fix},
  {'min_version' : '8.0.0.0', 'max_version' : '8.0.0.15', 'fixed_display' : fix},
  {'min_version' : '8.5.0.0', 'max_version' : '8.5.5.19', 'fixed_display' : '8.5.5.20 or ' + fix},
  {'min_version' : '9.0.0.0', 'max_version' : '9.0.5.6',  'fixed_display' : '9.0.5.7 or ' + fix}
];    

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
