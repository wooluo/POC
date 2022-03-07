#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126786);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19  8:37:25");

  script_cve_id("CVE-2019-1575");
  script_bugtraq_id(109176);
  script_xref(name:"IAVA", value:"2019-A-0247");

  script_name(english:"Palo Alto Networks PAN-OS 7.1.x < 7.1.24 / 8.0.x < 8.0.19 / 8.1.x < 8.1.8-h5 / 9.0.x < 9.0.2-h4 Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is 7.1.x prior to 7.1.24 or 8.0.x prior to 8.0.19 or
8.1.x prior to 8.1.8-h5 or 9.0.x prior to 9.0.2-h4. It is, therefore, affected by an information disclosure vulnerability
in the management API which could lead to the disclosure of API keys and credentials which could be leveraged for an
escalation of privilege.

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/157");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS 7.1.24 / 8.0.19 / 8.1.8-h5 / 9.0.2-h4 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:L/A:L");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1575");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Palo Alto Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("palo_alto_version.nbin");
  script_require_keys("Host/Palo_Alto/Firewall/Version", "Host/Palo_Alto/Firewall/Full_Version");

  exit(0);
}

include('vcf.inc');

app_name = 'Palo Alto Networks PAN-OS';

app_info = vcf::get_app_info(app:app_name, kb_ver:'Host/Palo_Alto/Firewall/Full_Version', webapp:true);

constraints = [
  { 'min_version' : '7.1.0', 'max_version' : '7.1.23', 'fixed_version' : '7.1.24' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.18', 'fixed_version' : '8.0.19' },
  { 'min_version' : '8.1.0', 'max_version' : '8.1.8-h4', 'fixed_version' : '8.1.8-h5' },
  { 'min_version' : '9.0.0', 'max_version' : '9.0.2', 'fixed_version' : '9.0.2-h4' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
