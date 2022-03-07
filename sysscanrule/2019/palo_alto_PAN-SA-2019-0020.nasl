#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126787);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/19  8:46:35");

  script_cve_id("CVE-2019-1579");

  script_name(english:"Palo Alto Networks PAN-OS 7.1.x < 7.1.19 / 8.0.x < 8.0.12 / 8.1.x < 8.1.3 Vulnerability");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote PAN-OS host is affected by vulnerability");
  script_set_attribute(attribute:"description", value:
"The version of Palo Alto Networks PAN-OS running on the remote host is 7.1.x prior to 7.1.19 or 8.0.x prior to 8.0.12 or
8.1.x prior to 8.1.3. It is, therefore, affected by a vulnerability. Note that GizaNE has not tested for this issue but
has instead relied only on the application's self-reported version number.");
  script_set_attribute(attribute:"see_also", value:"https://securityadvisories.paloaltonetworks.com/Home/Detail/158");
  script_set_attribute(attribute:"solution", value:
"Upgrade to PAN-OS 7.1.19 / 8.0.12 / 8.1.3 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1579");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/19");

  script_set_attribute(attribute:"plugin_type", value:"combined");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:paloaltonetworks:pan-os");
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
  { 'min_version' : '7.1.0', 'max_version' : '7.1.18', 'fixed_version' : '7.1.19' },
  { 'min_version' : '8.0.0', 'max_version' : '8.0.11', 'fixed_version' : '8.0.12' },
  { 'min_version' : '8.1.0', 'max_version' : '8.1.2', 'fixed_version' : '8.1.3' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
