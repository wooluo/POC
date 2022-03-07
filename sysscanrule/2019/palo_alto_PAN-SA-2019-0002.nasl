#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122348);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/18 15:47:53");

  script_cve_id("CVE-2019-1566");
  script_bugtraq_id(106750);

  script_name(english:"Palo Alto Networks 7.1.x < 7.1.22 / 8.0.x < 8.0.15 / 8.1.x < 8.1.6 Multiple Vulnerabilities (PAN-SA-2019-0002)");
  script_summary(english:"Checks the PAN-OS version.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The version of Palo Alto Networks PAN-OS running on the remote host is
 7.1.x prior to 7.1.22 or 8.0.x prior to 8.0.15 
or 8.1.x prior to 8.1.6. It is, therefore, affected by multiple 
vulnerabilities :

  - A cross-site scripting (XSS) vulnerability exists in Management Web
    Interface of PAN-OS due to improper validation of user-supplied
    input before returning it to users. An unauthenticated, remote attacker
    can exploit this, by convincing a user to click a specially crafted
    URL, to execute arbitrary script code in a user's browser session.
    (CVE-2019-1566)");
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Palo Alto Networks PAN-OS version 7.1.22 / 8.0.15 / 8.1.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1566");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/01/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/20");

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

include("vcf.inc");

app_name = "Palo Alto Networks PAN-OS";

app_info = vcf::get_app_info(app:app_name, kb_ver:"Host/Palo_Alto/Firewall/Full_Version", webapp:true);

vcf::check_granularity(app_info:app_info, sig_segments:2);

constraints = [
  { "min_version" : "7.1", "fixed_version" : "7.1.22" },
  { "min_version" : "8.0", "fixed_version" : "8.0.15" },
  { "min_version" : "8.1", "fixed_version" : "8.1.6" }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING, flags:{xss:TRUE});
