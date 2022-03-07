#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128034);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/21  9:43:47");

  script_cve_id("CVE-2019-1933");
  script_bugtraq_id(109031);
  script_xref(name:"CISCO-BUG-ID", value:"CSCvo55451");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20190703-esa-filterpass");

  script_name(english:"Cisco Email Security Appliance Content Filter Bypass Vulnerability (cisco-sa-20190703-esa-filterpass)");
  script_summary(english:"Checks the version of Cisco Email Security Appliance (ESA)");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is missing a vendor-supplied security patch.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version, Cisco Email Security
Appliance (ESA) is affected by a vulnerability in the email message
scanning of Cisco AsyncOS Software due to improper input validation
of certain email fields. An unauthenticated, remote attacker can
exploit this vulnerability by sending a crafted email message to a
recipient protected by the ESA. A successful exploit allows the
attacker to bypass configured message filters and inject arbitrary
scripting code inside the email body. The malicious code is not
executed by default unless the recipient's email client is configured
to execute scripts contained in emails.

Please see the included Cisco BID and Cisco Security Advisory for
more information.");
  # https://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20190703-esa-filterpass
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://bst.cloudapps.cisco.com/bugsearch/bug/CSCvo55451");
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant fixed version referenced in Cisco bug ID
CSCvo55451.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:H/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1933");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:email_security_appliance_(esa)");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CISCO");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("cisco_esa_version.nasl");
  script_require_keys("Host/AsyncOS/Cisco Email Security Appliance/Version", "Settings/ParanoidReport");

  exit(0);
}

include('audit.inc');
include('cisco_workarounds.inc');
include('ccf.inc');

if (report_paranoia < 2) audit(AUDIT_PARANOID);

product_info = cisco::get_product_info(name:'Cisco Email Security Appliance (ESA)');

version_list=make_list(
  '10.0.2-020',
  '11.1.2-023'
);

workarounds = make_list(CISCO_WORKAROUNDS['no workaround']);
workaround_params = make_list();


reporting = make_array(
'port'     , 0,
'severity' , SECURITY_HOLE,
'version'  , product_info['version'],
'bug_id'   , 'CSCvo55451'
);

cisco::check_and_report(product_info:product_info, workarounds:workarounds, workaround_params:workaround_params, reporting:reporting, vuln_versions:version_list);
