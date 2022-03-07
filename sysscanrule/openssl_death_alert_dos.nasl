include("compat.inc");

if (description)
{
  script_id(51799013);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/01/16 14:51:33 $");

  script_cve_id("CVE-2016-8610");
  script_bugtraq_id(93841);

  script_name(english:"OpenSSL Death Alert Denial of Service Vulnerability");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"This host is running OpenSSL and is prone to a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The flaw is due to an error in function
'ssl3_read_bytes' in ssl/s3_pkt.c script which might lead to higher CPU usage
due to improper handling of warning packets.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2016/q4/224");
  script_set_attribute(attribute:"see_also", value:"https://git.openssl.org/gitweb/?p=openssl.git;a=commit;h=af58be768ebb690f78530f796e92b8ae5c9a4401");
  script_set_attribute(attribute:"see_also", value:"https://securingtomorrow.mcafee.com/mcafee-labs/ssl-death-alert-cve-2016-8610-can-cause-denial-of-service-to-openssl-servers");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2j or 1.1.0bor later.");

  script_set_attribute(attribute:"risk_factor", value: "High" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/01/16");
  #script_set_attribute(attribute:"patch_publication_date", value:"2016/08/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/16");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2016-2017 WebRAY, Inc.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

fixs = make_list('0.9.8a', '1.0.1a', '1.0.2i', '1.1.0a');
openssl_check_version(fixed:fixs, severity:SECURITY_WARNING);
