#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122504);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/22 16:57:38");

  script_cve_id("CVE-2019-1559");
  script_bugtraq_id(107174);

  script_name(english:"OpenSSL 1.0.x < 1.0.2r Information Disclosure Vulnerability");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"A service running on the remote host is affected by an information
disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its banner, the version of OpenSSL running on the remote
host is 1.0.x prior to 1.0.2r. It is, therefore, affected by an
information disclosure vulnerability due to the decipherable way a
application responds to a 0 byte record. An unauthenticated, remote
attacker could exploit this vulnerability, via a padding oracle
attack, to potentially disclose sensitive information.

Note: Only 'non-stitched' ciphersuites are exploitable.");
  # https://mta.openssl.org/pipermail/openssl-announce/2019-February/000145.html 
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20190226.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.0.2r or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1559");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:'1.0.2r', min:"1.0.2", severity:SECURITY_WARNING);

