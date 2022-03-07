#
# 
#

include('compat.inc');

if (description)
{
  script_id(135919);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2020/04/29");

  script_cve_id("CVE-2020-1967");

  script_name(english:"OpenSSL 1.1.1 < 1.1.1g Vulnerability");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 1.1.1g advisory.

  - Server or client applications that call the
    SSL_check_chain() function during or after a TLS 1.3
    handshake may crash due to a NULL pointer dereference as
    a result of incorrect handling of the
    signature_algorithms_cert TLS extension. The crash
    occurs if an invalid or unrecognised signature algorithm
    is received from the peer. This could be exploited by a
    malicious peer in a Denial of Service attack. OpenSSL
    version 1.1.1d, 1.1.1e, and 1.1.1f are affected by this
    issue. This issue did not affect OpenSSL versions prior
    to 1.1.1d. Fixed in OpenSSL 1.1.1g (Affected
    1.1.1d-1.1.1f). (CVE-2020-1967)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/openssl/openssl/commit/eb563247aef3e83dda7679c43f9649270462e5b1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5929f842");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20200421.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.1g or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2020-1967");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");

  script_set_attribute(attribute:"vuln_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2020/04/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2020/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2020 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:"1.1.1g", min:"1.1.1d", severity:SECURITY_WARNING);
