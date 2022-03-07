#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(128117);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/23 11:22:11");

  script_cve_id("CVE-2019-1552");
  script_xref(name:"IAVA", value:"2019-A-0303");
  
  script_name(english:"OpenSSL 1.1.0 < 1.1.0l Vulnerability");
  script_summary(english:"Performs a banner check.");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by a vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of tested product installed on the remote host is prior to tested version. It is, therefore, affected by a
vulnerability as referenced in the 1.1.0l advisory.

  - OpenSSL has internal defaults for a directory tree where
    it can find a configuration file as well as certificates
    used for verification in TLS. This directory is most
    commonly referred to as OPENSSLDIR, and is configurable
    with the --prefix / --openssldir configuration options.
    For OpenSSL versions 1.1.0 and 1.1.1, the mingw
    configuration targets assume that resulting programs and
    libraries are installed in a Unix-like environment and
    the default prefix for program installation as well as
    for OPENSSLDIR should be '/usr/local'. However, mingw
    programs are Windows programs, and as such, find
    themselves looking at sub-directories of 'C:/usr/local',
    which may be world writable, which enables untrusted
    users to modify OpenSSL's default configuration, insert
    CA certificates, modify (or even replace) existing
    engine modules, etc. For OpenSSL 1.0.2, '/usr/local/ssl'
    is used as default for OPENSSLDIR on all Unix and
    Windows targets, including Visual C builds. However,
    some build instructions for the diverse Windows targets
    on 1.0.2 encourage you to specify your own --prefix.
    OpenSSL versions 1.1.1, 1.1.0 and 1.0.2 are affected by
    this issue. Due to the limited scope of affected
    deployments this has been assessed as low severity and
    therefore we are not creating new releases at this time.
    (CVE-2019-1552)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/openssl/openssl/commit/b15a19c148384e73338aa7c5b12652138e35ed28
  script_set_attribute(attribute:"see_also", value:"");
  # https://github.com/openssl/openssl/commit/e32bc855a81a2d48d215c506bdeb4f598045f7e9
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20190730.txt");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.0l or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-1552");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include("openssl_version.inc");

openssl_check_version(fixed:"1.1.0l", min:"1.1.0", severity:SECURITY_NOTE);