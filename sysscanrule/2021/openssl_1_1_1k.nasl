##
# 
##

include('compat.inc');

if (description)
{
  script_id(148125);
  script_version("1.4");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/04/01");

  script_cve_id("CVE-2021-3449", "CVE-2021-3450");
  script_xref(name:"IAVA", value:"2021-A-0149");

  script_name(english:"OpenSSL 1.1.1 < 1.1.1k Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"The remote service is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of OpenSSL installed on the remote host is prior to 1.1.1k. It is, therefore, affected by
multiple vulnerabilities as referenced in the 1.1.1k advisory.

  - The X509_V_FLAG_X509_STRICT flag enables additional security checks of the certificates present in a
    certificate chain. It is not set by default. Starting from OpenSSL version 1.1.1h a check to disallow
    certificates in the chain that have explicitly encoded elliptic curve parameters was added as an
    additional strict check. An error in the implementation of this check meant that the result of a previous
    check to confirm that certificates in the chain are valid CA certificates was overwritten. This
    effectively bypasses the check that non-CA certificates must not be able to issue other certificates. If a
    purpose has been configured then there is a subsequent opportunity for checks that the certificate is a
    valid CA. All of the named purpose values implemented in libcrypto perform this check. Therefore, where
    a purpose is set the certificate chain will still be rejected even when the strict flag has been used. A
    purpose is set by default in libssl client and server certificate verification routines, but it can be
    overridden or removed by an application. In order to be affected, an application must explicitly set the
    X509_V_FLAG_X509_STRICT verification flag and either not set a purpose for the certificate verification
    or, in the case of TLS client or server applications, override the default purpose. OpenSSL versions
    1.1.1h and newer are affected by this issue. Users of these versions should upgrade to OpenSSL 1.1.1k.
    OpenSSL 1.0.2 is not impacted by this issue. Fixed in OpenSSL 1.1.1k (Affected 1.1.1h-1.1.1j).
    (CVE-2021-3450)

  - An OpenSSL TLS server may crash if sent a maliciously crafted renegotiation ClientHello message from a
    client. If a TLSv1.2 renegotiation ClientHello omits the signature_algorithms extension (where it was
    present in the initial ClientHello), but includes a signature_algorithms_cert extension then a NULL
    pointer dereference will result, leading to a crash and a denial of service attack. A server is only
    vulnerable if it has TLSv1.2 and renegotiation enabled (which is the default configuration). OpenSSL TLS
    clients are not impacted by this issue. All OpenSSL 1.1.1 versions are affected by this issue. Users of
    these versions should upgrade to OpenSSL 1.1.1k. OpenSSL 1.0.2 is not impacted by this issue. Fixed in
    OpenSSL 1.1.1k (Affected 1.1.1-1.1.1j). (CVE-2021-3449)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://github.com/openssl/openssl/commit/2a40b7bc7b94dd7de897a74571e7024f0cf0d63b
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?d4121cee");
  script_set_attribute(attribute:"see_also", value:"https://www.openssl.org/news/secadv/20210325.txt");
  # https://github.com/openssl/openssl/commit/fb9fa6b51defd48157eeb207f52181f735d96148
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c12dbbc1");
  script_set_attribute(attribute:"solution", value:
"Upgrade to OpenSSL version 1.1.1k or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-3450");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/03/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:openssl:openssl");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("openssl_version.nasl");
  script_require_keys("openssl/port");

  exit(0);
}

include('openssl_version.inc');

openssl_check_version(fixed:'1.1.1k', min:'1.1.1', severity:SECURITY_WARNING);
