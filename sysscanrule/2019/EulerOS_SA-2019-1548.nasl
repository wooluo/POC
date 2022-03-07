#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125001);
  script_version("1.4");
  script_cvs_date("Date: 2019/06/27 13:33:26");

  script_cve_id(
    "CVE-2007-5135",
    "CVE-2009-0590",
    "CVE-2009-1377",
    "CVE-2009-1386",
    "CVE-2009-4355",
    "CVE-2011-4108",
    "CVE-2012-2110",
    "CVE-2014-3507",
    "CVE-2014-3571",
    "CVE-2014-8176",
    "CVE-2014-8275",
    "CVE-2015-0209",
    "CVE-2015-0286",
    "CVE-2015-0293",
    "CVE-2015-1789",
    "CVE-2015-1791",
    "CVE-2015-1792",
    "CVE-2015-4000",
    "CVE-2016-0703",
    "CVE-2019-1559"
  );
  script_bugtraq_id(
    25831,
    31692,
    34256,
    35001,
    35174,
    51281,
    53158,
    69078,
    71935,
    71937,
    73196,
    73225,
    73232,
    73239,
    74107,
    74733,
    75154,
    75156,
    75159,
    75161,
    75769
  );

  script_name(english:"EulerOS Virtualization 3.0.1.0 : openssl (EulerOS-SA-2019-1548)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl packages installed, the
EulerOS Virtualization installation on the remote host is affected by
the following vulnerabilities :

  - A race condition was found in the session handling code
    of OpenSSL. This issue could possibly cause a
    multi-threaded TLS/SSL client using OpenSSL to double
    free session ticket data and crash.(CVE-2015-1791)

  - An out-of-bounds read flaw was found in the
    X509_cmp_time() function of OpenSSL, which is used to
    test the expiry dates of SSL/TLS certificates. An
    attacker could possibly use a specially crafted SSL/TLS
    certificate or CRL (Certificate Revocation List), which
    when parsed by an application would cause that
    application to crash.(CVE-2015-1789)

  - The ASN1_STRING_print_ex function in OpenSSL before
    0.9.8k allows remote attackers to cause a denial of
    service (invalid memory access and application crash)
    via vectors that trigger printing of a (1) BMPString or
    (2) UniversalString with an invalid encoded
    length.(CVE-2009-0590)

  - An invalid-free flaw was found in the way OpenSSL
    handled certain DTLS handshake messages. A malicious
    DTLS client or server could send a specially crafted
    message to the peer, which could cause the application
    to crash or potentially result in arbitrary code
    execution.(CVE-2014-8176)

  - The DTLS implementation in OpenSSL before 0.9.8s and
    1.x before 1.0.0f performs a MAC check only if certain
    padding is valid, which makes it easier for remote
    attackers to recover plaintext via a padding oracle
    attack.(CVE-2011-4108)

  - Off-by-one error in the SSL_get_shared_ciphers function
    in OpenSSL 0.9.7 up to 0.9.7l, and 0.9.8 up to 0.9.8f,
    might allow remote attackers to execute arbitrary code
    via a crafted packet that triggers a one-byte buffer
    underflow. NOTE: this issue was introduced as a result
    of a fix for CVE-2006-3738. As of 20071012, it is
    unknown whether code execution is
    possible.(CVE-2007-5135)

  - A NULL pointer dereference flaw was found in the DTLS
    implementation of OpenSSL. A remote attacker could send
    a specially crafted DTLS message, which would cause an
    OpenSSL server to crash.(CVE-2014-3571)

  - The asn1_d2i_read_bio function in
    crypto/asn1/a_d2i_fp.c in OpenSSL before 0.9.8v, 1.0.0
    before 1.0.0i, and 1.0.1 before 1.0.1a does not
    properly interpret integer data, which allows remote
    attackers to conduct buffer overflow attacks, and cause
    a denial of service (memory corruption) or possibly
    have unspecified other impact, via crafted DER data, as
    demonstrated by an X.509 certificate or an RSA public
    key.(CVE-2012-2110)

  - It was discovered that the SSLv2 servers using OpenSSL
    accepted SSLv2 connection handshakes that indicated
    non-zero clear key length for non-export cipher suites.
    An attacker could use this flaw to decrypt recorded
    SSLv2 sessions with the server by using it as a
    decryption oracle.(CVE-2016-0703)

  - ssl/s3_pkt.c in OpenSSL before 0.9.8i allows remote
    attackers to cause a denial of service (NULL pointer
    dereference and daemon crash) via a DTLS
    ChangeCipherSpec packet that occurs before
    ClientHello.(CVE-2009-1386)

  - Memory leak in the zlib_stateful_finish function in
    crypto/comp/c_zlib.c in OpenSSL 0.9.8l and earlier and
    1.0.0 Beta through Beta 4 allows remote attackers to
    cause a denial of service (memory consumption) via
    vectors that trigger incorrect calls to the
    CRYPTO_cleanup_all_ex_data function, as demonstrated by
    use of SSLv3 and PHP with the Apache HTTP Server, a
    related issue to CVE-2008-1678.(CVE-2009-4355)

  - A flaw was discovered in the way OpenSSL handled DTLS
    packets. A remote attacker could use this flaw to cause
    a DTLS server or client using OpenSSL to crash or use
    excessive amounts of memory.(CVE-2014-3507)

  - The dtls1_buffer_record function in ssl/d1_pkt.c in
    OpenSSL 0.9.8k and earlier 0.9.8 versions allows remote
    attackers to cause a denial of service (memory
    consumption) via a large series of 'future epoch' DTLS
    records that are buffered in a queue, aka 'DTLS record
    buffer limitation bug.'(CVE-2009-1377)

  - A use-after-free flaw was found in the way OpenSSL
    imported malformed Elliptic Curve private keys. A
    specially crafted key file could cause an application
    using OpenSSL to crash when imported.(CVE-2015-0209)

  - A denial of service flaw was found in the way OpenSSL
    verified certain signed messages using CMS
    (Cryptographic Message Syntax). A remote attacker could
    cause an application using OpenSSL to use excessive
    amounts of memory by sending a specially crafted
    message for verification.(CVE-2015-1792)

  - A denial of service flaw was found in the way OpenSSL
    handled SSLv2 handshake messages. A remote attacker
    could use this flaw to cause a TLS/SSL server using
    OpenSSL to exit on a failed assertion if it had both
    the SSLv2 protocol and EXPORT-grade cipher suites
    enabled.(CVE-2015-0293)

  - An invalid pointer use flaw was found in OpenSSL's
    ASN1_TYPE_cmp() function. A remote attacker could crash
    a TLS/SSL client or server using OpenSSL via a
    specially crafted X.509 certificate when the
    attacker-supplied certificate was verified by the
    application.(CVE-2015-0286)

  - Multiple flaws were found in the way OpenSSL parsed
    X.509 certificates. An attacker could use these flaws
    to modify an X.509 certificate to produce a certificate
    with a different fingerprint without invalidating its
    signature, and possibly bypass fingerprint-based
    blacklisting in applications.(CVE-2014-8275)

  - If an application encounters a fatal protocol error and
    then calls SSL_shutdown() twice (once to send a
    close_notify, and once to receive one) then OpenSSL can
    respond differently to the calling application if a 0
    byte record is received with invalid padding compared
    to if a 0 byte record is received with an invalid MAC.
    If the application then behaves differently based on
    that in a way that is detectable to the remote peer,
    then this amounts to a padding oracle that could be
    used to decrypt data. In order for this to be
    exploitable 'non-stitched' ciphersuites must be in use.
    Stitched ciphersuites are optimised implementations of
    certain commonly used ciphersuites. Also the
    application must call SSL_shutdown() twice even if a
    protocol error has occurred (applications should not do
    this but some do anyway). Fixed in OpenSSL 1.0.2r
    (Affected 1.0.2-1.0.2q).(CVE-2019-1559)

  - A flaw was found in the way the TLS protocol composes
    the Diffie-Hellman exchange (for both export and
    non-export grade cipher suites). An attacker could use
    this flaw to downgrade a DHE connection to use
    export-grade key sizes, which could then be broken by
    sufficient pre-computation. This can lead to a passive
    man-in-the-middle attack in which the attacker is able
    to decrypt all traffic.(CVE-2015-4000)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1548
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:uvp:3.0.1.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
uvp = get_kb_item("Host/EulerOS/uvp_version");
if (uvp != "3.0.1.0") audit(AUDIT_OS_NOT, "EulerOS Virtualization 3.0.1.0");
if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "aarch64" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_ARCH_NOT, "i686 / x86_64", cpu);

flag = 0;

pkgs = ["openssl-1.0.2k-16.h5",
        "openssl-devel-1.0.2k-16.h5",
        "openssl-libs-1.0.2k-16.h5"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", reference:pkg)) flag++;

if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_HOLE,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl");
}
