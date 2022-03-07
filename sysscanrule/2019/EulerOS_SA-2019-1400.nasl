#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124903);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2014-3566",
    "CVE-2017-3735",
    "CVE-2018-0495",
    "CVE-2018-0732",
    "CVE-2018-0737",
    "CVE-2018-0739",
    "CVE-2019-1559"
  );
  script_bugtraq_id(
    70574
  );

  script_name(english:"EulerOS Virtualization for ARM 64 3.0.1.0 : openssl (EulerOS-SA-2019-1400)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS Virtualization for ARM 64 host is missing multiple security
updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the openssl packages installed, the
EulerOS Virtualization for ARM 64 installation on the remote host is
affected by the following vulnerabilities :

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

  - Constructed ASN.1 types with a recursive definition
    (such as can be found in PKCS7) could eventually exceed
    the stack given malicious input with excessive
    recursion. This could result in a Denial Of Service
    attack. There are no such structures used within
    SSL/TLS that come from untrusted sources so this is
    considered safe. Fixed in OpenSSL 1.1.0h (Affected
    1.1.0-1.1.0g). Fixed in OpenSSL 1.0.2o (Affected
    1.0.2b-1.0.2n).(CVE-2018-0739)

  - OpenSSL RSA key generation was found to be vulnerable
    to cache side-channel attacks. An attacker with
    sufficient access to mount cache timing attacks during
    the RSA key generation process could recover parts of
    the private key.(CVE-2018-0737)

  - During key agreement in a TLS handshake using a DH(E)
    based ciphersuite a malicious server can send a very
    large prime value to the client. This will cause the
    client to spend an unreasonably long period of time
    generating a key for this prime resulting in a hang
    until the client has finished. This could be exploited
    in a Denial Of Service attack. Fixed in OpenSSL
    1.1.0i-dev (Affected 1.1.0-1.1.0h). Fixed in OpenSSL
    1.0.2p-dev (Affected 1.0.2-1.0.2o).(CVE-2018-0732)

  - While parsing an IPAddressFamily extension in an X.509
    certificate, it is possible to do a one-byte overread.
    This would result in an incorrect text display of the
    certificate. This bug has been present since 2006 and
    is present in all versions of OpenSSL before 1.0.2m and
    1.1.0g.(CVE-2017-3735)

  - Libgcrypt before 1.7.10 and 1.8.x before 1.8.3 allows a
    memory-cache side-channel attack on ECDSA signatures
    that can be mitigated through the use of blinding
    during the signing process in the _gcry_ecc_ecdsa_sign
    function in cipher/ecc-ecdsa.c, aka the Return Of the
    Hidden Number Problem or ROHNP. To discover an ECDSA
    key, the attacker needs access to either the local
    machine or a different virtual machine on the same
    physical host.(CVE-2018-0495)

  - A flaw was found in the way SSL 3.0 handled padding
    bytes when decrypting messages encrypted using block
    ciphers in cipher block chaining (CBC) mode. This flaw
    allows a man-in-the-middle (MITM) attacker to decrypt a
    selected byte of a cipher text in as few as 256 tries
    if they are able to force a victim application to
    repeatedly send the same data over newly created SSL
    3.0 connections.(CVE-2014-3566)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1400
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/07");
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
if ("aarch64" >!< cpu) audit(AUDIT_ARCH_NOT, "aarch64", cpu);

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
    severity   : SECURITY_WARNING,
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
