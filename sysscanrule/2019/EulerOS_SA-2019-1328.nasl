#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124614);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2019-1543"
  );

  script_name(english:"EulerOS 2.0 SP3 : openssl110f (EulerOS-SA-2019-1328)");
  script_summary(english:"Checks the rpm output for the updated package.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to the version of the openssl110f packages installed, the
EulerOS installation on the remote host is affected by the following
vulnerability :

  - ChaCha20-Poly1305 is an AEAD cipher, and requires a
    unique nonce input for every encryption operation. RFC
    7539 specifies that the nonce value (IV) should be 96
    bits (12 bytes). OpenSSL allows a variable nonce length
    and front pads the nonce with 0 bytes if it is less
    than 12 bytes. However it also incorrectly allows a
    nonce to be set of up to 16 bytes. In this case only
    the last 12 bytes are significant and any additional
    leading bytes are ignored. It is a requirement of using
    this cipher that nonce values are unique. Messages
    encrypted using a reused nonce value are susceptible to
    serious confidentiality and integrity attacks. If an
    application changes the default nonce length to be
    longer than 12 bytes and then makes a change to the
    leading bytes of the nonce expecting the new value to
    be a new unique nonce then such an application could
    inadvertently encrypt messages with a reused nonce.
    Additionally the ignored bytes in a long nonce are not
    covered by the integrity guarantee of this cipher. Any
    application that relies on the integrity of these
    ignored leading bytes of a long nonce may be further
    affected. Any OpenSSL internal use of this cipher,
    including in SSL/TLS, is safe because no such use sets
    such a long nonce value. However user applications that
    use this cipher directly and set a non-default nonce
    length to be longer than 12 bytes may be vulnerable.
    OpenSSL versions 1.1.1 and 1.1.0 are affected by this
    issue. Due to the limited scope of affected deployments
    this has been assessed as low severity and therefore we
    are not creating new releases at this
    time.(CVE-2019-1543)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1328
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected openssl110f package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl110f");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl110f-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl110f-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:openssl110f-static");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:huawei:euleros:2.0");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Huawei Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/EulerOS/release", "Host/EulerOS/rpm-list", "Host/EulerOS/sp");
  script_exclude_keys("Host/EulerOS/uvp_version");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/EulerOS/release");
if (isnull(release) || release !~ "^EulerOS") audit(AUDIT_OS_NOT, "EulerOS");
if (release !~ "^EulerOS release 2\.0(\D|$)") audit(AUDIT_OS_NOT, "EulerOS 2.0");

sp = get_kb_item("Host/EulerOS/sp");
if (isnull(sp) || sp !~ "^(3)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP3", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["openssl110f-1.1.0f-5.h7",
        "openssl110f-devel-1.1.0f-5.h7",
        "openssl110f-libs-1.1.0f-5.h7",
        "openssl110f-static-1.1.0f-5.h7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"3", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "openssl110f");
}
