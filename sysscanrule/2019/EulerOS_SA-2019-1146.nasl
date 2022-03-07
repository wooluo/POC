#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123620);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2018-20783",
    "CVE-2019-9020",
    "CVE-2019-9021",
    "CVE-2019-9023",
    "CVE-2019-9024"
  );

  script_name(english:"EulerOS 2.0 SP5 : php (EulerOS-SA-2019-1146)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the php packages installed, the EulerOS
installation on the remote host is affected by the following
vulnerabilities :

  - In PHP before 5.6.39, 7.x before 7.0.33, 7.1.x before
    7.1.25, and 7.2.x before 7.2.13, a buffer over-read in
    PHAR reading functions may allow an attacker to read
    allocated or unallocated memory past the actual data
    when trying to parse a .phar file. This is related to
    phar_parse_pharfile in ext/phar/phar.c.(CVE-2018-20783)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. Invalid input to the function xmlrpc_decode()
    can lead to an invalid memory access (heap out of
    bounds read or read after free). This is related to
    xml_elem_parse_buf in
    ext/xmlrpc/libxmlrpc/xml_element.c.(CVE-2019-9020)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. A heap-based buffer over-read in PHAR reading
    functions in the PHAR extension may allow an attacker
    to read allocated or unallocated memory past the actual
    data when trying to parse the file name, a different
    vulnerability than CVE-2018-20783. This is related to
    phar_detect_phar_fname_ext in
    ext/phar/phar.c.(CVE-2019-9021)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. A number of heap-based buffer over-read
    instances are present in mbstring regular expression
    functions when supplied with invalid multibyte data.
    These occur in ext/mbstring/oniguruma/regcomp.c,
    ext/mbstring/oniguruma/regexec.c,
    ext/mbstring/oniguruma/regparse.c,
    ext/mbstring/oniguruma/enc/unicode.c, and
    ext/mbstring/oniguruma/src/utf32_be.c when a multibyte
    regular expression pattern contains invalid multibyte
    sequences.(CVE-2019-9023)

  - An issue was discovered in PHP before 5.6.40, 7.x
    before 7.1.26, 7.2.x before 7.2.14, and 7.3.x before
    7.3.1. xmlrpc_decode() can allow a hostile XMLRPC
    server to cause PHP to read memory outside of allocated
    areas in base64_decode_xmlrpc in
    ext/xmlrpc/libxmlrpc/base64.c.(CVE-2019-9024)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1146
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected php packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/02");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-cli");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-gd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-odbc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-pdo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-process");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-recode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-soap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xml");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:php-xmlrpc");
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
if (isnull(sp) || sp !~ "^(5)$") audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5");

uvp = get_kb_item("Host/EulerOS/uvp_version");
if (!empty_or_null(uvp)) audit(AUDIT_OS_NOT, "EulerOS 2.0 SP5", "EulerOS UVP " + uvp);

if (!get_kb_item("Host/EulerOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "EulerOS", cpu);

flag = 0;

pkgs = ["php-5.4.16-45.h7.eulerosv2r7",
        "php-cli-5.4.16-45.h7.eulerosv2r7",
        "php-common-5.4.16-45.h7.eulerosv2r7",
        "php-gd-5.4.16-45.h7.eulerosv2r7",
        "php-ldap-5.4.16-45.h7.eulerosv2r7",
        "php-mysql-5.4.16-45.h7.eulerosv2r7",
        "php-odbc-5.4.16-45.h7.eulerosv2r7",
        "php-pdo-5.4.16-45.h7.eulerosv2r7",
        "php-pgsql-5.4.16-45.h7.eulerosv2r7",
        "php-process-5.4.16-45.h7.eulerosv2r7",
        "php-recode-5.4.16-45.h7.eulerosv2r7",
        "php-soap-5.4.16-45.h7.eulerosv2r7",
        "php-xml-5.4.16-45.h7.eulerosv2r7",
        "php-xmlrpc-5.4.16-45.h7.eulerosv2r7"];

foreach (pkg in pkgs)
  if (rpm_check(release:"EulerOS-2.0", sp:"5", reference:pkg)) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php");
}
