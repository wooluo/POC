#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124437);
  script_version("1.2");
  script_cvs_date("Date: 2019/06/27 13:33:25");

  script_cve_id(
    "CVE-2019-3855",
    "CVE-2019-3856",
    "CVE-2019-3857",
    "CVE-2019-3858",
    "CVE-2019-3859",
    "CVE-2019-3860",
    "CVE-2019-3861",
    "CVE-2019-3862",
    "CVE-2019-3863"
  );

  script_name(english:"EulerOS 2.0 SP5 : libssh2 (EulerOS-SA-2019-1310)");
  script_summary(english:"Checks the rpm output for the updated packages.");

  script_set_attribute(attribute:"synopsis", value:
"The remote EulerOS host is missing multiple security updates.");
  script_set_attribute(attribute:"description", value:
"According to the versions of the libssh2 package installed, the
EulerOS installation on the remote host is affected by the following
vulnerabilities :

  - An out of bounds read flaw was discovered in libssh2
    when a specially crafted SFTP packet is received from
    the server. A remote attacker who compromises a SSH
    server may be able to cause a denial of service or read
    data in the client memory.(CVE-2019-3858)

  - An out of bounds read flaw was discovered in libssh2 in
    the _libssh2_packet_require and
    _libssh2_packet_requirev functions. A remote attacker
    who compromises a SSH server may be able to cause a
    denial of service or read data in the client
    memory.(CVE-2019-3859)

  - An out of bounds read flaw was discovered in libssh2 in
    the way SFTP packets with empty payloads are parsed. A
    remote attacker who compromises a SSH server may be
    able to cause a denial of service or read data in the
    client memory.(CVE-2019-3860)

  - An out of bounds read flaw was discovered in libssh2 in
    the way SSH packets with a padding length value greater
    than the packet length are parsed. A remote attacker
    who compromises a SSH server may be able to cause a
    denial of service or read data in the client
    memory.(CVE-2019-3861)

  - An out of bounds read flaw was discovered in libssh2 in
    the way SSH_MSG_CHANNEL_REQUEST packets with an exit
    status message and no payload are parsed. A remote
    attacker who compromises a SSH server may be able to
    cause a denial of service or read data in the client
    memory.(CVE-2019-3862)

  - An integer overflow flaw which could lead to an out of
    bounds write was discovered in libssh2 in the way
    packets are read from the server. A remote attacker who
    compromises a SSH server may be able to execute code on
    the client system when a user connects to the
    server.(CVE-2019-3855)

  - An integer overflow flaw, which could lead to an out of
    bounds write, was discovered in libssh2 in the way
    keyboard prompt requests are parsed. A remote attacker
    who compromises a SSH server may be able to execute
    code on the client system when a user connects to the
    server.(CVE-2019-3856)

  - An integer overflow flaw which could lead to an out of
    bounds write was discovered in libssh2 in the way
    SSH_MSG_CHANNEL_REQUEST packets with an exit signal are
    parsed. A remote attacker who compromises a SSH server
    may be able to execute code on the client system when a
    user connects to the server.(CVE-2019-3857)

  - A flaw was found in libssh2 before 1.8.1. A server
    could send a multiple keyboard interactive response
    messages whose total length are greater than unsigned
    char max characters. This value is used as an index to
    copy memory causing in an out of bounds memory write
    error.(CVE-2019-3863)

Note that WebRAY Network Security has extracted the preceding
description block directly from the EulerOS security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues.");
  # https://developer.huaweicloud.com/ict/en/site-euleros/euleros/security-advisories/EulerOS-SA-2019-1310
  script_set_attribute(attribute:"see_also", value:"");
  script_set_attribute(attribute:"solution", value:
"Update the affected libssh2 packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:huawei:euleros:libssh2");
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

pkgs = ["libssh2-1.4.3-10.1.h3.eulerosv2r7"];

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libssh2");
}
