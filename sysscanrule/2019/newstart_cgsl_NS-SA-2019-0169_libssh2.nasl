#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0169. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127458);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2019-3855",
    "CVE-2019-3856",
    "CVE-2019-3857",
    "CVE-2019-3863"
  );
  script_bugtraq_id(107485, 107485, 107485, 107485);

  script_name(english:"NewStart CGSL MAIN 4.05 : libssh2 Multiple Vulnerabilities (NS-SA-2019-0169)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version MAIN 4.05, has libssh2 packages installed that are affected by multiple
vulnerabilities:

  - An integer overflow flaw which could lead to an out of
    bounds write was discovered in libssh2 in the way
    packets are read from the server. A remote attacker who
    compromises a SSH server may be able to execute code on
    the client system when a user connects to the server.
    (CVE-2019-3855)

  - An integer overflow flaw, which could lead to an out of
    bounds write, was discovered in libssh2 in the way
    keyboard prompt requests are parsed. A remote attacker
    who compromises a SSH server may be able to execute code
    on the client system when a user connects to the server.
    (CVE-2019-3856)

  - An integer overflow flaw which could lead to an out of
    bounds write was discovered in libssh2 in the way
    SSH_MSG_CHANNEL_REQUEST packets with an exit signal are
    parsed. A remote attacker who compromises a SSH server
    may be able to execute code on the client system when a
    user connects to the server. (CVE-2019-3857)

  - A flaw was found in libssh2 before 1.8.1. A server could
    send a multiple keyboard interactive response messages
    whose total length are greater than unsigned char max
    characters. This value is used as an index to copy
    memory causing in an out of bounds memory write error.
    (CVE-2019-3863)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0169");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL libssh2 packages. Note that updated packages may not be available yet. Please contact ZTE
for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-3855");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"NewStart CGSL Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/ZTE-CGSL/release", "Host/ZTE-CGSL/rpm-list", "Host/cpu");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/ZTE-CGSL/release");
if (isnull(release) || release !~ "^CGSL (MAIN|CORE)") audit(AUDIT_OS_NOT, "NewStart Carrier Grade Server Linux");

if (release !~ "CGSL MAIN 4.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL MAIN 4.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL MAIN 4.05": [
    "libssh2-1.4.2-3.el6_10.1",
    "libssh2-debuginfo-1.4.2-3.el6_10.1",
    "libssh2-devel-1.4.2-3.el6_10.1",
    "libssh2-docs-1.4.2-3.el6_10.1"
  ]
};
pkg_list = pkgs[release];

foreach (pkg in pkg_list)
  if (rpm_check(release:"ZTE " + release, reference:pkg)) flag++;

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
