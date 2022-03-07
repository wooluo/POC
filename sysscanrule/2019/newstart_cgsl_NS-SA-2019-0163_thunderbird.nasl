#
# (C) WebRAY Network Security, Inc.
#

# The descriptive text and package checks in this plugin were
# extracted from ZTE advisory NS-SA-2019-0163. The text
# itself is copyright (C) ZTE, Inc.

include("compat.inc");

if (description)
{
  script_id(127447);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:04:15");

  script_cve_id(
    "CVE-2019-11703",
    "CVE-2019-11704",
    "CVE-2019-11705",
    "CVE-2019-11706",
    "CVE-2019-11707",
    "CVE-2019-11708"
  );

  script_name(english:"NewStart CGSL CORE 5.05 / MAIN 5.05 : thunderbird Multiple Vulnerabilities (NS-SA-2019-0163)");

  script_set_attribute(attribute:"synopsis", value:
"The remote machine is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote NewStart CGSL host, running version CORE 5.05 / MAIN 5.05, has thunderbird packages installed that are
affected by multiple vulnerabilities:

  - A flaw in Thunderbird's implementation of iCal causes a
    heap buffer overflow in parser_get_next_char when
    processing certain email messages, resulting in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7.1. (CVE-2019-11703)

  - A flaw in Thunderbird's implementation of iCal causes a
    stack buffer overflow in icalrecur_add_bydayrules when
    processing certain email messages, resulting in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7.1. (CVE-2019-11705)

  - A flaw in Thunderbird's implementation of iCal causes a
    type confusion in icaltimezone_get_vtimezone_properties
    when processing certain email messages, resulting in a
    crash. This vulnerability affects Thunderbird < 60.7.1.
    (CVE-2019-11706)

  - Insufficient vetting of parameters passed with the
    Prompt:Open IPC message between child and parent
    processes can result in the non-sandboxed parent process
    opening web content chosen by a compromised child
    process. When combined with additional vulnerabilities
    this could result in executing arbitrary code on the
    user's computer. This vulnerability affects Firefox ESR
    < 60.7.2, Firefox < 67.0.4, and Thunderbird < 60.7.2.
    (CVE-2019-11708)

  - A type confusion vulnerability can occur when
    manipulating JavaScript objects due to issues in
    Array.pop. This can allow for an exploitable crash. We
    are aware of targeted attacks in the wild abusing this
    flaw. This vulnerability affects Firefox ESR < 60.7.1,
    Firefox < 67.0.3, and Thunderbird < 60.7.2.
    (CVE-2019-11707)

  - A flaw in Thunderbird's implementation of iCal causes a
    heap buffer overflow in icalmemory_strdup_and_dequote
    when processing certain email messages, resulting in a
    potentially exploitable crash. This vulnerability
    affects Thunderbird < 60.7.1. (CVE-2019-11704)

Note that GizaNE has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  script_set_attribute(attribute:"see_also", value:"http://security.gd-linux.com/notice/NS-SA-2019-0163");
  script_set_attribute(attribute:"solution", value:
"Upgrade the vulnerable CGSL thunderbird packages. Note that updated packages may not be available yet. Please contact
ZTE for more information.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-11708");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/23");
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

if (release !~ "CGSL CORE 5.05" &&
    release !~ "CGSL MAIN 5.05")
  audit(AUDIT_OS_NOT, 'NewStart CGSL CORE 5.05 / NewStart CGSL MAIN 5.05');

if (!get_kb_item("Host/ZTE-CGSL/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "NewStart Carrier Grade Server Linux", cpu);

flag = 0;

pkgs = {
  "CGSL CORE 5.05": [
    "thunderbird-60.7.2-2.el7.centos",
    "thunderbird-debuginfo-60.7.2-2.el7.centos"
  ],
  "CGSL MAIN 5.05": [
    "thunderbird-60.7.2-2.el7.centos",
    "thunderbird-debuginfo-60.7.2-2.el7.centos"
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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "thunderbird");
}
