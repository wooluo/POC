#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-119b14075a.
#

include("compat.inc");

if (description)
{
  script_id(123801);
  script_version("1.4");
  script_cvs_date("Date: 2019/04/12  9:50:26");

  script_cve_id("CVE-2019-0211", "CVE-2019-0215", "CVE-2019-0217", "CVE-2019-0220");
  script_xref(name:"FEDORA", value:"2019-119b14075a");

  script_name(english:"Fedora 29 : httpd (2019-119b14075a)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the latest upstream release of **Apache httpd**,
version **2.4.39**, including multiple bug and security fixes. To see
the full list of changes in this release, see:
https://www.apache.org/dist/httpd/CHANGES_2.4.39

The following security vulnerabilities are addressed :

  - `CVE-2019-0211` - MPMs unix: Fix a local priviledge
    escalation vulnerability by not maintaining each child's
    listener bucket number in the scoreboard, preventing
    unprivileged code like scripts run by/on the server
    (e.g. via mod_php) from modifying it persistently to
    abuse the priviledged main process.

  - `CVE-2019-0215` - mod_ssl: Fix access control bypass for
    per-location/per-dir client certificate verification in
    TLSv1.3.

  - `CVE-2019-0217` - mod_auth_digest: Fix a race condition
    checking user credentials which could allow a user with
    valid credentials to impersonate another, under a
    threaded MPM.

  - `CVE-2019-0220`- Merge consecutive slashes in URL's.
    Opt-out with `MergeSlashes OFF`.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-119b14075a"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected httpd package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:httpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/08");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"httpd-2.4.39-2.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "httpd");
}
