#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-09ae31d880.
#

include("compat.inc");

if (description)
{
  script_id(122070);
  script_version("1.1");
  script_cvs_date("Date: 2019/02/11 11:26:49");

  script_cve_id("CVE-2019-6798");
  script_xref(name:"FEDORA", value:"2019-09ae31d880");

  script_name(english:"Fedora 29 : phpMyAdmin (2019-09ae31d880)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream announcement: # Security fix: phpMyAdmin 4.8.5 is released

The phpMyAdmin team announces the release of **phpMyAdmin version
4.8.5**. Among other bug fixes, this contains **several important
security fixes**. Upgrading is highly recommended for all users.

The security fixes involve :

  - Arbitrary file read vulnerability
    (https://www.phpmyadmin.net/security/PMASA-2019-1)

  - SQL injection in the Designer interface
    (https://www.phpmyadmin.net/security/PMASA-2019-2)

The arbitrary file read vulnerability could also be exploited to
delete arbitrary files on the server. This attack requires that
phpMyAdmin be run with the `$cfg['AllowArbitraryServer']` directive
set to true, which is not the default. An attacker must run a
malicious server process that will masquerade as a MySQL server. This
exploit has been found and fixed recently in several other related
projects and appears to be caused by a bug in PHP
(https://bugs.php.net/bug.php?id=77496).

In addition to the security fixes, this release also includes these
bug fixes and more as part of our regular release cycle :

  - Export to SQL format not available

  - QR code not shown when adding two-factor authentication
    to a user account

  - Issue with adding a new user in MySQL 8.0.11 and newer

  - Frozen interface relating to Text_Plain_Sql plugin

  - Table level Operations tab was missing

And several more. Complete notes are in the ChangeLog file included
with this release.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-09ae31d880"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected phpMyAdmin package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:phpMyAdmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/11");
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
if (rpm_check(release:"FC29", reference:"phpMyAdmin-4.8.5-1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "phpMyAdmin");
}
