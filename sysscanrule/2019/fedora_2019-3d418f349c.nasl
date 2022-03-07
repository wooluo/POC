#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-3d418f349c.
#

include("compat.inc");

if (description)
{
  script_id(127104);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/29  9:47:00");

  script_cve_id("CVE-2019-13226", "CVE-2019-13227", "CVE-2019-13228", "CVE-2019-13229");
  script_xref(name:"FEDORA", value:"2019-3d418f349c");

  script_name(english:"Fedora 30 : deepin-clone / dtkcore / dtkwidget (2019-3d418f349c)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Security fix for CVE-2019-13228, CVE-2019-13229, CVE-2019-13227,
CVE-2019-13226.

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-3d418f349c"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected deepin-clone, dtkcore and / or dtkwidget packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:deepin-clone");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dtkcore");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:dtkwidget");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/29");
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
if (! ereg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"deepin-clone-1.1.4-1.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"dtkcore-2.0.16.1-1.fc30")) flag++;
if (rpm_check(release:"FC30", reference:"dtkwidget-2.0.16.1-1.fc30")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "deepin-clone / dtkcore / dtkwidget");
}
