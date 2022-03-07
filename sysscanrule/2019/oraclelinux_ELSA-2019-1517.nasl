#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2019:1517 and 
# Oracle Linux Security Advisory ELSA-2019-1517 respectively.
#

include("compat.inc");

if (description)
{
  script_id(127591);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-3827");
  script_xref(name:"RHSA", value:"2019:1517");

  script_name(english:"Oracle Linux 8 : gvfs (ELSA-2019-1517)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2019:1517 :

An update for gvfs is now available for Red Hat Enterprise Linux 8.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

GVFS is the GNOME Desktop Virtual File System layer that allows users
to easily access local and remote data using File Transfer Protocol
(FTP), Secure Shell File Transfer Protocol (SFTP), Web Distributed
Authoring and Versioning (WebDAV), Common Internet File System (CIFS),
Server Message Block (SMB), and other protocols. GVFS integrates with
the GNOME I/O (GIO) abstraction layer.

Security Fix(es) :

* gvfs: Incorrect authorization in admin backend allows privileged
users to read and modify arbitrary files without prompting for
password (CVE-2019-3827)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2019-August/008982.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected gvfs packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-afc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-afp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-archive");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-fuse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-goa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-gphoto2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-mtp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:gvfs-smb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:8");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^8([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 8", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-afc-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-afp-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-archive-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-client-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-devel-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-fuse-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-goa-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-gphoto2-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-mtp-1.36.2-2.el8_0.1")) flag++;
if (rpm_check(release:"EL8", cpu:"x86_64", reference:"gvfs-smb-1.36.2-2.el8_0.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "gvfs / gvfs-afc / gvfs-afp / gvfs-archive / gvfs-client / etc");
}
