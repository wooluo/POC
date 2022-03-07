#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2019:1726 and 
# CentOS Errata and Security Advisory 2019:1726 respectively.
#

include("compat.inc");

if (description)
{
  script_id(126649);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/15 14:20:21");

  script_cve_id("CVE-2019-12749");
  script_xref(name:"RHSA", value:"2019:1726");

  script_name(english:"CentOS 6 : dbus (CESA-2019:1726)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for dbus is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

D-Bus is a system for sending messages between applications. It is
used both for the system-wide message bus service, and as a
per-user-login-session messaging facility.

Security Fix(es) :

* dbus: DBusServer DBUS_COOKIE_SHA1 authentication bypass
(CVE-2019-12749)

For more details about the security issue(s), including the impact, a
CVSS score, acknowledgments, and other related information, refer to
the CVE page(s) listed in the References section."
  );
  # https://lists.centos.org/pipermail/centos-announce/2019-July/023361.html
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(attribute:"solution", value:"Update the affected dbus packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:dbus-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/15");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"dbus-1.2.24-11.el6_10")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dbus-devel-1.2.24-11.el6_10")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dbus-doc-1.2.24-11.el6_10")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dbus-libs-1.2.24-11.el6_10")) flag++;
if (rpm_check(release:"CentOS-6", reference:"dbus-x11-1.2.24-11.el6_10")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
