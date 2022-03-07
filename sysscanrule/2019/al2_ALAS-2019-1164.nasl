#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux 2 Security Advisory ALAS-2019-1164.
#

include("compat.inc");

if (description)
{
  script_id(122261);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/04 11:19:02");

  script_cve_id("CVE-2019-6454");
  script_xref(name:"ALAS", value:"2019-1164");

  script_name(english:"Amazon Linux 2 : systemd (ALAS-2019-1164)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux 2 host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that bus_process_object() in bus-objects.c allocates a
buffer on the stack large enough to temporarily store the object path
specified in the incoming message. A malicious unprivileged local user
to send a message which results in the stack pointer moving outside of
the bounds of the currently mapped stack region, jumping over the
stack guard pages. A specifically crafted DBUS nessage could crash PID
1 and result in a subsequent kernel panic.(CVE-2019-6454)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/AL2/ALAS-2019-1164.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update systemd' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:libgudev1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-journal-gateway");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-networkd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-resolved");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:systemd-sysv");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux:2");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/03/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/19");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);

release = get_kb_item("Host/AmazonLinux/release");
if (isnull(release) || !strlen(release)) audit(AUDIT_OS_NOT, "Amazon Linux");
os_ver = pregmatch(pattern: "^AL(A|\d)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Amazon Linux");
os_ver = os_ver[1];
if (os_ver != "2")
{
  if (os_ver == 'A') os_ver = 'AMI';
  audit(AUDIT_OS_NOT, "Amazon Linux 2", "Amazon Linux " + os_ver);
}

if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"AL2", reference:"libgudev1-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"libgudev1-devel-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-debuginfo-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-devel-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-journal-gateway-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-libs-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-networkd-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-python-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-resolved-219-57.amzn2.0.9")) flag++;
if (rpm_check(release:"AL2", reference:"systemd-sysv-219-57.amzn2.0.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libgudev1 / libgudev1-devel / systemd / systemd-debuginfo / etc");
}
