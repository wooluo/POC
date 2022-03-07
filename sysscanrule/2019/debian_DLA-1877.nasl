#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1877-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127920);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/20 11:58:10");

  script_cve_id("CVE-2018-11563", "CVE-2019-12746", "CVE-2019-13458");

  script_name(english:"Debian DLA-1877-1 : otrs2 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues have been fixed in otrs2, a well known trouble
ticket system.

CVE-2018-11563

An attacker who is logged into OTRS as a customer can use the ticket
overview screen to disclose internal article information of their
customer tickets.

CVE-2019-12746

A user logged into OTRS as an agent might unknowingly disclose their
session ID by sharing the link of an embedded ticket article with
third parties. This identifier can be then potentially abused in order
to impersonate the agent user.

CVE-2019-13458

An attacker who is logged into OTRS as an agent user with appropriate
permissions can leverage OTRS tags in templates in order to disclose
hashed user passwords.

Due to an incomplete fix for CVE-2019-12248, viewing email attachments
was no longer possible. This update correctly implements the new
Ticket::Fronted::BlockLoadingRemoteContent option.

For Debian 8 'Jessie', these problems have been fixed in version
3.3.18-1+deb8u11.

We recommend that you upgrade your otrs2 packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/08/msg00018.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/otrs2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected otrs, and otrs2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:R/S:U/C:L/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:otrs2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/20");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"8.0", prefix:"otrs", reference:"3.3.18-1+deb8u11")) flag++;
if (deb_check(release:"8.0", prefix:"otrs2", reference:"3.3.18-1+deb8u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
