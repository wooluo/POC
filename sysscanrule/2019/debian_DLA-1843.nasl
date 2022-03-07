#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1843-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126481);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:38");

  script_cve_id("CVE-2019-10162", "CVE-2019-10163");

  script_name(english:"Debian DLA-1843-1 : pdns security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in pdns, an authoritative DNS
server which may result in denial of service via malformed zone
records and excessive NOTIFY packets in a master/slave setup.

CVE-2019-10162

An issue has been found in PowerDNS Authoritative Server allowing an
authorized user to cause the server to exit by inserting a crafted
record in a MASTER type zone under their control. The issue is due to
the fact that the Authoritative Server will exit when it runs into a
parsing error while looking up the NS/A/AAAA records it is about to
use for an outgoing notify.

CVE-2019-10163

An issue has been found in PowerDNS Authoritative Server allowing a
remote, authorized master server to cause a high CPU load or even
prevent any further updates to any slave zone by sending a large
number of NOTIFY messages. Note that only servers configured as slaves
are affected by this issue.

For Debian 8 'Jessie', these problems have been fixed in version
3.4.1-4+deb8u10.

We recommend that you upgrade your pdns packages.

For the detailed security status of pdns please refer to its security
tracker page at: https://security-tracker.debian.org/tracker/pdns

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/pdns"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/pdns"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-geo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-lmdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-lua");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-mydns");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-mysql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-pgsql");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-pipe");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-remote");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-backend-sqlite3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pdns-server-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/05");
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
if (deb_check(release:"8.0", prefix:"pdns-backend-geo", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-ldap", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-lmdb", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-lua", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-mydns", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-mysql", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-pgsql", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-pipe", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-remote", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-backend-sqlite3", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-server", reference:"3.4.1-4+deb8u10")) flag++;
if (deb_check(release:"8.0", prefix:"pdns-server-dbg", reference:"3.4.1-4+deb8u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
