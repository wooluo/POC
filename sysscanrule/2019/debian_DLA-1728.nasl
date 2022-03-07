#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1728-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(123095);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/02 21:54:16");

  script_cve_id("CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6111");

  script_name(english:"Debian DLA-1728-1 : openssh security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple scp client vulnerabilities have been discovered in OpenSSH,
the premier connectivity tool for secure remote shell login and secure
file transfer.

CVE-2018-20685

In scp.c, the scp client allowed remote SSH servers to bypass intended
access restrictions via the filename of . or an empty filename. The
impact was modifying the permissions of the target directory on the
client side.

CVE-2019-6109

Due to missing character encoding in the progress display, a malicious
server (or Man-in-The-Middle attacker) was able to employ crafted
object names to manipulate the client output, e.g., by using ANSI
control codes to hide additional files being transferred. This
affected refresh_progress_meter() in progressmeter.c.

CVE-2019-6111

Due to the scp implementation being derived from 1983 rcp, the server
chooses which files/directories are sent to the client. However, the
scp client only performed cursory validation of the object name
returned (only directory traversal attacks are prevented). A malicious
scp server (or Man-in-The-Middle attacker) was able to overwrite
arbitrary files in the scp client target directory. If recursive
operation (-r) was performed, the server was able to manipulate
subdirectories, as well (for example, to overwrite the
.ssh/authorized_keys file).

For Debian 8 'Jessie', these problems have been fixed in version
1:6.7p1-5+deb8u8.

We recommend that you upgrade your openssh packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/03/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/openssh"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-client-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-server-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-sftp-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh-askpass-gnome");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ssh-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/03/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/03/26");
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
if (deb_check(release:"8.0", prefix:"openssh-client", reference:"1:6.7p1-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-client-udeb", reference:"1:6.7p1-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-server", reference:"1:6.7p1-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-server-udeb", reference:"1:6.7p1-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"openssh-sftp-server", reference:"1:6.7p1-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"ssh", reference:"1:6.7p1-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"ssh-askpass-gnome", reference:"1:6.7p1-5+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"ssh-krb5", reference:"1:6.7p1-5+deb8u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
