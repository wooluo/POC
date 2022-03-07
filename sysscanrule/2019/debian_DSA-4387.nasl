#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4387. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(122068);
  script_version("1.3");
  script_cvs_date("Date: 2019/04/02 21:54:16");

  script_cve_id("CVE-2018-20685", "CVE-2019-6109", "CVE-2019-6111");
  script_xref(name:"DSA", value:"4387");

  script_name(english:"Debian DSA-4387-1 : openssh - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Harry Sintonen from F-Secure Corporation discovered multiple
vulnerabilities in OpenSSH, an implementation of the SSH protocol
suite. All the vulnerabilities are in found in the scp client
implementing the SCP protocol.

  - CVE-2018-20685
    Due to improper directory name validation, the scp
    client allows servers to modify permissions of the
    target directory by using empty or dot directory name.

  - CVE-2019-6109
    Due to missing character encoding in the progress
    display, the object name can be used to manipulate the
    client output, for example to employ ANSI codes to hide
    additional files being transferred.

  - CVE-2019-6111
    Due to scp client insufficient input validation in path
    names sent by server, a malicious server can do
    arbitrary file overwrites in target directory. If the
    recursive (-r) option is provided, the server can also
    manipulate subdirectories as well.

  The check added in this version can lead to regression if the client
  and the server have differences in wildcard expansion rules. If the
  server is trusted for that purpose, the check can be disabled with a
  new -T option to the scp client."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=793412"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=919101"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2018-20685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-6109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-6111"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/openssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/openssh"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4387"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssh packages.

For the stable distribution (stretch), these problems have been fixed
in version 1:7.4p1-10+deb9u5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/01/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/02/11");
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
if (deb_check(release:"9.0", prefix:"openssh-client", reference:"1:7.4p1-10+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-client-ssh1", reference:"1:7.4p1-10+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-client-udeb", reference:"1:7.4p1-10+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-server", reference:"1:7.4p1-10+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-server-udeb", reference:"1:7.4p1-10+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"openssh-sftp-server", reference:"1:7.4p1-10+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"ssh", reference:"1:7.4p1-10+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"ssh-askpass-gnome", reference:"1:7.4p1-10+deb9u5")) flag++;
if (deb_check(release:"9.0", prefix:"ssh-krb5", reference:"1:7.4p1-10+deb9u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
