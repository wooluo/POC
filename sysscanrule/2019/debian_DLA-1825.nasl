#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1825-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126010);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/19 13:26:27");

  script_cve_id("CVE-2019-10732");

  script_name(english:"Debian DLA-1825-1 : kdepim security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A reply-based decryption oracle was found in kdepim, which provides
the KMail e-mail client.

An attacker in possession of S/MIME or PGP encrypted emails can wrap
them as sub-parts within a crafted multipart email. The encrypted
part(s) can further be hidden using HTML/CSS or ASCII newline
characters. This modified multipart email can be re-sent by the
attacker to the intended receiver. If the receiver replies to this
(benign looking) email, they unknowingly leak the plaintext of the
encrypted message part(s) back to the attacker.

For Debian 8 'Jessie', this problem has been fixed in version
4:4.14.1-1+deb8u2.

We recommend that you upgrade your kdepim packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/06/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/kdepim"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:L/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:akonadiconsole");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:akregator");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:blogilo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kaddressbook");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kaddressbook-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kalarm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdepim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdepim-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdepim-kresources");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdepim-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kdepim-mobileui-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kjots");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kleopatra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kmail");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kmail-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:knode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:knotes");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:konsolekalendar");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kontact");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:korganizer");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:korganizer-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ktimetracker");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcalendarsupport4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcomposereditorng4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libeventviews4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfollowupreminder4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libincidenceeditorsng4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdepim4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdepimdbusinterfaces4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdepimmobileui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkdgantt2-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkleo4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkmanagesieve4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkpgp4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libksieve4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libksieveui4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmailcommon4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmailimporter4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmessagecomposer4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmessagecore4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmessagelist4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmessageviewer4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnoteshared4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpimcommon4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsendlater4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtemplateparser4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:notes-mobile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:storageservicemanager");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tasks-mobile");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/06/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/19");
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
if (deb_check(release:"8.0", prefix:"akonadiconsole", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"akregator", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"blogilo", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kaddressbook", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kaddressbook-mobile", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kalarm", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kdepim", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kdepim-dbg", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kdepim-kresources", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kdepim-mobile", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kdepim-mobileui-data", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kjots", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kleopatra", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kmail", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kmail-mobile", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"knode", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"knotes", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"konsolekalendar", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"kontact", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"korganizer", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"korganizer-mobile", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"ktimetracker", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libcalendarsupport4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libcomposereditorng4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libeventviews4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libfollowupreminder4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libincidenceeditorsng4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkdepim4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkdepimdbusinterfaces4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkdepimmobileui4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkdgantt2-0", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkleo4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkmanagesieve4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libkpgp4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libksieve4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libksieveui4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmailcommon4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmailimporter4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmessagecomposer4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmessagecore4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmessagelist4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmessageviewer4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libnoteshared4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpimcommon4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libsendlater4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libtemplateparser4", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"notes-mobile", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"storageservicemanager", reference:"4:4.14.1-1+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"tasks-mobile", reference:"4:4.14.1-1+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
