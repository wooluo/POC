#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-1867-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127476);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/12 17:35:29");

  script_cve_id("CVE-2019-11555", "CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");

  script_name(english:"Debian DLA-1867-1 : wpa security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in WPA supplicant / hostapd.
Some of them could only partially be mitigated, please read below for
details.

CVE-2019-9495

Cache-based side-channel attack against the EAP-pwd implementation: an
attacker able to run unprivileged code on the target machine
(including for example JavaScript code in a browser on a smartphone)
during the handshake could deduce enough information to discover the
password in a dictionary attack.

This issue has only very partially been mitigated against by
reducing measurable timing differences during private key
operations. More work is required to fully mitigate this
vulnerability.

CVE-2019-9497

Reflection attack against EAP-pwd server implementation: a lack of
validation of received scalar and elements value in the EAP-pwd-Commit
messages could have resulted in attacks that would have been able to
complete EAP-pwd authentication exchange without the attacker having
to know the password. This did not result in the attacker being able
to derive the session key, complete the following key exchange and
access the network.

CVE-2019-9498

EAP-pwd server missing commit validation for scalar/element: hostapd
didn't validate values received in the EAP-pwd-Commit message, so an
attacker could have used a specially crafted commit message to
manipulate the exchange in order for hostapd to derive a session key
from a limited set of possible values. This could have resulted in an
attacker being able to complete authentication and gain access to the
network.

This issue could only partially be mitigated.

CVE-2019-9499

EAP-pwd peer missing commit validation for scalar/element:
wpa_supplicant didn't validate values received in the EAP-pwd-Commit
message, so an attacker could have used a specially crafted commit
message to manipulate the exchange in order for wpa_supplicant to
derive a session key from a limited set of possible values. This could
have resulted in an attacker being able to complete authentication and
operate as a rogue AP.

This issue could only partially be mitigated.

CVE-2019-11555

The EAP-pwd implementation did't properly validate fragmentation
reassembly state when receiving an unexpected fragment. This could
have lead to a process crash due to a NULL pointer derefrence.

An attacker in radio range of a station or access point with
EAP-pwd support could cause a crash of the relevant process
(wpa_supplicant or hostapd), ensuring a denial of service.

For Debian 8 'Jessie', these problems have been fixed in version
2.3-1+deb8u8.

We recommend that you upgrade your wpa packages.

NOTE: WebRAY Network Security has extracted the preceding description
block directly from the DLA security advisory. WebRAY has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2019/07/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/wpa"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hostapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpagui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpasupplicant-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/12");
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
if (deb_check(release:"8.0", prefix:"hostapd", reference:"2.3-1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"wpagui", reference:"2.3-1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"wpasupplicant", reference:"2.3-1+deb8u8")) flag++;
if (deb_check(release:"8.0", prefix:"wpasupplicant-udeb", reference:"2.3-1+deb8u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
