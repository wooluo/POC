#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-4430. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(124038);
  script_version("1.2");
  script_cvs_date("Date: 2019/04/19 10:37:09");

  script_cve_id("CVE-2019-9495", "CVE-2019-9497", "CVE-2019-9498", "CVE-2019-9499");
  script_xref(name:"DSA", value:"4430");

  script_name(english:"Debian DSA-4430-1 : wpa - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mathy Vanhoef (NYUAD) and Eyal Ronen (Tel Aviv University & KU Leuven)
found multiple vulnerabilities in the WPA implementation found in
wpa_supplication (station) and hostapd (access point). These
vulnerability are also collectively known as 'Dragonblood'.

  - CVE-2019-9495
    Cache-based side-channel attack against the EAP-pwd
    implementation: an attacker able to run unprivileged
    code on the target machine (including for example
    JavaScript code in a browser on a smartphone) during the
    handshake could deduce enough information to discover
    the password in a dictionary attack.

  - CVE-2019-9497
    Reflection attack against EAP-pwd server implementation:
    a lack of validation of received scalar and elements
    value in the EAP-pwd-Commit messages could result in
    attacks that would be able to complete EAP-pwd
    authentication exchange without the attacker having to
    know the password. This does not result in the attacker
    being able to derive the session key, complete the
    following key exchange and access the network.

  - CVE-2019-9498
    EAP-pwd server missing commit validation for
    scalar/element: hostapd doesn't validate values received
    in the EAP-pwd-Commit message, so an attacker could use
    a specially crafted commit message to manipulate the
    exchange in order for hostapd to derive a session key
    from a limited set of possible values. This could result
    in an attacker being able to complete authentication and
    gain access to the network.

  - CVE-2019-9499
    EAP-pwd peer missing commit validation for
    scalar/element: wpa_supplicant doesn't validate values
    received in the EAP-pwd-Commit message, so an attacker
    could use a specially crafted commit message to
    manipulate the exchange in order for wpa_supplicant to
    derive a session key from a limited set of possible
    values. This could result in an attacker being able to
    complete authentication and operate as a rogue AP.

Note that the Dragonblood moniker also applies to CVE-2019-9494 and
CVE-2014-9496 which are vulnerabilities in the SAE protocol in WPA3.
SAE is not enabled in Debian stretch builds of wpa, which is thus not
vulnerable by default.

Due to the complexity of the backporting process, the fix for these
vulnerabilities are partial. Users are advised to use strong passwords
to prevent dictionary attacks or use a 2.7-based version from
stretch-backports (version above 2:2.7+git20190128+0c1e29f-4)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/cgi-bin/bugreport.cgi?bug=926801"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-9495"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-9497"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-9498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-9499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2019-9494"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9496"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/source-package/wpa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/stretch/wpa"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/security/2019/dsa-4430"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wpa packages.

For the stable distribution (stretch), these problems have been fixed
in version 2:2.4-1+deb9u3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wpa");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:9.0");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/15");
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
if (deb_check(release:"9.0", prefix:"hostapd", reference:"2:2.4-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"wpagui", reference:"2:2.4-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"wpasupplicant", reference:"2:2.4-1+deb9u3")) flag++;
if (deb_check(release:"9.0", prefix:"wpasupplicant-udeb", reference:"2:2.4-1+deb9u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
