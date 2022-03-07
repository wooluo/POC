#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from SUSE update advisory SUSE-SU-2019:1040-1.
# The text itself is copyright (C) SUSE.
#

include("compat.inc");

if (description)
{
  script_id(124320);
  script_version("1.1");
  script_cvs_date("Date: 2019/04/26  9:36:41");

  script_cve_id("CVE-2019-3880");

  script_name(english:"SUSE SLED15 / SLES15 Security Update : samba (SUSE-SU-2019:1040-1)");
  script_summary(english:"Checks rpm output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote SUSE host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for samba fixes the following issues :

Security issue fixed :

CVE-2019-3880: Fixed a path/symlink traversal vulnerability, which
allowed an unprivileged user to save registry files outside a share
(bsc#1131060).

ldb was updated to version 1.2.4 (bsc#1125410 bsc#1131686): Out of
bound read in ldb_wildcard_compare

Hold at most 10 outstanding paged result cookies

Put 'results_store' into a doubly linked list

Refuse to build Samba against a newer minor version of ldb

Non-security issues fixed: Fixed update-apparmor-samba-profile script
after apparmor switched to using named profiles (bsc#1126377).

Abide to the load_printers parameter in smb.conf (bsc#1124223).

Provide the 32bit samba winbind PAM module and its dependend 32bit
libraries.

Note that WebRAY Network Security has extracted the preceding
description block directly from the SUSE security advisory. WebRAY
has attempted to automatically clean and format it as much as possible
without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1114407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1124223"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1125410"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1126377"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131060"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.suse.com/show_bug.cgi?id=1131686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.suse.com/security/cve/CVE-2019-3880/"
  );
  # https://www.suse.com/support/update/announcement/2019/suse-su-20191040-1/
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"To install this SUSE Security Update use the SUSE recommended
installation methods like YaST online_update or 'zypper patch'.

Alternatively you can run the command listed for your product :

SUSE Linux Enterprise Module for Packagehub Subpackages 15:zypper in
-t patch SUSE-SLE-Module-Packagehub-Subpackages-15-2019-1040=1

SUSE Linux Enterprise Module for Open Buildservice Development Tools
15:zypper in -t patch
SUSE-SLE-Module-Development-Tools-OBS-15-2019-1040=1

SUSE Linux Enterprise Module for Development Tools 15:zypper in -t
patch SUSE-SLE-Module-Development-Tools-15-2019-1040=1

SUSE Linux Enterprise Module for Desktop Applications 15:zypper in -t
patch SUSE-SLE-Module-Desktop-Applications-15-2019-1040=1

SUSE Linux Enterprise Module for Basesystem 15:zypper in -t patch
SUSE-SLE-Module-Basesystem-15-2019-1040=1

SUSE Linux Enterprise High Availability 15:zypper in -t patch
SUSE-SLE-Product-HA-15-2019-1040=1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:N/I:L/A:L");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-autoipd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-autoipd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-compat-howl-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-compat-mDNSResponder-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-glib2-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:avahi-utils-gtk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-pcp-pmda");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-pcp-pmda-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-tests");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ctdb-tests-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-config");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-ddk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-ddk-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:cups-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gamin-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gamin-devel-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls-guile");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:gnutls-guile-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:ldb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-client3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-common3-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-core7");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-core7-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-glib1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-gobject-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-gobject0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-gobject0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-ui-gtk3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-ui-gtk3-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-ui0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libavahi-ui0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcups2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcups2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcups2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupscgi1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupscgi1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsimage2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsimage2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsmime1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsmime1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsppdc1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libcupsppdc1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-binding0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc-samr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdcerpc0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns_sd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libdns_sd-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfam0-gamin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfam0-gamin-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libfam0-gamin-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgamin-1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgamin-1-0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls30");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls30-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutls30-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutlsxx-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutlsxx28");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libgnutlsxx28-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhogweed4-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhowl0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libhowl0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libldb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-krb5pac0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-nbt0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr-standard0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libndr0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnetapi0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libnettle6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libp11-kit0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libp11-kit0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libp11-kit0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-credentials0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-errors0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-hostconfig0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-passdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-policy0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamba-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsamdb0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbconf0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libsmbldap2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc2-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtalloc2-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-6-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-6-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtasn1-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtdb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtdb1-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtdb1-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent-util0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libtevent0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:libwbclient0-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nettle");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:nettle-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-nss-trust");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:p11-kit-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-avahi");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-avahi-gtk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-ldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-ldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-talloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-talloc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-talloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python-tevent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ldb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-ldb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-talloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-talloc-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-talloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-tdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-tdb-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-tevent");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:python3-tevent-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-client-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-core-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-libs-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-python");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-test");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-test-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-32bit-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:samba-winbind-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:talloc-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:talloc-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tdb-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tdb-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tevent-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:tevent-man");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:suse_linux:typelib-1_0-Avahi");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:suse_linux:15");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/04/26");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release !~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "SUSE");
os_ver = eregmatch(pattern: "^(SLE(S|D)\d+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "SUSE");
os_ver = os_ver[1];
if (! ereg(pattern:"^(SLED15|SLES15)$", string:os_ver)) audit(AUDIT_OS_NOT, "SUSE SLED15 / SLES15", "SUSE " + os_ver);

if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^i[3-6]86$" && "x86_64" >!< cpu && "s390x" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "SUSE " + os_ver, cpu);

sp = get_kb_item("Host/SuSE/patchlevel");
if (isnull(sp)) sp = "0";
if (os_ver == "SLES15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLES15 SP0", os_ver + " SP" + sp);
if (os_ver == "SLED15" && (! ereg(pattern:"^(0)$", string:sp))) audit(AUDIT_OS_NOT, "SLED15 SP0", os_ver + " SP" + sp);


flag = 0;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnettle-devel-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"avahi-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"cups-debugsource-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"gnutls-debugsource-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libavahi-client3-32bit-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libavahi-client3-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libavahi-common3-32bit-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libavahi-common3-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnettle-debugsource-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libp11-kit0-32bit-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libp11-kit0-32bit-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtasn1-6-32bit-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtasn1-6-32bit-debuginfo-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtasn1-debugsource-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"p11-kit-32bit-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"p11-kit-debugsource-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libavahi-client3-32bit-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libavahi-client3-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libavahi-common3-32bit-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libavahi-common3-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libdcerpc0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libdcerpc0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libfam0-gamin-32bit-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libfam0-gamin-32bit-debuginfo-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libldb1-32bit-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libldb1-32bit-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libndr-standard0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libndr-standard0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libndr0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libndr0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnetapi0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnetapi0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libp11-kit0-32bit-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libp11-kit0-32bit-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-errors0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-passdb0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-util0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamba-util0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamdb0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsamdb0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsmbclient0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsmbclient0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsmbconf0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsmbconf0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsmbldap2-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libsmbldap2-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtalloc2-32bit-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtalloc2-32bit-debuginfo-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtasn1-6-32bit-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtasn1-6-32bit-debuginfo-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtdb1-32bit-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtdb1-32bit-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtevent-util0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtevent-util0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtevent0-32bit-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libtevent0-32bit-debuginfo-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libwbclient0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"libwbclient0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"samba-client-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"samba-client-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"samba-libs-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"samba-libs-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"samba-winbind-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", cpu:"x86_64", reference:"samba-winbind-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-debugsource-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-avahi-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debugsource-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-python-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-debugsource-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-glib2-debugsource-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ctdb-pcp-pmda-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ctdb-pcp-pmda-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ctdb-tests-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ctdb-tests-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gnutls-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gnutls-debugsource-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gnutls-guile-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gnutls-guile-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ldb-debugsource-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ldb-tools-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ldb-tools-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnettle-debugsource-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nettle-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"nettle-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-avahi-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-avahi-gtk-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-tdb-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-tdb-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-tevent-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-tevent-debuginfo-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-tdb-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-tdb-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-tevent-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-tevent-debuginfo-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debugsource-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-python-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-test-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-test-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tdb-debugsource-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tevent-debugsource-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-ddk-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-ddk-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-debugsource-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-autoipd-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-autoipd-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-debugsource-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-glib2-debugsource-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-utils-gtk-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-utils-gtk-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-gobject-devel-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-compat-howl-devel-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-compat-mDNSResponder-devel-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-debugsource-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-glib2-debugsource-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-utils-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"avahi-utils-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-client-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-client-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-config-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-debugsource-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"cups-devel-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gamin-devel-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gamin-devel-debugsource-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gnutls-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gnutls-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"gnutls-debugsource-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"ldb-debugsource-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-client3-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-client3-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-common3-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-common3-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-core7-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-core7-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-devel-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-glib-devel-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-glib1-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-glib1-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-gobject0-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-gobject0-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-ui-gtk3-0-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-ui-gtk3-0-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-ui0-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libavahi-ui0-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcups2-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcups2-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupscgi1-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupscgi1-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsimage2-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsimage2-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsmime1-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsmime1-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsppdc1-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libcupsppdc1-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-binding0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-binding0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-samr-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-samr0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc-samr0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdcerpc0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdns_sd-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libdns_sd-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfam0-gamin-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libfam0-gamin-debuginfo-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgamin-1-0-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgamin-1-0-debuginfo-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgnutls-devel-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgnutls30-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgnutls30-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgnutlsxx-devel-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgnutlsxx28-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libgnutlsxx28-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libhogweed4-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libhogweed4-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libhowl0-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libhowl0-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libldb-devel-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libldb1-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libldb1-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-krb5pac-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-krb5pac0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-krb5pac0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-nbt-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-nbt0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-nbt0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-standard-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-standard0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr-standard0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libndr0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnetapi-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnetapi0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnetapi0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnettle-debugsource-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnettle-devel-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnettle6-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libnettle6-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libp11-kit0-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libp11-kit0-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-credentials-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-credentials0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-credentials0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-errors-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-errors0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-errors0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-hostconfig-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-hostconfig0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-hostconfig0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-passdb-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-passdb0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-passdb0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-policy-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-policy0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-util-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-util0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamba-util0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamdb-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamdb0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsamdb0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbclient-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbclient0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbclient0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbconf-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbconf0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbconf0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbldap-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbldap2-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libsmbldap2-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtalloc-devel-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtalloc2-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtalloc2-debuginfo-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtasn1-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtasn1-6-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtasn1-6-debuginfo-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtasn1-debuginfo-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtasn1-debugsource-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtasn1-devel-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtdb-devel-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtdb1-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtdb1-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-devel-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-util-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-util0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent-util0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent0-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libtevent0-debuginfo-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwbclient-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwbclient0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"libwbclient0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"p11-kit-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"p11-kit-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"p11-kit-debugsource-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"p11-kit-devel-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"p11-kit-nss-trust-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"p11-kit-tools-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"p11-kit-tools-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-ldb-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-ldb-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-ldb-devel-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-talloc-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-talloc-debuginfo-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python-talloc-devel-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-ldb-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-ldb-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-ldb-devel-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-talloc-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-talloc-debuginfo-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"python3-talloc-devel-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-client-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-client-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-core-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-debugsource-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-libs-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-libs-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-winbind-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"samba-winbind-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"talloc-debugsource-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"talloc-man-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tdb-debugsource-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tdb-tools-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tdb-tools-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tevent-debugsource-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"tevent-man-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLES15", sp:"0", reference:"typelib-1_0-Avahi-0_6-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnettle-devel-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"avahi-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"cups-debugsource-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"gnutls-debugsource-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libavahi-client3-32bit-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libavahi-client3-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libavahi-common3-32bit-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libavahi-common3-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnettle-debugsource-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libp11-kit0-32bit-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libp11-kit0-32bit-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtasn1-6-32bit-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtasn1-6-32bit-debuginfo-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtasn1-debugsource-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"p11-kit-32bit-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"p11-kit-debugsource-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libavahi-client3-32bit-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libavahi-client3-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libavahi-common3-32bit-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libavahi-common3-32bit-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libcups2-32bit-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libdcerpc-binding0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libdcerpc0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libdcerpc0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libfam0-gamin-32bit-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libfam0-gamin-32bit-debuginfo-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libgnutls30-32bit-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libgnutls30-32bit-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libhogweed4-32bit-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libldb1-32bit-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libldb1-32bit-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libndr-krb5pac0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libndr-nbt0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libndr-standard0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libndr-standard0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libndr0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libndr0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnetapi0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnetapi0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libnettle6-32bit-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libp11-kit0-32bit-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libp11-kit0-32bit-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-credentials0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-errors0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-errors0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-hostconfig0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-passdb0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-passdb0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-util0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamba-util0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamdb0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsamdb0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsmbclient0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsmbclient0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsmbconf0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsmbconf0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsmbldap2-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libsmbldap2-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtalloc2-32bit-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtalloc2-32bit-debuginfo-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtasn1-6-32bit-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtasn1-6-32bit-debuginfo-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtdb1-32bit-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtdb1-32bit-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtevent-util0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtevent-util0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtevent0-32bit-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libtevent0-32bit-debuginfo-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libwbclient0-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"libwbclient0-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"samba-client-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"samba-client-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"samba-libs-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"samba-libs-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"samba-winbind-32bit-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", cpu:"x86_64", reference:"samba-winbind-32bit-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-debugsource-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-avahi-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debugsource-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-python-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-debugsource-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-glib2-debugsource-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ctdb-pcp-pmda-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ctdb-pcp-pmda-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ctdb-tests-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ctdb-tests-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gnutls-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gnutls-debugsource-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gnutls-guile-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gnutls-guile-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ldb-debugsource-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ldb-tools-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ldb-tools-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnettle-debugsource-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nettle-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"nettle-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-avahi-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-avahi-gtk-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-tdb-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-tdb-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-tevent-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-tevent-debuginfo-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-tdb-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-tdb-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-tevent-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-tevent-debuginfo-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debugsource-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-python-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-test-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-test-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tdb-debugsource-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tevent-debugsource-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-ddk-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-ddk-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-debugsource-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-autoipd-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-autoipd-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-debugsource-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-glib2-debugsource-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-utils-gtk-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-utils-gtk-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-gobject-devel-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-compat-howl-devel-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-compat-mDNSResponder-devel-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-debugsource-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-glib2-debugsource-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-utils-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"avahi-utils-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-client-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-client-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-config-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-debugsource-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"cups-devel-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gamin-devel-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gamin-devel-debugsource-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gnutls-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gnutls-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"gnutls-debugsource-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"ldb-debugsource-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-client3-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-client3-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-common3-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-common3-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-core7-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-core7-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-devel-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-glib-devel-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-glib1-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-glib1-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-gobject0-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-gobject0-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-ui-gtk3-0-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-ui-gtk3-0-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-ui0-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libavahi-ui0-debuginfo-0.6.32-5.5.8")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcups2-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcups2-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupscgi1-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupscgi1-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsimage2-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsimage2-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsmime1-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsmime1-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsppdc1-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libcupsppdc1-debuginfo-2.2.7-3.11.7")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-binding0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-binding0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-samr-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-samr0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc-samr0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdcerpc0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdns_sd-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libdns_sd-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfam0-gamin-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libfam0-gamin-debuginfo-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgamin-1-0-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgamin-1-0-debuginfo-0.1.10-3.2.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgnutls-devel-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgnutls30-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgnutls30-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgnutlsxx-devel-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgnutlsxx28-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libgnutlsxx28-debuginfo-3.6.2-6.5.4")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libhogweed4-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libhogweed4-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libhowl0-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libhowl0-debuginfo-0.6.32-5.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libldb-devel-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libldb1-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libldb1-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-krb5pac-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-krb5pac0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-krb5pac0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-nbt-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-nbt0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-nbt0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-standard-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-standard0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr-standard0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libndr0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnetapi-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnetapi0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnetapi0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnettle-debugsource-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnettle-devel-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnettle6-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libnettle6-debuginfo-3.4.1-4.9.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libp11-kit0-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libp11-kit0-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-credentials-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-credentials0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-credentials0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-errors-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-errors0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-errors0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-hostconfig-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-hostconfig0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-hostconfig0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-passdb-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-passdb0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-passdb0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-policy-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-policy0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-util-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-util0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamba-util0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamdb-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamdb0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsamdb0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbclient-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbclient0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbclient0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbconf-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbconf0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbconf0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbldap-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbldap2-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libsmbldap2-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtalloc-devel-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtalloc2-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtalloc2-debuginfo-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtasn1-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtasn1-6-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtasn1-6-debuginfo-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtasn1-debuginfo-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtasn1-debugsource-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtasn1-devel-4.13-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtdb-devel-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtdb1-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtdb1-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-devel-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-util-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-util0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent-util0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent0-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libtevent0-debuginfo-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwbclient-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwbclient0-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"libwbclient0-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"p11-kit-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"p11-kit-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"p11-kit-debugsource-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"p11-kit-devel-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"p11-kit-nss-trust-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"p11-kit-tools-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"p11-kit-tools-debuginfo-0.23.2-4.2.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-ldb-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-ldb-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-ldb-devel-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-talloc-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-talloc-debuginfo-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python-talloc-devel-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-ldb-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-ldb-debuginfo-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-ldb-devel-1.2.4-3.12.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-talloc-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-talloc-debuginfo-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"python3-talloc-devel-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-client-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-client-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-core-devel-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-debugsource-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-libs-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-libs-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-winbind-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"samba-winbind-debuginfo-4.7.11+git.153.b36ceaf2235-4.27.1")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"talloc-debugsource-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"talloc-man-2.1.11-3.5.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tdb-debugsource-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tdb-tools-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tdb-tools-debuginfo-1.3.15-3.6.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tevent-debugsource-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"tevent-man-0.9.36-4.10.3")) flag++;
if (rpm_check(release:"SLED15", sp:"0", reference:"typelib-1_0-Avahi-0_6-0.6.32-5.5.8")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "samba");
}
