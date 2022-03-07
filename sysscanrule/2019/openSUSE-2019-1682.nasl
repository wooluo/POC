#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1682.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126437);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2018-16860", "CVE-2019-12098");

  script_name(english:"openSUSE Security Update : libheimdal (openSUSE-2019-1682)");
  script_summary(english:"Check for the openSUSE-2019-1682 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for libheimdal fixes the following issues :

libheimdal was updated to version 7.7.0 :

  + Bug fixes :

  - PKCS#11 hcrypto back-end :

  + initialize the p11_module_load function list

  + verify that not only is a mechanism present but that its
    mechanism info states that it offers the required
    encryption, decryption or digest services

  - krb5 :

  + Starting with 7.6, Heimdal permitted requesting
    authenticated anonymous tickets. However, it did not
    verify that a KDC in fact returned an anonymous ticket
    when one was requested.

  + Cease setting the KDCOption reaquest_anonymous flag when
    issuing S4UProxy (constrained delegation) TGS requests.

  + when the Win2K PKINIT compatibility option is set, do
    not require krbtgt otherName to match when validating
    KDC certificate.

  + set PKINIT_BTMM flag per Apple implementation

  + use memset_s() instead of memset()

  - kdc :

  + When generating KRB5SignedPath in the AS, use the reply
    client name rather than the one from the request, so
    validation will work correctly in the TGS.

  + allow checksum of PA-FOR-USER to be HMAC_MD5. Even if
    TGT used an enctype with a different checksum. Per
    [MS-SFU] 2.2.1 PA-FOR-USER the checksum is always
    HMAC_MD5, and that's what Windows and MIT clients send.
    In Heimdal both the client and kdc use instead the
    checksum of the TGT, and therefore work with each other
    but Windows and MIT clients fail against Heimdal KDC.
    Both Windows and MIT KDC would allow any keyed checksum
    to be used so Heimdal client work fine against it.
    Change Heimdal KDC to allow HMAC_MD5 even for non RC4
    based TGT in order to support per-spec clients.

  + use memset_s() instead of memset()

  + Detect Heimdal 1.0 through 7.6 clients that issue
    S4UProxy (constrained delegation) TGS Requests with the
    request anonymous flag set. These requests will be
    treated as S4UProxy requests and not anonymous requests.

  - HDB :

  + Set SQLite3 backend default page size to 8KB.

  + Add hdb_set_sync() method

  - kadmind :

  + disable HDB sync during database load avoiding
    unnecessary disk i/o.

  - ipropd :

  + disable HDB sync during receive_everything. Doing an
    fsync per-record when receiving the complete HDB is a
    performance disaster. Among other things, if the HDB is
    very large, then one slave receving a full HDB can cause
    other slaves to timeout and, if HDB write activity is
    high enough to cause iprop log truncation, then also
    need full syncs, which leads to a cycle of full syncs
    for all slaves until HDB write activity drops. Allowing
    the iprop log to be larger helps, but improving
    receive_everything() performance helps even more.

  - kinit :

  + Anonymous PKINIT tickets discard the realm information
    used to locate the issuing AS. Store the issuing realm
    in the credentials cache in order to locate a KDC which
    can renew them.

  + Do not leak the result of krb5_cc_get_config() when
    determining anonymous PKINIT start realm.

  - klist :

  + Show transited-policy-checked, ok-as-delegate and
    anonymous flags when listing credentials.

  - tests :

  + Regenerate certs so that they expire before the 2038
    armageddon so the test suite will pass on 32-bit
    operating systems until the underlying issues can be
    resolved.

  - documentation :

  + rename verify-password to verify-password-quality

  + hprop default mode is encrypt

  + kadmind 'all' permission does not include 'get-keys'

  + verify-password-quality might not be stateless

Version 7.6.0 :

  + Security (#555) :

  - CVE-2018-16860 Heimdal KDC: Reject PA-S4U2Self with
    unkeyed checksum

    When the Heimdal KDC checks the checksum that is placed
    on the S4U2Self packet by the server to protect the
    requested principal against modification, it does not
    confirm that the checksum algorithm that protects the
    user name (principal) in the request is keyed. This
    allows a man-in-the-middle attacker who can intercept
    the request to the KDC to modify the packet by replacing
    the user name (principal) in the request with any
    desired user name (principal) that exists in the KDC and
    replace the checksum protecting that name with a CRC32
    checksum (which requires no prior knowledge to compute).
    This would allow a S4U2Self ticket requested on behalf
    of user name (principal) user@EXAMPLE.COM to any service
    to be changed to a S4U2Self ticket with a user name
    (principal) of Administrator@EXAMPLE.COM. This ticket
    would then contain the PAC of the modified user name
    (principal).

  - CVE-2019-12098, client-only :

    RFC8062 Section 7 requires verification of the
    PA-PKINIT-KX key exchange when anonymous PKINIT is used.
    Failure to do so can permit an active attacker to become
    a man-in-the-middle.

  + Bug fixes :

  - Happy eyeballs: Don't wait for responses from
    known-unreachable KDCs.

  - kdc :

  + check return copy_Realm, copy_PrincipalName,
    copy_EncryptionKey

  - kinit :

  + cleanup temporary ccaches

  + see man page for 'kinit --anonymous' command line syntax
    change

  - kdc :

  + Make anonymous AS-requests more RFC8062-compliant.
    Updated expired test certificates

  + Features :

  - kuser: support authenticated anonymous AS-REQs in kinit

  - kdc: support for anonymous TGS-REQs

  - kgetcred support for anonymous service tickets

  - Support builds with OpenSSL 1.1.1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1047218"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1084909"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libheimdal packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:L/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimdal");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimdal-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimdal-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libheimdal-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:42.3");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0|SUSE15\.1|SUSE42\.3)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1 / 42.3", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libheimdal-7.7.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libheimdal-debuginfo-7.7.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libheimdal-debugsource-7.7.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", cpu:"x86_64", reference:"libheimdal-devel-7.7.0-lp150.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libheimdal-7.7.0-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libheimdal-debuginfo-7.7.0-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libheimdal-debugsource-7.7.0-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", cpu:"x86_64", reference:"libheimdal-devel-7.7.0-lp151.3.3.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libheimdal-7.7.0-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libheimdal-debuginfo-7.7.0-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libheimdal-debugsource-7.7.0-12.1") ) flag++;
if ( rpm_check(release:"SUSE42.3", reference:"libheimdal-devel-7.7.0-12.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libheimdal / libheimdal-debuginfo / libheimdal-debugsource / etc");
}
