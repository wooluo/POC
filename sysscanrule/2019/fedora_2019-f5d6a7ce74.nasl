#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-f5d6a7ce74.
#

include("compat.inc");

if (description)
{
  script_id(124556);
  script_version("1.3");
  script_cvs_date("Date: 2019/07/15 14:20:31");

  script_cve_id("CVE-2019-10912");
  script_xref(name:"FEDORA", value:"2019-f5d6a7ce74");

  script_name(english:"Fedora 30 : php-symfony4 (2019-f5d6a7ce74)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"**Version 4.2.7** (2019-04-17)

  - bug #31107 [Routing] fix trailing slash redirection with
    non-greedy trailing vars (nicolas-grekas)

  - bug #31108 [FrameworkBundle] decorate the
    ValidatorBuilder's translator with LegacyTranslatorProxy
    (nicolas-grekas)

  - bug #31121 [HttpKernel] Fix get session when the request
    stack is empty (yceruto)

  - bug #31084 [HttpFoundation] Make
    MimeTypeExtensionGuesser case insensitive
    (vermeirentony)

  - bug #31142 Revert 'bug #30423 [Security] Rework
    firewall's access denied rule (dimabory)' (chalasr)

  - security #cve-2019-10910 [DI] Check service IDs are
    valid (nicolas-grekas)

  - security #cve-2019-10909 [FrameworkBundle][Form] Fix XSS
    issues in the form theme of the PHP templating engine
    (stof)

  - security #cve-2019-10912 [Cache][PHPUnit Bridge] Prevent
    destructors with side-effects from being unserialized
    (nicolas-grekas)

  - security #cve-2019-10911 [Security] Add a separator in
    the remember me cookie hash (pborreli)

  - security #cve-2019-10913 [HttpFoundation] reject invalid
    method override (nicolas-grekas)

----

**Version 4.2.6** (2019-04-16)

  - bug #31088 [DI] fix removing non-shared definition while
    inlining them (nicolas-grekas)

  - bug #29944 [DI] Overriding services autowired by name
    under _defaults bind not working (przemyslaw-bogusz,
    renanbr)

  - bug #30993 [FrameworkBundle] Fix for Controller
    DEPRECATED when using composer --optimized (aweelex)

  - bug #31076 [HttpKernel] Fixed LoggerDataCollector
    crashing on empty file (althaus)

  - bug #31071 property normalizer should also pass format
    and context to isAllowedAttribute (dbu)

  - bug #31059 Show more accurate message in profiler when
    missing stopwatch (linaori)

  - bug #31026 [Serializer] Add default object class
    resolver (jdecool)

  - bug #31031 [Serializer] MetadataAwareNameConverter: Do
    not assume that property names are strings (soyuka)

  - bug #31043 [VarExporter] support PHP7.4 __serialize &
    __unserialize (nicolas-grekas)

  - bug #30423 [Security] Rework firewall's access denied
    rule (dimabory)

  - bug #31020 [VarExporter] fix exporting classes with
    private constructors (nicolas-grekas)

  - bug #31012 [Process] Fix missing $extraDirs when
    open_basedir returns (arsonik)

  - bug #30852 [Console] fix buildTableRows when Colspan is
    use with content too long (Raulnet)

  - bug #30950 [Serializer] Also validate callbacks when
    given in the normalizer context (dbu)

  - bug #30907 [Serializer] Respect ignored attributes in
    cache key of normalizer (dbu)

  - bug #30085 Fix TestRunner compatibility to PhpUnit 8
    (alexander-schranz)

  - bug #30999 Fix dark themed componnents (ro0NL)

  - bug #30977 [serializer] prevent mixup in normalizer of
    the object to populate (dbu)

  - bug #30976 [Debug] Fixed error handling when an error is
    already handled when another error is already handled
    (5) (lyrixx)

  - bug #30979 Fix the configurability of CoreExtension deps
    in standalone usage (stof)

  - bug #30918 [Cache] fix using ProxyAdapter inside
    TagAwareAdapter (dmaicher)

  - bug #30961 [Form] fix translating file validation error
    message (xabbuh)

  - bug #30951 Handle case where no translations were found
    (greg0ire)

  - bug #29800 [Validator] Only traverse arrays that are
    cascaded into (corphi)

  - bug #30921 [Translator] Warm up the translations cache
    in dev (tgalopin)

  - bug #30922 [TwigBridge] fix horizontal spacing of
    inlined Bootstrap forms (xabbuh)

  - bug #30860 [Profiler] Fix dark theme elements color
    (dFayet)

  - bug #30895 [Form] turn failed file uploads into form
    errors (xabbuh)

  - bug #30919 [Translator] Fix wrong dump for PO files
    (deguif)

  - bug #30889 [DependencyInjection] Fix a wrong error when
    using a factory (Simperfit)

  - bug #30911 [Console] Fix table trailing backslash
    (maidmaid)

  - bug #30903 [Messenger] Uses the `SerializerStamp` when
    deserializing the envelope (sroze)

  - bug #30879 [Form] Php doc fixes and cs + optimizations
    (Jules Pietri)

  - bug #30883 [Console] Fix stty not reset when aborting in
    QuestionHelper::autocomplete() (Simperfit)

  - bug #30878 [Console] Fix inconsistent result for choice
    questions in non-interactive mode (chalasr)

  - bug #30825 [Routing] Fix: annotation loader ignores
    method's default values (voronkovich)

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-f5d6a7ce74"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected php-symfony4 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:L/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:php-symfony4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:30");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/02");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Fedora Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Fedora" >!< release) audit(AUDIT_OS_NOT, "Fedora");
os_ver = eregmatch(pattern: "Fedora.*release ([0-9]+)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Fedora");
os_ver = os_ver[1];
if (! ereg(pattern:"^30([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 30", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC30", reference:"php-symfony4-4.2.7-2.fc30")) flag++;


if (flag)
{
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : rpm_report_get()
  );
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "php-symfony4");
}
