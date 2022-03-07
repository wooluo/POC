#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(125449);
  script_version("1.5");
  script_cvs_date("Date: 2019/07/26 16:46:13");

  script_cve_id("CVE-2018-18511", "CVE-2019-11691", "CVE-2019-11692", "CVE-2019-11693", "CVE-2019-11698", "CVE-2019-5798", "CVE-2019-7317", "CVE-2019-9797", "CVE-2019-9800", "CVE-2019-9816", "CVE-2019-9817", "CVE-2019-9819", "CVE-2019-9820");

  script_name(english:"Scientific Linux Security Update : firefox on SL7.x x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update upgrades Firefox to version 60.7.0 ESR.

Security Fix(es) :

  - Mozilla: Memory safety bugs fixed in Firefox 67 and
    Firefox ESR 60.7 (CVE-2019-9800)

  - Mozilla: Cross-origin theft of images with
    createImageBitmap (CVE-2019-9797)

  - Mozilla: Type confusion with object groups and
    UnboxedObjects (CVE-2019-9816)

  - Mozilla: Stealing of cross-domain images using canvas
    (CVE-2019-9817)

  - Mozilla: Compartment mismatch with fetch API
    (CVE-2019-9819)

  - Mozilla: Use-after-free of ChromeEventHandler by
    DocShell (CVE-2019-9820)

  - Mozilla: Use-after-free in XMLHttpRequest
    (CVE-2019-11691)

  - Mozilla: Use-after-free removing listeners in the event
    listener manager (CVE-2019-11692)

  - Mozilla: Buffer overflow in WebGL bufferdata on Linux
    (CVE-2019-11693)

  - mozilla: Cross-origin theft of images with
    ImageBitmapRenderingContext (CVE-2018-18511)

  - chromium-browser: Out of bounds read in Skia
    (CVE-2019-5798)

  - Mozilla: Theft of user history data through drag and
    drop of hyperlinks to and from bookmarks
    (CVE-2019-11698)

  - libpng: use-after-free in png_image_free in png.c
    (CVE-2019-7317)"
  );
  # https://listserv.fnal.gov/scripts/wa.exe?A2=ind1905&L=SCIENTIFIC-LINUX-ERRATA&P=5954
  script_set_attribute(
    attribute:"see_also",
    value:""
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected firefox and / or firefox-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/02/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/28");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"firefox-60.7.0-1.el7_6")) flag++;
if (rpm_check(release:"SL7", cpu:"x86_64", reference:"firefox-debuginfo-60.7.0-1.el7_6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");