#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1770.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126903);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/22 10:22:10");

  script_cve_id("CVE-2019-9836");

  script_name(english:"openSUSE Security Update : kernel-firmware (openSUSE-2019-1770)");
  script_summary(english:"Check for the openSUSE-2019-1770 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for kernel-firmware fixes the following issues :

kernel-firmware was updated to version 20190618 :

  - cavium: Add firmware for CNN55XX crypto driver.

  - linux-firmware: Update firmware file for Intel Bluetooth
    22161

  - linux-firmware: Update firmware file for Intel Bluetooth
    9560

  - linux-firmware: Update firmware file for Intel Bluetooth
    9260

  - linux-firmware: Update AMD SEV firmware (CVE-2019-9836,
    bsc#1139383)

  - linux-firmware: update licence text for Marvell firmware

  - linux-firmware: update firmware for mhdp8546

  - linux-firmware: rsi: update firmware images for Redpine
    9113 chipset

  - imx: sdma: update firmware to v3.5/v4.5

  - nvidia: update GP10[2467] SEC2 RTOS with the one already
    used on GP108

  - linux-firmware: Update firmware file for Intel Bluetooth
    8265

  - linux-firmware: Update firmware file for Intel Bluetooth
    9260

  - linux-firmware: Update firmware file for Intel Bluetooth
    9560

  - amlogic: add video decoder firmwares

  - iwlwifi: update -46 firmwares for 22260 and 9000 series

  - iwlwifi: add firmware for 22260 and update 9000 series
    -46 firmwares

  - iwlwifi: add -46.ucode firmwares for 9000 series

  - amdgpu: update vega20 to the latest 19.10 firmware

  - amdgpu: update vega12 to the latest 19.10 firmware

  - amdgpu: update vega10 to the latest 19.10 firmware

  - amdgpu: update polaris11 to the latest 19.10 firmware

  - amdgpu: update polaris10 to the latest 19.10 firmware

  - amdgpu: update raven2 to the latest 19.10 firmware

  - amdgpu: update raven to the latest 19.10 firmware

  - amdgpu: update picasso to the latest 19.10 firmware

  - linux-firmware: update fw for qat devices

  - Mellanox: Add new mlxsw_spectrum firmware 13.2000.1122

  - drm/i915/firmware: Add ICL HuC v8.4.3238

  - drm/i915/firmware: Add ICL GuC v32.0.3

  - drm/i915/firmware: Add GLK HuC v03.01.2893

  - drm/i915/firmware: Add GLK GuC v32.0.3

  - drm/i915/firmware: Add KBL GuC v32.0.3

  - drm/i915/firmware: Add SKL GuC v32.0.3

  - drm/i915/firmware: Add BXT GuC v32.0.3

  - linux-firmware: Add firmware file for Intel Bluetooth
    22161

  - cxgb4: update firmware to revision 1.23.4.0
    (bsc#1136334)

  - linux-firmware: Update NXP Management Complex firmware
    to version 10.14.3

  - linux-firmware: add firmware for MT7615E

  - mediatek: update MT8173 VPU firmware to v1.1.2 [decoder]
    Enlarge struct vdec_pic_info to support more capture
    buffer plane and capture buffer format change.

  - linux-firmware: update Marvell 8797/8997 firmware images

  - nfp: update Agilio SmartNIC flower firmware to rev
    AOTC-2.10.A.23

This update was imported from the SUSE:SLE-15:Update update project."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1136498"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1139383"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:kernel-firmware");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:ucode-amd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");
  script_set_attribute(attribute:"generated_plugin", value:"current");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE15\.0|SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);



flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"kernel-firmware-20190618-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"ucode-amd-20190618-lp150.2.19.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"kernel-firmware-20190618-lp151.2.6.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"ucode-amd-20190618-lp151.2.6.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-firmware / ucode-amd");
}
