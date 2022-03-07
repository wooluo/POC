#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1793.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126977);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/24  9:40:16");

  script_cve_id("CVE-2018-18541", "CVE-2019-10877", "CVE-2019-10878", "CVE-2019-10879");

  script_name(english:"openSUSE Security Update : teeworlds (openSUSE-2019-1793)");
  script_summary(english:"Check for the openSUSE-2019-1793 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for teeworlds fixes the following issues :

  - CVE-2019-10879: An integer overflow in
    CDataFileReader::Open() could have lead to a buffer
    overflow and possibly remote code execution, because
    size-related multiplications were mishandled.
    (boo#1131729)

  - CVE-2019-10878: A failed bounds check in
    CDataFileReader::GetData() and
    CDataFileReader::ReplaceData() and related functions
    could have lead to an arbitrary free and out-of-bounds
    pointer write, possibly resulting in remote code
    execution.

  - CVE-2019-10877: An integer overflow in CMap::Load()
    could have lead to a buffer overflow, because
    multiplication of width and height were mishandled.

  - CVE-2018-18541: Connection packets could have been
    forged. There was no challenge-response involved in the
    connection build up. A remote attacker could have sent
    connection packets from a spoofed IP address and occupy
    all server slots, or even use them for a reflection
    attack using map download packets. (boo#1112910)

  - Update to version 0.7.3.1

  - Colorful gametype and level icons in the browser instead
    of grayscale.

  - Add an option to use raw mouse inputs, revert to (0.6)
    relative mode by default.

  - Demo list marker indicator.

  - Restore ingame Player and Tee menus, add a warning that
    a reconnect is needed.

  - Emotes can now be cancelled by releasing the mouse in
    the middle of the circle.

  - Improve add friend text.

  - Add a confirmation for removing a filter

  - Add a 'click a player to follow' hint

  - Also hint players which key they should press to set
    themselves ready.

  - fixed using correct array measurements when placing egg
    doodads

  - fixed demo recorder downloaded maps using the sha256
    hash

  - show correct game release version in the start menu and
    console

  - Fix platform-specific client libraries for Linux

  - advanced scoreboard with game statistics

  - joystick support (experimental!)

  - copy paste (one-way)

  - bot cosmetics (a visual difference between players and
    NPCs)

  - chat commands (type / in chat)

  - players can change skin without leaving the server
    (again)

  - live automapper and complete rules for 0.7 tilesets

  - audio toggling HUD

  - an Easter surprise...

  - new gametypes: 'last man standing' (LMS) and 'last team
    standing' (LTS). survive by your own or as a team with
    limited weaponry

  - 64 players support. official gametypes are still
    restricted to 16 players maximum but allow more
    spectators

  - new skin system. build your own skins based on a variety
    of provided parts

  - enhanced security. all communications require a
    handshake and use a token to counter spoofing and
    reflection attacks

  - new maps: ctf8, dm3, lms1. Click to discover them!

  - animated background menu map: jungle, heavens (day/night
    themes, customisable in the map editor)

  - new design for the menus: added start menus, reworked
    server browser, settings

  - customisable gametype icons (browser). make your own!

  - chat overhaul, whispers (private messages)

  - composed binds (ctrl+, shift+, alt+)

  - scoreboard remodelled, now shows kills/deaths

  - demo markers

  - master server list cache (in case the masters are
    unreachable)

  - input separated from rendering (optimisation)

  - upgrade to SDL2. support for multiple monitors,
    non-english keyboards, and more

  - broadcasts overhaul, optional colours support

  - ready system, for competitive settings

  - server difficulty setting (casual, competitive, normal),
    shown in the browser

  - spectator mode improvements: follow flags, click on
    players

  - bot flags for modified servers: indicate NPCs, can be
    filtered out in the server browser

  - sharper graphics all around (no more tileset_borderfix
    and dilate)

  - refreshed the HUD, ninja cooldown, new mouse cursor

  - mapres update (higher resolution, fixes...)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1112910"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1131729"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected teeworlds packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:teeworlds");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:teeworlds-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:teeworlds-debugsource");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2018/10/20");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/24");
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
if (release !~ "^(SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.1", reference:"teeworlds-0.7.3.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"teeworlds-debuginfo-0.7.3.1-lp151.2.3.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"teeworlds-debugsource-0.7.3.1-lp151.2.3.1") ) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "teeworlds / teeworlds-debuginfo / teeworlds-debugsource");
}
