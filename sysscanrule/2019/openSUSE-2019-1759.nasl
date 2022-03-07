#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update openSUSE-2019-1759.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(126899);
  script_version("1.2");
  script_cvs_date("Date: 2019/08/12 17:35:39");

  script_cve_id("CVE-2019-12735");

  script_name(english:"openSUSE Security Update : neovim (openSUSE-2019-1759)");
  script_summary(english:"Check for the openSUSE-2019-1759 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update for neovim fixes the following issues :

neovim was updated to version 0.3.7 :

  - CVE-2019-12735: source should check sandbox
    (boo#1137443)

  - genappimage.sh: migrate to linuxdeploy

Version Update to version 0.3.5 :

  - options: properly reset directories on 'autochdir'

  - Remove MSVC optimization workaround for SHM_ALL

  - Make SHM_ALL to a variable instead of a compound literal
    #define

  - doc: mention 'pynvim' module rename

  - screen: don't crash when drawing popupmenu with
    'rightleft' option

  - look-behind match may use the wrong line number

  - :terminal : set topline based on window height

  - :recover : Fix crash on non-existent *.swp

Version Update to version 0.3.4 :

  - test: add tests for conceal cursor movement

  - display: unify ursorline and concealcursor redraw logic

Version Update to version 0.3.3 :

  - health/provider: Check for available pynvim when neovim
    mod is missing

  - python#CheckForModule: Use the given module string
    instead of hard-coding pynvim

  - (health.provider)/python: Import the neovim, rather than
    pynvim, module

  - TUI: Konsole DECSCUSR fixup

Version Update to version 0.3.2:- 

  - Features

  - clipboard: support Custom VimL functions (#9304)

  - win/TUI: improve terminal/console support (#9401)

  - startup: Use $XDG_CONFIG_DIRS/nvim/sysinit.vim if exists
    (#9077)

  - support mapping in more places (#9299)

  - diff/highlight: show underline for low-priority
    CursorLine (#9028)

  - signs: Add 'nuhml' argument (#9113)

  - clipboard: support Wayland (#9230)

  - TUI: add support for undercurl and underline color
    (#9052)

  - man.vim: soft (dynamic) wrap (#9023)

  - API

  - API: implement object namespaces (#6920)

  - API: implement nvim_win_set_buf() (#9100)

  - API: virtual text annotations
    (nvim_buf_set_virtual_text) (#8180)

  - API: add nvim_buf_is_loaded() (#8660)

  - API: nvm_buf_get_offset_for_line (#8221)

  - API/UI: ext_newgrid, ext_histate (#8221)

  - UI

  - TUI: use BCE again more often (smoother resize) (#8806)

  - screen: add missing status redraw when
    redraw_later(CLEAR) was used (#9315)

  - TUI: clip invalid regions on resize (#8779)

  - TUI: improvements for scrolling and clearing (#9193)

  - TUI: disable clearing almost everywhere (#9143)

  - TUI: always use safe cursor movement after resize
    (#9079)

  - ui_options: also send when starting or from OptionSet
    (#9211)

  - TUI: Avoid reset_color_cursor_color in old VTE (#9191)

  - Don't erase screen on :hi Normal during startup (#9021)

  - TUI: Hint wrapped lines to terminals (#8915) 

  - FIXES

  - RPC: turn errors from async calls into notifications

  - TUI: Restore terminal title via 'title stacking' (#9407)

  - genappimage: Unset $ARGV0 at invocation (#9376)

  - TUI: Konsole 18.07.70 supports DECSCUSR (#9364)

  - provider: improve error message (#9344) 

  - runtime/syntax: Fix highlighting of autogroup contents
    (#9328)

  - VimL/confirm(): Show dialog even if :silent (#9297)

  - clipboard: prefer xclip (#9302)

  - provider/nodejs: fix npm, yarn detection

  - channel: avoid buffering output when only terminal is
    active (#9218)

  - ruby: detect rbenv shims for other versions (#8733)

  - third-party/unibilium: Fix parsing of extended
    capabilitiy entries (#9123)

  - jobstart(): Fix hang on non-executable cwd (#9204)

  - provide/nodejs: Simultaneously query npm and yarn
    (#9054)

  - undo: Fix infinite loop if undo_read_byte returns EOF
    (#2880) 

  - 'swapfile: always show dialog' (#9034) 

  - Add to the system-wide configuration file extension of
    runtimepath by /usr/share/vim/site, so that neovim uses
    other Vim plugins installed from packages.

  - Add /usr/share/vim/site tree of directories to be owned
    by neovim as well."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.opensuse.org/show_bug.cgi?id=1137443"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected neovim packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neovim");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neovim-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neovim-debugsource");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:neovim-lang");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:15.1");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/06/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/22");
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
if (release !~ "^(SUSE15\.0|SUSE15\.1)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "15.0 / 15.1", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(x86_64)$") audit(AUDIT_ARCH_NOT, "x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE15.0", reference:"neovim-0.3.7-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"neovim-debuginfo-0.3.7-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"neovim-debugsource-0.3.7-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.0", reference:"neovim-lang-0.3.7-lp150.13.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"neovim-0.3.7-lp151.2.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"neovim-debuginfo-0.3.7-lp151.2.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"neovim-debugsource-0.3.7-lp151.2.7.1") ) flag++;
if ( rpm_check(release:"SUSE15.1", reference:"neovim-lang-0.3.7-lp151.2.7.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "neovim / neovim-debuginfo / neovim-debugsource / neovim-lang");
}
