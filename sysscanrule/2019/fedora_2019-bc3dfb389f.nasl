#
# (C) WebRAY Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Fedora Security Advisory FEDORA-2019-bc3dfb389f.
#

include("compat.inc");

if (description)
{
  script_id(126663);
  script_version("1.1");
  script_cvs_date("Date: 2019/07/15 14:20:21");

  script_cve_id("CVE-2019-11503");
  script_xref(name:"FEDORA", value:"2019-bc3dfb389f");

  script_name(english:"Fedora 29 : snapd-glib (2019-bc3dfb389f)");
  script_summary(english:"Checks rpm output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Fedora host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"#### Update to v1.48

  - New API :

  - `snapd_client_get_connections_async`

  - `snapd_client_get_connections_finish`

  - `snapd_client_get_connections_sync`

  - `snapd_client_get_interfaces2_async`

  - `snapd_client_get_interfaces2_finish`

  - `snapd_client_get_interfaces2_sync`

  - `snapd_client_get_snap_conf_async`

  - `snapd_client_get_snap_conf_finish`

  - `snapd_client_get_snap_conf_sync`

  - `snapd_client_set_snap_conf_async`

  - `snapd_client_set_snap_conf_finish`

  - `snapd_client_set_snap_conf_sync`

  - `snapd_connection_get_gadget`

  - `snapd_connection_get_interface`

  - `snapd_connection_get_manual`

  - `snapd_connection_get_plug`

  - `snapd_connection_get_plug_attribute`

  - `snapd_connection_get_plug_attribute_names`

  - `snapd_connection_get_slot`

  - `snapd_connection_get_slot_attribute`

  - `snapd_connection_get_slot_attribute_names`

  - `snapd_connection_has_plug_attribute`

  - `snapd_connection_has_slot_attribute`

  - `snapd_interface_get_doc_url`

  - `snapd_interface_get_name`

  - `snapd_interface_get_plugs`

  - `snapd_interface_get_slots`

  - `snapd_interface_get_summary`

  - `snapd_markdown_node_get_children`

  - `snapd_markdown_node_get_node_type`

  - `snapd_markdown_node_get_text`

  - `snapd_markdown_parser_new`

  - `snapd_markdown_parser_get_combine_whitespace`

  - `snapd_markdown_parser_parse`

  - `snapd_markdown_parser_set_combine_whitespace`

  - `snapd_plug_get_connected_slots`

  - `snapd_plug_ref_get_plug`

  - `snapd_plug_ref_get_snap`

  - `snapd_slot_get_connected_plugs`

  - `snapd_slot_ref_get_slot`

  - `snapd_slot_ref_get_snap`

  - `SNAPD_ERROR_OPTION_NOT_FOUND`

  - Deprecated API :

  - `snapd_client_get_interfaces_async`

  - `snapd_client_get_interfaces_finish`

  - `snapd_client_get_interfaces_sync`

  - `snapd_connection_get_name`

  - `snapd_connection_get_snap`

  - `snapd_plug_get_connections`

  - `snapd_slot_get_connections`

  - Allow searching via common-id

  - Add a description markdown parser

  - Replace `SnapdConnection` with `SnapdPlugRef` and
    `SnapdSlotRef`

  - Support updated connections API (`/v2/connections`)

  - Support updated `/v2/interfaces&select=` API

  - Support snap configuration API

  - Add Qt interface attribute API

  - Make `snapd_client_set_socket_path` revert to the
    default when `NULL` passed.

  - Fix C99 mode not being enabled on older versions of GCC

Note that WebRAY Network Security has extracted the preceding
description block directly from the Fedora update system website.
WebRAY has attempted to automatically clean and format it as much as
possible without introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bodhi.fedoraproject.org/updates/FEDORA-2019-bc3dfb389f"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected snapd-glib package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:H/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:fedoraproject:fedora:snapd-glib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:fedoraproject:fedora:29");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/15");
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
if (! ereg(pattern:"^29([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Fedora 29", "Fedora " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Fedora", cpu);


flag = 0;
if (rpm_check(release:"FC29", reference:"snapd-glib-1.48-1.fc29")) flag++;


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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "snapd-glib");
}
