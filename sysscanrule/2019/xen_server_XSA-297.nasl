#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125389);
  script_version("1.1");
  script_cvs_date("Date: 2019/05/24 15:36:10");

  script_name(english:"Xen Project Microarchitectural Data Sampling Speculative Side-Channel Vulnerabilities (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout) (XSA-297)");
  script_summary(english:"Checks 'xl info' output for the Xen hypervisor version.");

  script_cve_id(
    "CVE-2018-12126",
    "CVE-2018-12127",
    "CVE-2018-12130",
    "CVE-2019-11091"
  );
  script_bugtraq_id(108330);
  script_xref(name:"IAVA", value:"2019-A-0168");

  script_set_attribute(attribute:"synopsis", value:
"The remote Xen hypervisor installation is missing a security update.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Xen hypervisor
installed on the remote host is affected by microarchitectural data
sampling speculative side-channel vulnerabilities. These
vulnerabilities may allow a local attacker on a guest machine to sample
the contents of memory reads and writes. Only a subset of Intel x86
processors are affected.

Note that GizaNE has checked the changeset versions based on the
xen.git change log. GizaNE did not check guest hardware configurations
or if patches were applied manually to the source code before a
recompile and reinstall.");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/xsa/advisory-297.html");
  script_set_attribute(attribute:"see_also", value:"https://xenbits.xen.org/gitweb/?p=xen.git;a=summary");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch according to the vendor advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12126");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/24");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:xen:xen");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("xen_server_detect.nbin");
  script_require_keys("installed_sw/Xen Hypervisor", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("install_func.inc");
include("misc_func.inc");

app_name = "Xen Hypervisor";
install  = get_single_install(app_name:app_name);
if (report_paranoia < 2) audit(AUDIT_PARANOID);

version         = install['version'];
display_version = install['display_version'];
path            = install['path'];
managed_status  = install['Managed status'];
changeset       = install['Changeset'];

if (!empty_or_null(changeset))
  display_version += " (changeset " + changeset + ")";

# Installations that are vendor-managed are handled by OS-specific local package checks
if (managed_status == "managed")
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, display_version, path);

fixes['4.10']['fixed_ver']           = '4.10.4';
fixes['4.10']['fixed_ver_display']   = '4.10.4-pre (changeset ab261f5)';
fixes['4.10']['affected_ver_regex']  = '^4\\.10\\.';
fixes['4.10']['affected_changesets'] = make_list("71f4a76", "b32dde3",
  "0771bb6", "4852a15", "0fe82c1", "8f0b53c", "aa6978c", "923d4e8",
  "7ddfc2a", "f725721", "7dfea78", "f0c5805", "3f5490d", "d06f561",
  "92fc0b6", "b8071f3", "5200791", "3b0eebb", "5a81de4", "b2bbd34",
  "7842419", "9f663d2", "d176cd6", "a595111", "aae0d18", "631b902",
  "f6f1e94", "b450b20", "dfc7e3c", "382e4a6", "edbc9b0", "edb80d2");

fixes['4.11']['fixed_ver']           = '4.11.2';
fixes['4.11']['fixed_ver_display']   = '4.11.2-pre (changeset a6e0749)';
fixes['4.11']['affected_ver_regex']  = '^4\\.11\\.';
fixes['4.11']['affected_changesets'] = make_list("bd03b27", "b09886e",
  "bac4405", "0d8e6f7", "9be6613", "f5cc6e1", "3b062f5", "0825fbd",
  "bdb0630", "eb8acba", "0ebfc81", "e983e8a", "348922b", "718a8d2",
  "fc46e15", "4db8fdd", "c74683a", "793d669", "1b0e77d", "dd32dab",
  "03afae6", "aea41c3", "935a4ad", "833788f", "b77bf91", "cf99010",
  "0c0f0ab", "e984846", "4f9ab5f", "c567b05", "6c197f9", "7bbd3a5",
  "92227e2", "4835974", "be58f86", "4298abd", "4f785ea", "1028304",
  "87f51bf", "dd492b8", "e2e3a1d", "850ca94", "514dccd", "e202feb",
  "1986728", "2cd833d", "de09411", "dd914e4", "63d7113", "af25f52",
  "91f2ad7", "0b2be0b", "7d1bd98", "d8b2418", "bf608fd");

fixes['4.12']['fixed_ver']           = '4.12.1';
fixes['4.12']['fixed_ver_display']   = '4.12.1-pre (changeset 714207b)';
fixes['4.12']['affected_ver_regex']  = '^4\\.12\\.';
fixes['4.12']['affected_changesets'] = make_list("45d570e", "0a317c5",
  "fe1ba9d", "6d8f5e3", "944b400", "143712d", "fd2a34c", "e25d133",
  "7cf6fbc", "7f53be2", "eb90521", "c75d5fe", "e3a1ebe", "70d613d",
  "8593e79", "a6c708d", "36f0463", "c4b1a75", "18f6fb9");

fix = NULL;
foreach ver_branch (keys(fixes))
{
  if (version =~ fixes[ver_branch]['affected_ver_regex'])
  {
    ret = ver_compare(ver:version, fix:fixes[ver_branch]['fixed_ver']);
    if (ret < 0)
      fix = fixes[ver_branch]['fixed_ver_display'];
    else if (ret == 0)
    {
      if (empty_or_null(changeset))
        fix = fixes[ver_branch]['fixed_ver_display'];
      else
        foreach affected_changeset (fixes[ver_branch]['affected_changesets'])
          if (changeset == affected_changeset)
            fix = fixes[ver_branch]['fixed_ver_display'];
    }
  }
}

if (empty_or_null(fix))
  audit(AUDIT_INST_PATH_NOT_VULN, app_name, display_version, path);

items  = make_array(
  "Installed version", display_version,
  "Fixed version", fix,
  "Path", path
);

order  = make_list("Path", "Installed version", "Fixed version");
report = report_items_str(report_items:items, ordered_fields:order) + '\n';

security_report_v4(port:0, extra:report, severity:SECURITY_WARNING);
