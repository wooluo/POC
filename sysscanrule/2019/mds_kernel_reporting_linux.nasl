#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(126244);
  script_version("1.1");
  script_cvs_date("Date: 2019/06/25 10:59:07");

  script_cve_id("CVE-2018-12126", "CVE-2018-12127", "CVE-2018-12130", "CVE-2019-11091");

  script_name(english:"Linux Kernel Detection of MDS vulnerabilities (MDSUM/RIDL) (MFBDS/RIDL/ZombieLoad) (MLPDS/RIDL) (MSBDS/Fallout)");
  script_summary(english:"Checks for vulnerability indicators in /sys/devices/system/cpu/vulnerabilities/mds.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Linux kernel is affected by a series of information
disclosure vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to the remote Linux kernel, this system is vulnerable to
the following information disclosure vulnerabilities:

  - MSBDS leaks Store Buffer Entries which can be
    speculatively forwarded to a dependent load
    (store-to-load forwarding) as an optimization. The
    forward can also happen to a faulting or assisting load
    operation for a different memory address, which can
    cause an issue under certain conditions. Store buffers
    are partitioned between Hyper-Threads so cross thread
    forwarding is not possible. But if a thread enters or
    exits a sleep state the store buffer is repartitioned
    which can expose data from one thread to the other.
    (MSBDS/Fallout) (CVE-2018-12126)

  - MLDPS leaks Load Port Data. Load ports are used to
    perform load operations from memory or I/O. The received
    data is then forwarded to the register file or a
    subsequent operation. In some implementations the Load
    Port can contain stale data from a previous operation
    which can be forwarded to faulting or assisting loads
    under certain conditions, which again can cause an issue
    eventually. Load ports are shared between Hyper-Threads
    so cross thread leakage is possible. (MLPDS/RIDL)
    (CVE-2018-12127)

    MFBDS leaks Fill Buffer Entries. Fill buffers are used
    internally to manage L1 miss situations and to hold data
    which is returned or sent in response to a memory or I/O
    operation. Fill buffers can forward data to a load
    operation and also write data to the cache. When the
    fill buffer is deallocated it can retain the stale data
    of the preceding operations which can then be forwarded
    to a faulting or assisting load operation, which can
    cause an issue under certain conditions. Fill buffers
    are shared between Hyper-Threads so cross thread leakage
    is possible. (MFBDS/RIDL/ZombieLoad) (CVE-2018-12130)

  - MDSUM is a special case of MSBDS, MFBDS and MLPDS. An
    uncacheable load from memory that takes a fault or
    assist can leave data in a microarchitectural structure
    that may later be observed using one of the same methods
    used by MSBDS, MFBDS or MLPDS. (MDSUM/RIDL)
    (CVE-2019-11091)

To address these issues, update the kernel packages on your Linux
system, disable Simultaneous Multi-Threading (SMT) or otherwise
configure it to a non-vulnerable state, and apply microcode fixes to
your hardware. Consult your Linux distribution and processor hardware
vendors for details and patches.");
  script_set_attribute(attribute:"see_also", value:"https://mdsattacks.com/");
  script_set_attribute(attribute:"see_also", value:"https://www.kernel.org/doc/html/latest/admin-guide/hw-vuln/mds.html");
  script_set_attribute(attribute:"solution", value:
"1.  Ensure the latest kernel and package updates are applied to your
    linux packages for your OS distribution.
2.  Either disable SMT or configure it to a non-vulnerable state.
    Consult your processor manufacturer for details.
3.  Apply the appropriate microcode fix for your hardware. Consult
    your processor manufacturer for details.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:C/C:H/I:N/A:N");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-12126");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/05/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/06/25");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:linux:linux_kernel");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("ssh_get_info2.nasl");
  script_require_keys("Host/Linux", "Settings/ParanoidReport");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("audit.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("Host/Linux");
mds_results = get_one_kb_item("Host/cpu/vulnerabilities/mds");
if (empty_or_null(mds_results))
{
  report =
"Either the Linux system is running a kernel that is outdated enough
that it does not record whether or not it is vulnerable to
Microarchitectural Data Sampling attacks, or a permissions issue was
encountered when trying to access that data. A file containing those
details should be found in /sys/devices/system/cpu/vulnerabilities/mds
Ensure your scan has access to that file, and rerun the scan. It is
extremely likely that the kernel is vulnerable if that mds file is not
present.

Check your scan account's permissions, and update your kernel packages
to the latest versions available from your Linux distribution vendor
(and reboot the system). If this scan continues to report that the
file is missing, you may need to contact your Linux distribution
vendor to determine why the kernel is not reporting details of whether
or not MDS attacks are mitigated or vulnerable on the system."; 
  security_report_v4(
    port       : 0,
    severity   : SECURITY_WARNING,
    extra      : report
  );
  exit(0);
}
matches = pregmatch(string:mds_results, pattern:"^(Vulnerable|Not affected|Mitigation)(?:[:;] (.+))?$");
if(!empty_or_null(matches) && len(matches) >= 2)
{
  result = matches[1];
  details = "";
  if (!empty_or_null(matches[2]))
  {
    details = matches[2];
  }
  if (result == "Not affected")
  {
    exit(0, "The processor is not vulnerable to MDS attacks.");
  }
  else if (result == "Mitigation")
  {
    report = 'The processor is vulnerable to MDS attacks, but the CPU buffer clearing\nmitigation is enabled, so the vulnerability is mitigated.';
    if (!empty_or_null(details)) {
      report += " Additional Details: " + details;
    } 
    exit(0, report);
  }
  else
  {
    report = mds_results + '\n\nThe processor is vulnerable to MDS attacks, and the CPU buffer clearing\nmitigation has not been enabled.\n\n' +
             'Consult your processor hardware and OS software vendors for patches and\nmitigations to apply.';
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : report
    );
    exit(0);
  }
}

# If this spot is reached then /sys/devices/system/cpu/vulnerabilities/mds contains something unusual.
exit(0, "The contents of /sys/devices/system/cpu/vulnerabilities/mds contain an unexpected result and the host's vulnerability to MDS attacks cannot be determined.");
