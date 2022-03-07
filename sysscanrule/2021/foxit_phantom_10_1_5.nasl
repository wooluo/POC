
##
# 
##


include('compat.inc');

if (description)
{
  script_id(152861);
  script_version("1.3");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/08/30");

  script_cve_id(
    "CVE-2021-21831",
    "CVE-2021-21870",
    "CVE-2021-21893",
    "CVE-2021-34831",
    "CVE-2021-34832",
    "CVE-2021-34833",
    "CVE-2021-34834",
    "CVE-2021-34835",
    "CVE-2021-34836",
    "CVE-2021-34837",
    "CVE-2021-34838",
    "CVE-2021-34839",
    "CVE-2021-34840",
    "CVE-2021-34841",
    "CVE-2021-34842",
    "CVE-2021-34843",
    "CVE-2021-34844",
    "CVE-2021-34845",
    "CVE-2021-34846",
    "CVE-2021-34847",
    "CVE-2021-34851",
    "CVE-2021-34852",
    "CVE-2021-34853"
  );

  script_name(english:"Foxit PhantomPDF < 10.1.5 Multiple Vulnerabilities");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally known as Phantom) installed on the remote Windows
host is prior to 10.1.5. It is, therefore affected by multiple vulnerabilities:

  - A use-after-free vulnerability exists in the JavaScript engine of Foxit Softwares PDF Reader, version
    10.1.3.37598. A specially crafted PDF document can trigger the reuse of previously freed memory, which can
    lead to arbitrary code execution. An attacker needs to trick the user to open the malicious file to
    trigger this vulnerability. Exploitation is also possible if a user visits a specially crafted, malicious
    site if the browser plugin extension is enabled. (CVE-2021-21831)

  - A use-after-free vulnerability exists in the JavaScript engine of Foxit Softwares PDF Reader, version
    10.1.4.37651. A specially crafted PDF document can trigger the reuse of previously free memory, which can
    lead to arbitrary code execution. An attacker needs to trick the user into opening a malicious file or
    site to trigger this vulnerability if the browser plugin extension is enabled. (CVE-2021-21870)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit
    Reader 10.1.4.37651. User interaction is required to exploit this vulnerability in that the target must
    visit a malicious page or open a malicious file. The specific flaw exists within the handling of Document
    objects. The issue results from the lack of validating the existence of an object prior to performing
    operations on the object. An attacker can leverage this vulnerability to execute code in the context of
    the current process. Was ZDI-CAN-13741. (CVE-2021-34831)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit
    PDF Reader 11.0.0.49893. User interaction is required to exploit this vulnerability in that the target
    must visit a malicious page or open a malicious file. The specific flaw exists within the handling of the
    delay property. The issue results from the lack of validating the existence of an object prior to
    performing operations on the object. An attacker can leverage this vulnerability to execute code in the
    context of the current process. Was ZDI-CAN-13928. (CVE-2021-34832)

  - This vulnerability allows remote attackers to execute arbitrary code on affected installations of Foxit
    PDF Reader 11.0.0.49893. User interaction is required to exploit this vulnerability in that the target
    must visit a malicious page or open a malicious file. The specific flaw exists within the handling of
    Annotation objects. The issue results from the lack of validating the existence of an object prior to
    performing operations on the object. An attacker can leverage this vulnerability to execute code in the
    context of the current process. Was ZDI-CAN-14270. (CVE-2021-34847)

Note that Nessus has not tested for this issue but has instead relied only on the application's self-reported version
number.");
  # https://www.foxitsoftware.com/support/security-bulletins.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a27a3e57");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 10.1.5 or later");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2021-34853");

  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2021/07/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2021/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2021/08/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF", "SMB/Registry/Enumerated");

  exit(0);
}

include('vcf.inc');

var app_info = vcf::get_app_info(app:'FoxitPhantomPDF', win_local:TRUE);

var constraints = [
  { 'max_version' : '10.1.4.37651', 'fixed_version' : '10.1.5' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_WARNING);
