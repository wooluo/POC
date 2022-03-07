#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(125153);
  script_version("1.3");
  script_cvs_date("Date: 2019/06/13 17:57:55");

  script_cve_id(
    "CVE-2018-20309",
    "CVE-2018-20310",
    "CVE-2018-20311",
    "CVE-2018-20312",
    "CVE-2018-20313",
    "CVE-2018-20314",
    "CVE-2018-20315",
    "CVE-2018-20316",
    "CVE-2019-6754",
    "CVE-2019-6755",
    "CVE-2019-6756",
    "CVE-2019-6757",
    "CVE-2019-6758",
    "CVE-2019-6759",
    "CVE-2019-6760",
    "CVE-2019-6761",
    "CVE-2019-6762",
    "CVE-2019-6763",
    "CVE-2019-6764",
    "CVE-2019-6765",
    "CVE-2019-6766",
    "CVE-2019-6767",
    "CVE-2019-6768",
    "CVE-2019-6769",
    "CVE-2019-6770",
    "CVE-2019-6771",
    "CVE-2019-6772",
    "CVE-2019-6773"
  );
  script_xref(name:"ZDI", value:"ZDI-19-428");
  script_xref(name:"ZDI", value:"ZDI-19-429");
  script_xref(name:"ZDI", value:"ZDI-19-430");
  script_xref(name:"ZDI", value:"ZDI-19-431");
  script_xref(name:"ZDI", value:"ZDI-19-432");
  script_xref(name:"ZDI", value:"ZDI-19-433");
  script_xref(name:"ZDI", value:"ZDI-19-434");
  script_xref(name:"ZDI", value:"ZDI-19-435");
  script_xref(name:"ZDI", value:"ZDI-19-436");
  script_xref(name:"ZDI", value:"ZDI-19-437");
  script_xref(name:"ZDI", value:"ZDI-19-438");
  script_xref(name:"ZDI", value:"ZDI-19-439");
  script_xref(name:"ZDI", value:"ZDI-19-440");
  script_xref(name:"ZDI", value:"ZDI-19-441");
  script_xref(name:"ZDI", value:"ZDI-19-442");
  script_xref(name:"ZDI", value:"ZDI-19-443");
  script_xref(name:"ZDI", value:"ZDI-19-444");
  script_xref(name:"ZDI", value:"ZDI-19-445");
  script_xref(name:"ZDI", value:"ZDI-19-446");
  script_xref(name:"ZDI", value:"ZDI-19-447");
  script_xref(name:"ZDI", value:"ZDI-CAN-7407");
  script_xref(name:"ZDI", value:"ZDI-CAN-7561");
  script_xref(name:"ZDI", value:"ZDI-CAN-7613");
  script_xref(name:"ZDI", value:"ZDI-CAN-7614");
  script_xref(name:"ZDI", value:"ZDI-CAN-7620");
  script_xref(name:"ZDI", value:"ZDI-CAN-7694");
  script_xref(name:"ZDI", value:"ZDI-CAN-7696");
  script_xref(name:"ZDI", value:"ZDI-CAN-7701");
  script_xref(name:"ZDI", value:"ZDI-CAN-7769");
  script_xref(name:"ZDI", value:"ZDI-CAN-7777");
  script_xref(name:"ZDI", value:"ZDI-CAN-7844");
  script_xref(name:"ZDI", value:"ZDI-CAN-7874");
  script_xref(name:"ZDI", value:"ZDI-CAN-7972");
  script_xref(name:"ZDI", value:"ZDI-CAN-8162");
  script_xref(name:"ZDI", value:"ZDI-CAN-8163");
  script_xref(name:"ZDI", value:"ZDI-CAN-8164");
  script_xref(name:"ZDI", value:"ZDI-CAN-8165");
  script_xref(name:"ZDI", value:"ZDI-CAN-8170");
  script_xref(name:"ZDI", value:"ZDI-CAN-8229");
  script_xref(name:"ZDI", value:"ZDI-CAN-8230");
  script_xref(name:"ZDI", value:"ZDI-CAN-8231");
  script_xref(name:"ZDI", value:"ZDI-CAN-8272");

  script_name(english:"Foxit Reader < 9.5.0 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit Reader.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",  value:
"According to its version, the Foxit Reader application (formally
known as Phantom) installed on the remote Windows host is prior to
8.3.10. It is, therefore, affected by multiple vulnerabilities:

  - A heap-based buffer overflow condition exists in the 
    proxyCPDFAction, proxyCheckLicence, proxyDoAction, 
    proxyGetAppEdition, or proxyPreviewAction due to a stack buffer 
    overflow or out-of-bounds read. An authenticated, local attacker 
    can exploit this, via large integer or long string causing a 
    denial of service condition or the execution of arbitrary code.

  - A directory traversal vulnerability exists in the cPDF plugin due
    to unexpected javascript invocation resulting in remote code 
    execution. An unauthenticated, remote attacker can exploit this, 
    by invoking javascript through the console to write local files. 
    (ZDI-CAN-7407)

  - A integer overflow and crash condition exists in the XFA stuff 
    method due to the lack of proper validation of user-supplied 
    data. An attacker can explit this to disclose information. 
    (ZDI-CAN-7561)

  - A use-after-free, out-of-bounds read, and crash vulnerability 
    exists when converting HTML files to PDFs. An authenticated, 
    remote attacker can exploit this to disclose information
    or to execute arbitrary code. 
    (ZDI-CAN-7620/ZDI-CAN-7844/ZDI-CAN-8170)   

  - A out-of-bounds write and crash vulnerability exists. An 
    authenticated, remote attacker can exploit this to execute 
    arbitrary code. (ZDI-CAN-7613/ZDI-CAN-7614/ZDI-CAN-7701/
    ZDI-CAN-7972)

  - A use-after-free or out-of-bounds write and crash vulnerability 
    exists. An authenticated, local attacker can exploit this to 
    execute arbitrary code. (ZDI-CAN-7696/ZDI-CAN-7694)

  - A use-after-free vulnerability. An authenticated, 
    remote attacker can exploit this to execute arbitrary 
    code. (ZDI-CAN-7696/ZDI-CAN-7694/ZDI-CAN-7777/ZDI-CAN-7874)

  - A use-after-free, remote code execution, information 
    disclosure vulnerability exists when deleting Field with nested
    scripts. An authenticated, local attacker can exploit this to 
    execute arbitrary code. (ZDI-CAN-8162/ZDI-CAN-8163/ZDI-CAN-8164/
    ZDI-CAN-8165/ZDI-CAN-8229/ZDI-CAN-8230/ZDI-CAN-8231/ZDI-CAN-8272)");
  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-428/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-429/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-430/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-431/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-432/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-433/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-434/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-435/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-436/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-437/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-438/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-439/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-440/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-441/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-442/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-443/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-444/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-445/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-446/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-19-447/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7407/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7561/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7613/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7614/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7620/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7694/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7696/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7701/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7769/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7777/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7844/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7874/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-7972/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8162/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8163/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8164/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8165/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8170/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8229/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8230/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8231/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8272/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit Reader version 9.5.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2018-20316");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/05/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:foxit_reader");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_reader_installed.nasl");
  script_require_keys("installed_sw/Foxit Reader");

  exit(0);
}

include('vcf.inc');

app = 'Foxit Reader';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '9.0', 'max_version' : '9.4.1.16828', 'fixed_version' : '9.5.0'}
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
