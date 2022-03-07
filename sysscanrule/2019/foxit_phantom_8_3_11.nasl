#
# (C) WebRAY Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(127059);
  script_version("1.2");
  script_cvs_date("Date: 2019/07/26 16:36:28");

  script_cve_id(
    "CVE-2019-6774",
    "CVE-2019-6775",
    "CVE-2019-6776",
    "CVE-2019-13315",
    "CVE-2019-13316",
    "CVE-2019-13317",
    "CVE-2019-13318",
    "CVE-2019-13319",
    "CVE-2019-13320",
    "CVE-2019-14207",
    "CVE-2019-14211",
    "CVE-2019-14212",
    "CVE-2019-14213"
  );

  script_bugtraq_id(
    109313,
    109314,
    109358,
    109368
  );

  script_xref(name:"IAVA", value:"2019-A-0265");

  script_name(english:"Foxit PhantomPDF < 8.3.11 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Foxit PhantomPDF.");

  script_set_attribute(attribute:"synopsis", value:
"A PDF toolkit installed on the remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"According to its version, the Foxit PhantomPDF application (formally
known as Phantom) installed on the remote Windows host is prior to
8.3.11. It is, therefore affected by multiple vulnerabilities: 

   - An uninitialized pointer flaw exists when calling
    xfa.event.rest XFA JavaScript that can cause the
    application to crash the application.

  - A NULL pointer dereference flaw exists when calling
    certain XFA JavaScript and can cause the application
    to crash. (CVE-2019-14212)
    
  - An array-indexing error exists during XFA layout when
    the original node object contains one more contentArea
    object than that in XFA layout and cause the
    application to crash.

  - A use-after-free remote code execution vulnerability
    exists when processing AcroForms because an additional
    event is triggered to delete ListBox and ComboBox
    Field when trying to delete the items in ListBox and
    ComboBox Field by calling the deleteItemAt method.
    (CVE-2019-6774)

  - A heap buffer overflow vulnerability exists because the
    maximum length in For loop is not updated correctly
    when all the Field APs are updated after executing
    Field related JavaScript, and this can cause the
    application to crash.

  - An unspecified vulnerability exists where the repeated
    release of signature dictionary during CSG_SignatureF
    and CPDF_Document destruction can cause the application
    to crash.(CVE-2019-14213)

  - An unspecified vulnerability exists due to the lack of
    proper validation of the existence of an object prior
    to performing operations on the object when executing
    JavaScript. This can cause the application to crash.
    (CVE-2019-14211)

  - A use-after-free remote code execution vulnerability
    exists because Field object is deleted during parameter
    calculation when setting certain attributes in Field
    object using JavaScript. (CVE-2019-6775, CVE-2019-6776,
    CVE-2019-13315, CVE-2019-13316, CVE-2019-13317,
    CVE-2019-13320)
  
  - An infinite loop condition exists when calling the
    clone function due to confused relationships between
    the child and parent object caused by append error.
    This can cause the application to crash. (CVE-2019-14207)

  - A NULL pointer dereference flaw exists when parsing
    certain Epub files. This occurs because a null string
    is written to FXSYS_wcslen which does not support null
    strings. This can cause the application to crash.

  - A use-after-free remote code execution vulnerability
    exists due to the use of Field objects or control after
    they have been deleted or released which can cause the
    application to crash. (CVE-2019-13319)
     
  - An information disclosure vulnerability exists when
    calling util.printf JavaScript as the actual memory
    address of any variable available to the JavaScript can
    be extracted. (CVE-2019-13318)

  - An out-of-bounds write vulnerability exists when users
    use the application in Internet Explorer because the
    input argument exceed the array length. This can cause
    the application to crash.

Note that GizaNE has not tested for this issue but has instead relied
only on the application's self-reported version number.");

  script_set_attribute(attribute:"see_also", value:"https://www.foxitsoftware.com/support/security-bulletins.php");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8295/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8491/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8544/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8656/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8669/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8757/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8759/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8801/");
  script_set_attribute(attribute:"see_also", value:"https://www.zerodayinitiative.com/advisories/ZDI-CAN-8814/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Foxit PhantomPDF version 8.3.11 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-6774");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/07/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/07/26");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantom");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:foxitsoftware:phantompdf");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("foxit_phantom_installed.nasl");
  script_require_keys("installed_sw/FoxitPhantomPDF");

  exit(0);
}

include('vcf.inc');

app = 'FoxitPhantomPDF';

app_info = vcf::get_app_info(app:app, win_local:TRUE);

constraints = [
  { 'min_version' : '8.0', 'max_version' : '8.3.10.42705', 'fixed_version' : '8.3.11' }
];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
