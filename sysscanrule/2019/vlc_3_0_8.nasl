#
# (C) WebRAY Network Security, Inc.
#
include('compat.inc');

if (description)
{
  script_id(128080);
  script_version("1.1");
  script_cvs_date("Date: 2019/08/23  4:58:12");

  script_cve_id(
    "CVE-2019-13602",
    "CVE-2019-13962",
    "CVE-2019-14437",
    "CVE-2019-14438",
    "CVE-2019-14498",
    "CVE-2019-14533",
    "CVE-2019-14534",
    "CVE-2019-14535",
    "CVE-2019-14776",
    "CVE-2019-14777",
    "CVE-2019-14778",
    "CVE-2019-14970"
  );
  script_bugtraq_id(109158, 109306);
  script_xref(name:"IAVB", value:"2019-B-0074");

  script_name(english:"VLC < 3.0.8 Multiple Vulnerabilities");
  script_summary(english:"Checks version of VLC");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a media player that is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of VLC media player installed on the remote Windows host is prior to 3.0.8. It is, therefore, affected by 
multiple vulnerabilities:

  - An integer underflow condition exists in the modules/demux/mp4/mp4.c component of VLC Player. An unauthenticated, 
    remote attacker can exploit this, by supplying a crafted mp4 file, to cause a denial of service condition or the 
    execution of arbitrary code (CVE-2019-13602).

  - A heap-based buffer overflow condition exists in the modules/codec/avcodec/video.c component of VLC Player due to 
    improper sanitization of the width and height values. A remote attacker can exploit this, by supplying a specially
    crafted video file, to cause a denial of service condition or the execution of arbitrary code (CVE-2019-13962).

  - A NULL pointer de-reference flaw exists in the ASF Demuxer component of VLC Player. An unauthenticated, remote 
    attacker can exploit this, by supplying crafted input, to cause a denial of service condition when the application 
    attempts to read or write memory with a NULL pointer (CVE-2019-14534).
");
  script_set_attribute(attribute:"see_also", value:"http://www.videolan.org/developers/vlc-branch/NEWS");
  script_set_attribute(attribute:"solution", value:"Upgrade to VLC version 3.0.8 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"cvss_score_source", value:"CVE-2019-13962");

  script_set_attribute(attribute:"vuln_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2019/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2019/08/23");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2019 and is owned by WebRAY, Inc. or an Affiliate thereof.");

  script_dependencies("vlc_installed.nasl");
  script_require_keys("SMB/VLC/Version");

  exit(0);
}

include('vcf.inc');

app_info = vcf::get_app_info(app:'VLC media player', win_local:TRUE);

constraints = [{'fixed_version':'3.0.8'}];

vcf::check_version_and_report(app_info:app_info, constraints:constraints, severity:SECURITY_HOLE);
