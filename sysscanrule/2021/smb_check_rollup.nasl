#
# 
#

include("compat.inc");

if (description)
{
  script_id(93962);
  script_version("1.151");
  script_set_attribute(attribute:"plugin_modification_date", value:"2021/07/13");

  script_name(english:"Microsoft Security Rollup Enumeration");
  script_summary(english:"Enumerates installed Microsoft security rollups.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin enumerates installed Microsoft security rollups.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the Microsoft security rollups installed
on the remote Windows host.");
  # https://blogs.technet.microsoft.com/windowsitpro/2016/08/15/further-simplifying-servicing-model-for-windows-7-and-windows-8-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b23205aa");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2021 and is owned by Tenable, Inc. or an Affiliate thereof.");

  script_dependencies("smb_hotfixes.nasl", "wmi_enum_qfes.nbin", "smb_enum_qfes.nasl", "dism_enum_packages.nbin", "wevtutil_removed_packages.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_timeout(30*60);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("debug.inc");

# in order from latest to earliest
rollup_dates = make_list(
  "07_2021",
  "06_2021_07_01",
  "06_2021",
  "05_2021",
  "04_2021",
  "03_2021",
  "02_2021_2",
  "02_2021",
  "01_2021",
  "12_2020",
  "11_2020",
  "10_2020",
  "09_2020",
  "08_2020_02",
  "08_2020",
  "07_2020",
  "06_2020",
  "05_2020",
  "04_2020",
  "03_2020_2",
  "03_2020",
  "02_2020",
  "01_2020",
  "12_2019",
  "11_2019",
  "10_2019",
  "09_2019",
  "08_2019",
  "07_2019",
  "06_2019",
  "05_2019",
  "04_2019",
  "03_2019",
  "02_2019",
  "01_2019",
  "13_2018",
  "12_2018",
  "11_2018",
  "10_2018",
  "09_2018",
  "08_2018",
  "07_2018",
  "06_2018",
  "05_2018",
  "04_2018",
  "03_2018_3",
  "03_2018_2",
  "03_2018_1",
  "02_2018",
  "01_2018_2",
  "01_2018",
  "12_2017",
  "11_2017",
  "10_2017",
  "09_2017",
  "08_2017",
  "07_2017",
  "06_2017",
  "05_2017",
  "04_2017",
  "03_2017",
  "01_2017",
  "12_2016",
  "11_2016",
  "10_2016"
);

rollup_patches = {
  # rollup    #   arguments to pass to hotfix_check_fversion, "dir" argument also passed                      # kb list
  # date      #   if present

  # October 2016
  # 7 / 2008 R2
  "10_2016" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "ntoskrnl.exe", "version": "6.1.7601.23564"}, {"cum": 3185330, "sec": 3192391, "pre": 3192403}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "Gdiplus.dll", "version": "6.2.9200.21976"}, {"cum": 3185332, "sec": 3192393, "pre": 3192406}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "Gdiplus.dll", "version": "6.3.9600.18468"}, {"cum": 3185331, "sec": 3192392, "pre": 3192404}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "Gdiplus.dll", "version": "10.0.10240.17146"}, {"cum": 3192440}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "Gdiplus.dll", "version": "10.0.10586.633"}, {"cum": 3192441}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "Gdiplus.dll", "version": "10.0.14393.321"}, {"cum": 3194798}]],

  # November 2016
  # 7 / 2008 R2
  "11_2016" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "ntoskrnl.exe", "version": "6.1.7601.23569"}, {"cum": 3197868, "sec": 3197867, "pre": 3197869}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "ntoskrnl.exe", "version": "6.2.9200.22005"}, {"cum": 3197877, "sec": 3197876, "pre": 3197878}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18524"}, {"cum": 3197874, "sec": 3197873, "pre": 3197875}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10240.17184"}, {"cum": 3198585}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10586.672"}, {"cum": 3198586}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.447"}, {"cum": 3200970}]],

  # December 2016
  # 7 / 2008 R2
  "12_2016" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23601"}, {"cum": 3207752, "sec": 3205394}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "bcrypt.dll", "version": "6.2.9200.22037"}, {"cum": 3205409, "sec": 3205408}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18533"}, {"cum": 3205401, "sec": 3205400}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10240.17202"}, {"cum": 3205383}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "user32.dll", "version": "10.0.10586.713"}, {"cum": 3205386}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.576"}, {"cum": 3206632}]],

  # January 2017
  # 7 / 2008 R2
  "01_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23642"}, {"cum": 3212646, "sec": 3212642}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10240.17236"}, {"cum": 3210720}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10586.753"}, {"cum": 3210721}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.693"}, {"cum": 3213986}]],

  # February 2017 - Canceled :)

  # March 2017
  # 7 / 2008 R2
  "03_2017" : [[{"os":'6.1', "sp":1, "path":"\System32\drivers", "file": "srv.sys", "version": "6.1.7601.23689"}, {"cum": 4012215, "sec": 4012212, "pre": 4012218}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.2.9200.22097"}, {"cum": 4012217, "sec": 4012214, "pre":4012220}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18603"}, {"cum": 4012216, "sec": 4012213, "pre": 4012219}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10240.17319"}, {"cum": 4012606}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10586.839"}, {"cum": 4013198}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.953"}, {"cum": 4013429}]],

  # April 2017
  # 7 / 2008 R2#
  "04_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23714"}, {"cum": 4015549, "sec": 4015546, "pre": 4015552}],
  # 2012#
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.2.9200.22109"}, {"cum": 4015551, "sec": 4015548, "pre": 4015554}],
  # 8.1 / 2012 R2#
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18623"}, {"cum": 4015550, "sec": 4015547, "pre": 4015553}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10240.17354"}, {"cum": 4015221}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10586.873"}, {"cum": 4015219}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.1066"}, {"cum": 4015217}],
  # 10 1703 (AKA 15063)
               [{"os":'10', "sp":0, "os_build":"15063", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.15063.138"}, {"cum": 4015583}]],

  # May 2017
  # 7 / 2008 R2
  "05_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23796"}, {"cum": 4019264, "sec": 4019263, "pre": 4019265}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "gdi32.dll", "version": "6.2.9200.22139"}, {"cum": 4019216, "sec": 4019214, "pre": 4019218}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18683"}, {"cum": 4019215, "sec": 4019213, "pre":4019217}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10240.17394"}, {"cum": 4019474}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10586.916"}, {"cum": 4019473}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.1198"}, {"cum": 4019472}],
  # 10 1703 (AKA 15063)
               [{"os":'10', "sp":0, "os_build":"15063", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.15063.296"}, {"cum": 4016871}]],

  # June 2017
  # 7 / 2008 R2
  "06_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23816"}, {"cum": 4022719, "sec": 4022722, "pre": 4022168}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "gdi32.dll", "version": "6.2.9200.22168"}, {"cum": 4022724, "sec": 4022718, "pre": 4022721}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18698"}, {"cum": 4022726, "sec": 4022717, "pre": 4022720}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10240.17443"}, {"cum": 4022727}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10586.962"}, {"cum": 4022714}],
  # 10 1607 (AKA 14393) / Server 2016
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.1358"}, {"cum": 4022715}],
  # 10 1703 (AKA 15063)
               [{"os":'10', "sp":0, "os_build":"15063", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.15063.413"}, {"cum": 4022725}]],

  # July 2017
  # 7 / 2008 R2
  "07_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23841"}, {"cum": 4025341, "sec": 4025337, "pre": 4025340}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.2.9200.22210"}, {"cum": 4025331, "sec": 4025343, "pre": 4025332}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18737"}, {"cum": 4025336, "sec": 4025333, "pre": 4025335}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10240.17488"}, {"cum": 4025338}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10586.1007"}, {"cum": 4025344}],
  # 10 1607 (AKA 14393) / Server 2016
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "shell32.dll", "version": "10.0.14393.1478"}, {"cum": 4025339}],
  # 10 1703 (AKA 15063)
               [{"os":'10', "sp":0, "os_build":"15063", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.15063.483"}, {"cum": 4025342}]],

  # August 2017
  # 7 / 2008 R2
  "08_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23864"}, {"cum": 4034664, "sec": 4034679, "pre": 4034670}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.2.9200.22229"}, {"cum": 4034665, "sec": 4034666, "pre": 4034659}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18759"}, {"cum": 4034681, "sec": 4034672, "pre": 4034663}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10240.17533"}, {"cum": 4034668}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10586.1045"}, {"cum": 4034660}],
  # 10 1607 (AKA 14393) / Server 2016
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "shell32.dll", "version": "10.0.14393.1593"}, {"cum": 4034658, "oob":[4034661,4039396]}],
  # 10 1703 (AKA 15063)
               [{"os":'10', "sp":0, "os_build":"15063", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.15063.540"}, {"cum": 4034674}]],


    # September 2017 
  # 7 / 2008 R2
  "09_2017" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.23889"}, {"cum":4038777, "sec":4038779, "pre":4038803}],
  # 2012
               [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22254"}, {"cum":4038799, "sec":4038786, "pre":4038797}],
  # 8.1 / 2012 R2
               [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.18790"}, {"cum":4038792, "sec":4038793, "pre":4038774}],
  # 10
               [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.17609"}, {"cum":4038781}],
  # 10 1511 (AKA 10586)
               [{"os":"10", "sp":0, "os_build":"10586", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10586.1106"}, {"cum":4038783}],
  # 10 1607 (AKA 14393) / Server 2016
               [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.1715"}, {"cum":4038782, "oob":[4038801]}],
 # 10 1703 (AKA 15063)
               [{"os":'10', "sp":0, "os_build":"15063", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.15063.608"}, {"cum": 4038788, "oob":[4040724]}]],


  # October 2017
  # 7 / 2008 R2
  "10_2017" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"bcrypt.dll", "version":"6.1.7601.23915"}, {"cum":4041681, "sec":4041678, "pre": 4041686}],
  # 2012
               [{"os":"6.2", "sp":0, "path":"\system32", "file":"win32k.sys", "version":"6.2.9200.22280"}, {"cum":4041690, "sec":4041679, "pre": 4041692}],
  # 8.1 / 2012 R2
               [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.18821"}, {"cum":4041693, "sec":4041687, "pre": 4041685}],
  # 10
               [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"shell32.dll", "version":"10.0.10240.1684"}, {"cum":4042895}],
  # 10 1511 (AKA 10586)
               [{"os":"10", "sp":0, "os_build":"10586", "path":"\system32", "file":"shell32.dll", "version":"10.0.10586.1176"}, {"cum":4041689, "oob":[4052232]}],
  # 10 1607 (AKA 14393) / Server 2016
               [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"shell32.dll", "version":"10.0.14393.1770"}, {"cum":4041691, "oob":[4041688,4052231]}],
  # 10 1703 (AKA 15063)
               [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"shell32.dll", "version":"10.0.15063.674"}, {"cum":4041676, "oob":[4049370]}]],

# November 2017
  # 7 / 2008 R2
  "11_2017" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"win32k.sys", "version":"6.1.7601.23932"}, {"cum":4048957, "sec":4048960, "pre":4051034}],
  # 2012
               [{"os":"6.2", "sp":0, "path":"\system32", "file":"win32k.sys", "version":"6.2.9200.22298"}, {"cum":4048959, "sec":4048962, "pre":4050945}],
  # 8.1 / 2012 R2
               [{"os":"6.3", "sp":0, "path":"\system32", "file":"win32k.sys", "version":"6.3.9600.18838"}, {"cum":4048958, "sec":4048961, "pre":4050946}],
  # 10 LTSB (AKA 10240)
               [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"win32kfull.sys", "version":"10.0.10240.17673"}, {"cum":4048956}],
  # 10 1511 (AKA 10586)
               # PT
               [{"os":"10", "sp":0, "os_build":"10586", "path":"\system32", "file":"win32kfull.sys", "version":"10.0.10586.1232"}, {"cum":4048952}],
  # 10 1607 (AKA 14393) / Server 2016
               # PT
               [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"win32kfull.sys", "version":"10.0.14393.1884"}, {"cum":4048953, "oob":[4051033]}],
  # 10 1703 (AKA 15063)
               # PT
               [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"shell32.dll", "version":"10.0.15063.726"}, {"cum":4048954, "oob":[4055254]}],
  # 10 1709
               # PT
               [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.64"}, {"cum":4048955, "oob":[4051963]}]],


  # December 2017
  # 7 / 2008 R2
  "12_2017" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"tzres.dll", "version":"6.1.7601.23949"}, {"cum":4054518, "sec":4054521}],
  # 2012
               [{"os":"6.2", "sp":0, "path":"\system32", "file":"iprtrmgr.dll", "version":"6.2.9200.22313"}, {"cum":4054520, "sec":4054523}],
  # 8.1 / 2012 R2
             [{"os":"6.3", "sp":0, "path":"\system32", "file":"iprtrmgr.dll", "version":"6.3.9600.18858"}, {"cum":4054519, "sec":4054522}],
  # 10 LTSB (AKA 10240)
             [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"win32kfull.sys", "version":"10.0.10240.17709"}, {"cum":4053581}],
  # 10 1511 (AKA 10586)
               [{"os":"10", "sp":0, "os_build":"10586", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10586.1295"}, {"cum":4053578}],
  # 10 1607 (AKA 14393) / Server 2016
               [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.1944"}, {"cum":4053579}],
  # 10 1703 (AKA 15063)
               [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.786"}, {"cum":4053580}],
  # 10 1709
               [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"bcrypt.dll", "version":"10.0.16299.125"}, {"cum":4054517}]],

  # January 2018
  # 7 / 2008 R2
  "01_2018" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24000"}, {"cum":4056894, "sec":4056897, "pre":4057400}],
  # 2012
               [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22331"}, {"cum":4056896, "sec":4056899, "pre":4057402}],
  # 8.1 / 2012 R2
             [{"os":"6.3", "sp":0, "path":"\system32", "file":"shell32.dll", "version":"6.3.9600.18895"}, {"cum":4056895, "sec":4056898, "pre":4057401}],
  # 10 LTSB (AKA 10240)
             [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.17738"}, {"cum":4056893, "oob":[4075199,4077735]}],
  # 10 1511 (AKA 10586)
               [{"os":"10", "sp":0, "os_build":"10586", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10586.1356"}, {"cum":4056888, "oob":[4075200]}],
  # 10 1607 (AKA 14393) / Server 2016
               [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2007"}, {"cum":4056890,"oob":[4057142]}],
  # 10 1703 (AKA 15063)
               [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.850"}, {"cum":4056891, "oob":[4057144]}],
  # 10 1709
               [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.192"}, {"cum":4056892, "oob":[4058258]}]],

  # 10 1709 OOB
  "01_2018_2" : [[{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.201"}, {"cum":4073291}]],

  # February 2018
  # 7 / 2008 R2
  "02_2018" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"ntdll.dll", "version":"6.1.7601.24024"}, {"cum":4074598, "sec":4074587, "pre":4075211}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"win32k.sys", "version":"6.2.9200.22346"}, {"cum":4074593, "sec":4074589,"pre":4075213}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"win32k.sys", "version":"6.3.9600.18907"}, {"cum":4074594, "sec":4074597,"pre":4075212}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.17770"}, {"cum":4074596}],
  # 10 1511 (AKA 10586)
              [{"os":"10", "sp":0, "os_build":"10586", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10586.1417"}, {"cum":4074591}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2068"}, {"cum":4074590, "oob":[4077525]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.909"}, {"cum":4074592, "oob":[4077528,4092077]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.248"}, {"cum":4074588}]],

  # March oob
  "03_2018_1" : [[{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.251"}, {"cum":4090913}]],

  # March 2018
  # 7 / 2008 R2
  "03_2018_2" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"bcrypt.dll", "version":"6.1.7601.24059"}, {"cum":4088875, "sec":4088878, "pre":4088881}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"win32k.sys", "version":"6.2.9200.22376"}, {"cum":4088877, "sec":4088880, "pre":4088883}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.18946"}, {"cum":4088876, "sec":4088879, "pre":4088882}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"win32kfull.sys", "version":"10.0.10240.17797"}, {"cum":4088786}],
  # 10 1511 (AKA 10586)
              [{"os":"10", "sp":0, "os_build":"10586", "path":"\system32", "file":"win32kfull.sys", "version":"10.0.10586.1478"}, {"cum":4088779}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"win32kfull.sys", "version":"10.0.14393.2125"}, {"cum":4088787, "oob":[4088889]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"win32kfull.sys", "version":"10.0.15063.966"}, {"cum":4088782, "oob":[4088891]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"win32kfull.sys", "version":"10.0.16299.309"}, {"cum":4088776, "oob":[4089848]}]],

  # March oob 2 (30 MAR 2018)
  "03_2018_3" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24093"}, {"cum":4100480}]],

  # April 2018
  # 7 / 2008 R2
  "04_2018" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"advapi32.dll", "version":"6.1.7601.24094"}, {"cum":4093118, "sec":4093108, "pre":4093113}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22402"}, {"cum":4093123, "sec":4093122, "pre":4093121}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.18969"}, {"cum":4093114, "sec":4093115, "pre":4093116}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"pcasvc.dll", "version":"10.0.10240.17831"}, {"cum":4093111}],
  # 10 1511 (AKA 10586)
              [{"os":"10", "sp":0, "os_build":"10586", "path":"\system32", "file":"pcadm.dll", "version":"10.0.10586.1540"}, {"cum":4093109}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2189"}, {"cum":4093119, "oob":[4093120]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"coremessaging.dll", "version":"10.0.15063.997"}, {"cum":4093107, "oob":[4093117]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.371"}, {"cum":4093112, "oob":[4093105]}]],

  # May 2018
  # 7 / 2008 R2
  "05_2018" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"advapi32.dll", "version":"6.1.7601.24117"}, {"cum":4103718, "sec":4103712, "pre":4103713}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22432"}, {"cum":4103730, "sec":4103726, "pre":4103719}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19000"}, {"cum":4103725, "sec":4103715, "pre":4103724}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"pcadm.dll", "version":"10.0.10240.17861"}, {"cum":4103716}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2248"}, {"cum":4103723, "oob":[4103720]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"coremessaging.dll", "version":"10.0.15063.1088"}, {"cum":4103731, "oob":[4103722]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"winload.exe", "version":"10.0.16299.431"}, {"cum":4103727, "oob":[4103714]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.48"}, {"cum":4103721, "oob":[4100403]}]],
  # June 2018
  # 7 / 2008 R2
  "06_2018" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"advapi32.dll", "version":"6.1.7601.24150"}, {"cum":4284826, "sec":4284867, "pre":4284842}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22462"}, {"cum":4284855, "sec":4284846, "pre":4284852}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19035"}, {"cum":4284815, "sec":4284878, "pre":4284863}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"pcadm.dll", "version":"10.0.10240.17889"}, {"cum":4284860}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2311"}, {"cum":4284880, "oob":[4284833]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"coremessaging.dll", "version":"10.0.15063.1155"}, {"cum":4284874, "oob":[4284830]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"winload.exe", "version":"10.0.16299.492"}, {"cum":4284819, "oob":[4284822]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.112"}, {"cum":4284835, "oob":[4284848]}]],
  # July 2018
  # 7 / 2008 R2
  "07_2018" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"advapi32.dll", "version":"6.1.7601.24168"}, {"cum":4338818, "sec":4338823, "pre":4338821}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22490"}, {"cum":4338830, "sec":4338820, "pre":4338816}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19067"}, {"cum":4338815, "sec":4338824, "pre":4338831}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"pcadm.dll", "version":"10.0.10240.17914"}, {"cum":4338829, "oob":[4345455]}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2363"}, {"cum":4338814, "oob":[4345418, 4338822, 4346877]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"coremessaging.dll", "version":"10.0.15063.1182"}, {"cum":4338826, "oob":[4345419, 4338827]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"winload.exe", "version":"10.0.16299.522"}, {"cum":4338825, "oob":[4345420, 4338817, 4346644]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.165"}, {"cum":4338819, "oob":[4345421, 4340917]}]],

  # Auguest 2018
  # 7 / 2008 R2
  "08_2018" : [[{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24214"}, {"cum":4343900, "sec":4343899, "pre":4343894}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22522"}, {"cum":4343901, "sec":4343896, "pre":4343895}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19101"}, {"cum":4343898, "sec":4343888, "pre":4343891}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.17946"}, {"cum":4343892}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2430"}, {"cum":4343887, "oob":[4343884]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1266"}, {"cum":4343885, "oob":[4343889]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.611"}, {"cum":4343897, "oob":[4343893]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.228"}, {"cum":4343909, "oob":[4346783]}]],

  # September 2018
  # 2008
  "09_2018" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6002.24463"}, {"cum":4458010, "sec":4457984, "pre":4458315}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24231"}, {"cum":4457144, "sec":4457145, "pre":4457139}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22547"}, {"cum":4457135, "sec":4457140, "pre":4457134}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19125"}, {"cum":4457129, "sec":4457143, "pre":4457133}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.17976"}, {"cum":4457132}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2485"}, {"cum":4457131, "oob":[4457127]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1324"}, {"cum":4457138, "oob":[4457141]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.665"}, {"cum":4457142, "oob":[4464217,4457136]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.285"}, {"cum":4457128, "oob":[4464218,4458469]}]],

 # October 2018
  # 2008
  "10_2018" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6002.24491"}, {"cum":4463097, "sec":4463104, "pre":4463105}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24260"}, {"cum":4462923, "sec":4462915, "pre":4462927}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22570"}, {"cum":4462929, "sec":4462931, "pre":4462925}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19153"}, {"cum":4462926, "sec":4462941, "pre":4462921}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18005"}, {"cum":4462922}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2551"}, {"cum":4462917, "oob":[4462928]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1387"}, {"cum":4462937, "oob":[4462939]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.726"}, {"cum":4462918, "oob":[4462932]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.345"}, {"cum":4462919, "oob":[4462933]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.55"}, {"cum":4464330, "oob":[4464455]}]],

  # November 2018
  # 2008
  "11_2018" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6002.24521"}, {"cum":4467706, "sec":4467700, "pre":4467687}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24291"}, {"cum":4467107, "sec":4467106, "pre":4467108}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22601"}, {"cum":4467701, "sec":4467678, "pre":4467683}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19179"}, {"cum":4467697, "sec":4467703, "pre":4467695}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18036"}, {"cum":4467680}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2608"}, {"cum":4467691, "oob":[4467684,4478877]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1446"}, {"cum":4467696, "oob":[4467699]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.785"}, {"cum":4467686, "oob":[4467681]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.407"}, {"cum":4467702, "oob":[4467682]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.134"}, {"cum":4467708, "oob":[4469342]}]],

  # December 2018
  # 2008
  "12_2018" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6002.24535"}, {"cum":4471325, "sec":4471319}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24308"}, {"cum":4471318, "sec":4471328}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22618"}, {"cum":4471330, "sec":4471326}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19202"}, {"cum":4471320, "sec":4471322}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18063"}, {"cum":4471323}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2665"}, {"cum":4471321}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1506"}, {"cum":4471327}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.846"}, {"cum":4471329}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.471"}, {"cum":4471324}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.194"}, {"cum":4471332}]],

  # December 2018 OOB
  "13_2018" : [
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"pcadm.dll", "version":"10.0.10240.18064"}, {"cum":4483228}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"pcadm.dll", "version":"10.0.14393.2670"}, {"cum":4483229}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"pcadm.dll", "version":"10.0.15063.1508"}, {"cum":4483230}],
  # 10 1709 (AKA 16299)
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"pcadm.dll", "version":"10.0.16299.847"}, {"cum":4483232}],
  # 10 1803 (AKA 17134)
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"bcastdvruserservice.dll", "version":"10.0.17134.472"}, {"cum":4483234}],
  # 10 1809 (AKA 17763)
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"bcastdvruserservice.dll", "version":"10.0.17763.195"}, {"cum":4483235}]
  ],

  # January 2019
  "01_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6002.24555"}, {"cum":4480968, "sec":4480957, "pre":4480974}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24335"}, {"cum":4480970, "sec":4480960, "pre":4480955}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22638"}, {"cum":4480975, "sec":4480972, "pre":4480971}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19228"}, {"cum":4480963, "sec":4480964, "pre":4480969}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18094"}, {"cum":4480962}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2724"}, {"cum":4480961, "oob":[4480977]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1563"}, {"cum":4480973, "oob":[4480959]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.904"}, {"cum":4480978, "oob":[4480967]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.523"}, {"cum":4480966, "oob":[4480976]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.253"}, {"cum":4480116, "oob":[4476976]}]],

  # February 2019 
  "02_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6002.24556"}, {"cum":4487023, "sec":4487019, "pre":4487022}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24354"}, {"cum":4486563, "sec":4486564, "pre":4486565}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22672"}, {"cum":4487025, "sec":4486993, "pre":4487024}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19263"}, {"cum":4487000, "sec":4487028, "pre":4487016}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18132"}, {"cum":4487018}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2791"}, {"cum":4487026, "oob":[4487006]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1631"}, {"cum":4487020, "oob":[4487011]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.967"}, {"cum":4486996, "oob":[4487021]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.590"}, {"cum":4487017, "oob":[4487029]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.316"}, {"cum":4487044, "oob":[4482887]}]],

  # March 2019 
  "03_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6002.24565"}, {"cum":4489880, "sec":4489876, "pre":4489887}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24387"}, {"cum":4489878, "sec":4489885, "pre":4489892}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22702"}, {"cum":4489891, "sec":4489884, "pre":4489920}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19304"}, {"cum":4489881, "sec":4489883, "pre":4489893}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18158"}, {"cum":4489872}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2848"}, {"cum":4489882, "oob":[4489889]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1689"}, {"cum":4489871, "oob":[4489888]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1029"}, {"cum":4489886, "oob":[4489890]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.648"}, {"cum":4489868, "oob":[4489894]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.379"}, {"cum":4489899}]],

  # April 2019 
  "04_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20489"}, {"cum":4493471, "sec":4493458, "pre":4493460}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24408"}, {"cum":4493472, "sec":4493448, "pre":4493453}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22720"}, {"cum":4493451, "sec":4493450, "pre":4493462}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19321"}, {"cum":4493446, "sec":4493467, "pre":4493443}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18186"}, {"cum":4493475, "oob":[4498375]}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2906"}, {"cum":4493470, "oob":[4493473]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1746"}, {"cum":4493474, "oob":[4493436]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1087"}, {"cum":4493441, "oob":[4493440]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.706"}, {"cum":4493464, "oob":[4493437]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.437"}, {"cum":4493509, "oob":[4501835,4495667]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.53"}, {"cum":4495666}]],

   # May 2019 
  "05_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20512"}, {"cum":4499149, "sec":4499180, "pre":4499184}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24441"}, {"cum":4499164, "sec":4499175, "pre":4499178}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22753"}, {"cum":4499171, "sec":4499158, "pre":4499145}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19358"}, {"cum":4499151, "sec":4499165, "pre":4499182}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18215"}, {"cum":4499154, "oob":[4505051]}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.2969"}, {"cum":4494440, "oob":[4505052, 4499177]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1805"}, {"cum":4499181, "oob":[4505055, 4499162]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1146"}, {"cum":4499179, "oob":[4505062, 4499147]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.765"}, {"cum":4499167, "oob":[4505064, 4499183]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.503"}, {"cum":4494441, "oob":[4505056, 4497934]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.113"}, {"cum":4497936, "oob":[4497935]}]],

  # June 2019 
  "06_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20540"}, {"cum":4503273, "sec":4503287, "pre":4503271}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24475"}, {"cum":4503292, "sec":4503269, "pre":4503277}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22775"}, {"cum":4503285, "sec":4503263, "pre":4503295}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19376"}, {"cum":4503276, "sec":4503290, "pre":4503283}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18244"}, {"cum":4503291}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3024"}, {"cum":4503267, "oob":[4503294, 4509475]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1868"}, {"cum":4503279, "oob":[4503289, 4509476]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1217"}, {"cum":4503284, "oob":[4503281, 4509477]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.799"}, {"cum":4503286, "oob":[4503288, 4509478]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.557"}, {"cum":4503327, "oob":[4501371, 4509479]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.175"}, {"cum":4503293, "oob":[4501375]}]],

  # July 2019  
  "07_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20562"}, {"cum":4507452, "sec":4507461, "pre":4507451}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24499"}, {"cum":4507449, "sec":4507456, "pre":4507437}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22794"}, {"cum":4507462, "sec":4507464, "pre":4507447}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19395"}, {"cum":4507448, "sec":4507457, "pre":4507463}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18275"}, {"cum":4507458}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3085"}, {"cum":4507460, "oob":[4507459]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1928"}, {"cum":4507450, "oob":[4507467]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1268"}, {"cum":4507455, "oob":[4507465]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.885"}, {"cum":4507435, "oob":[4507466]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.615"}, {"cum":4507469, "oob":[4505658]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.239"}, {"cum":4507453, "oob":[4505903]}]],

  # August 2019 
  "08_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20597"}, {"cum":4512476, "sec":4512491, "pre":4512499}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24511"}, {"cum":4512506, "sec":4512486, "pre":4512514}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22825"}, {"cum":4512518, "sec":4512482, "pre":4512512}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19426"}, {"cum":4512488, "sec":4512489, "pre":4512478, "oob":[4517298]}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18303"}, {"cum":4512497, "oob":[4517276]}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3143"}, {"cum":4512517, "oob":[4512495]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.1987"}, {"cum":4512507, "oob":[4512474]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1331"}, {"cum":4512516, "oob":[4512494]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.946"}, {"cum":4512501, "oob":[4512509]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.678"}, {"cum":4511553, "oob":[4512534]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.295"}, {"cum":4512508, "oob":[4512941]}]],

  # September 2019 
  "09_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20625"}, {"cum":4516026, "sec":4516051, "pre":4516030}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24520"}, {"cum":4516065, "sec":4516033, "pre":4516048}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22859"}, {"cum":4516055, "sec":4516062, "pre":4516069}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19464"}, {"cum":4516067, "sec":4516064, "pre":4516041}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18333"}, {"cum":4516070}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3204"}, {"cum":4516044}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.2045"}, {"cum":4516068}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1387"}, {"cum":4516066}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1006"}, {"cum":4516058}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.737"}, {"cum":4512578}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.356"}, {"cum":4515384}]],

  # October 2019
  "10_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20654"}, {"cum":4520002, "sec":4520009, "pre":4520015}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24524"}, {"cum":4519976, "sec":4520003, "pre":4519972}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22881"}, {"cum":4520007, "sec":4519985, "pre":4520013}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19478"}, {"cum":4520005, "sec":4519990, "pre":4520012}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18366"}, {"cum":4520011}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3269"}, {"cum":4519998, "oob":[4519979]}],
  # 10 1703 (AKA 15063)
              [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.2106"}, {"cum":4520010}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1448"}, {"cum":4520004, "oob":[4520006]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1067"}, {"cum":4520008, "oob":[4519978]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.802"}, {"cum":4519338, "oob":[4520062]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.418"}, {"cum":4517389, "oob":[4522355]}]],

  # November 2019
  "11_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20667"}, {"cum":4525234, "sec":4525239}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24535"}, {"cum":4525235, "sec":4525233}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22904"}, {"cum":4525246, "sec":4525253}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19538"}, {"cum":4525243, "sec":4525250}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18394"}, {"cum":4525232}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3321"}, {"cum":4525236}],
  # 10 1703 (AKA 15063)
  #            [{"os":"10", "sp":0, "os_build":"15063", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.15063.2106"}, {"cum":4520010}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1504"}, {"cum":4525241}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1130"}, {"cum":4525237}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.864"}, {"cum":4523205}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.476"}, {"cum":4524570}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.476"}, {"cum":4524570}]],

  # December 2019
  "12_2019" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20686"}, {"cum":4530695, "sec":4530719}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24540"}, {"cum":4530734, "sec":4530692}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22922"}, {"cum":4530691, "sec":4530698}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"gdi32.dll", "version":"6.3.9600.19574"}, {"cum":4530702, "sec":4530730}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18427"}, {"cum":4530681}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3383"}, {"cum":4530689}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1565"}, {"cum":4530714}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1184"}, {"cum":4530717}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.914"}, {"cum":4530715}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.535"}, {"cum":4530684}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.535"}, {"cum":4530684}]],

  # January 2020
  "01_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"crypt32.dll", "version":"6.0.6003.20705"}, {"cum":4534303, "sec":4534312}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"crypt32.dll", "version":"6.1.7601.24542"}, {"cum":4534310, "sec":4534314, "pre":4539601}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"cryptcatsvc.dll", "version":"6.2.9200.22948"}, {"cum":4534283, "sec":4534288, "pre":4534320}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"cryptcatsvc.dll", "version":"6.3.9600.19596"}, {"cum":4534297, "sec":4534309, "pre":4534324}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"crypt32.dll", "version":"10.0.10240.18452"}, {"cum":4534306, "oob":[4534306]}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"crypt32.dll", "version":"10.0.14393.3442"}, {"cum":4534271, "oob":[4534307]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"crypt32.dll", "version":"10.0.16299.1622"}, {"cum":4534276, "oob":[4534318]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"crypt32.dll", "version":"10.0.17134.1246"}, {"cum":4534293, "oob":[4534308]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"crypt32.dll", "version":"10.0.17763.973"}, {"cum":4534273, "oob":[4534321]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"crypt32.dll", "version":"10.0.18362.592"}, {"cum":4528760, "oob":[4532695]}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"crypt32.dll", "version":"10.0.18362.592"}, {"cum":4528760, "oob":[4532695]}]],

  # February 2020
  "02_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20731"}, {"cum":4537810, "sec":4537822}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24548"}, {"cum":4537820, "sec":4537813}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.22978"}, {"cum":4537814, "sec":4537794, "pre":4537807}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19629"}, {"cum":4537821, "sec":4537803, "pre":4537819}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18485"}, {"cum":4537776}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3503"}, {"cum":4537764, "oob":[4537806]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1685"}, {"cum":4537789, "oob":[4537816]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1304"}, {"cum":4537762, "oob":[4537795]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1039"}, {"cum":4532691, "oob":[4537818]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.657"}, {"cum":4532693, "oob":[4535996]}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.657"}, {"cum":4532693, "oob":[4535996]}]],

  # March 2020
  "03_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20749"}, {"cum":4541506, "sec":4541504}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24549"}, {"cum":4540688, "sec":4541500}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23009"}, {"cum":4541510, "sec":4540694, "pre":4541332}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19665"}, {"cum":4541509, "sec":4541505, "pre":541334}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18519"}, {"cum":4540693}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3564"}, {"cum":4540670}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1747"}, {"cum":4540681, "oob":[4541330,4554342]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1365"}, {"cum":4540689, "oob":[4541333,4554349]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1098"}, {"cum":4538461, "oob":[4541331,4554354]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.719"}, {"cum":4540673, "oob":[4551762,4541335,4554364]}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.719"}, {"cum":4540673, "oob":[4551762,4541335,4554364]}]],

  # SMB3 Oob for 1903/1909
  "03_2020_2" : [
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.720"}, {"cum":4551762}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.720"}, {"cum":4551762}]],

  # April 2020
  "04_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20812"}, {"cum":4550951, "sec":4550957}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24552"}, {"cum":4550964, "sec":4550965}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23022"}, {"cum":4550917, "sec":4550971, "pre":4550960}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19678"}, {"cum":4550961, "sec":4550970, "pre":4550958}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18545"}, {"cum":4550930}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3630"}, {"cum":4550929, "oob":[4550947]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1806"}, {"cum":4550927, "oob":[4550944]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1425"}, {"cum":4550922}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1158"}, {"cum":4549949, "oob":[4550969]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.778"}, {"cum":4549951, "oob":[4550945]}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.778"}, {"cum":4549951, "oob":[4550945]}]],

  # (May 2020)
  "05_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20825"}, {"cum":4556860, "sec":4556854}],
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24553"}, {"cum":4556836, "sec":4556843}],
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23037"}, {"cum":4556840, "sec":4556852}],
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19697"}, {"cum":4556846, "sec":4556853}],
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18575"}, {"cum":4556826}],
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3686"}, {"cum":4556813}],
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1868"}, {"cum":4556812}],
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1488"}, {"cum":4556807}],
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1217"}, {"cum":4551853}],
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.836"}, {"cum":4556799}],
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.836"}, {"cum":4556799}]],

    # June 2020
  "06_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20851"}, {"cum":4561670, "sec":4561645}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24556"}, {"cum":4561643, "sec":4561669}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23060"}, {"cum":4561612, "sec":4561674}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19724"}, {"cum":4561666, "sec":4561673}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18608"}, {"cum":4561649, "oob":[4567518]}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3750"}, {"cum":4561616, "oob":[4567517]}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1932"}, {"cum":4561602, "oob":[4567515]}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1550"}, {"cum":4561621, "oob":[4567514]}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1282"}, {"cum":4561608, "oob":[4567513]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.900"}, {"cum":4560960, "oob":[4567512]}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.900"}, {"cum":4560960, "oob":[4567512]}],
  # 10 2004
              [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.329"}, {"cum":4557957, "oob":[4567523]}]],

  # (July 2020)
  "07_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20881"}, {"cum":4565536, "sec":4565529}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24557"}, {"cum":4565524, "sec":4565539}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23084"}, {"cum":4565537, "sec":4565535}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19761"}, {"cum":4565541, "sec":4565540}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18638"}, {"cum":4565513}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3808"}, {"cum":4565511}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.1992"}, {"cum":4565508}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1610"}, {"cum":4565489}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1339"}, {"cum":4558998, "oob":[4559003]}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.959"}, {"cum":4565483, "oob":[4559004]}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.959"}, {"cum":4565483, "oob":[4559004]}],
  # 10 2004
              [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.388"}, {"cum":4565503}]],

  # Aug 2020
  "08_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20898"}, {"cum":4571730, "sec":4571746}],
  # 7 / 2008 R2
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24559"}, {"cum":4571729, "sec":4571719}],
  # 2012
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23118"}, {"cum":4571736, "sec":4571702}],
  # 8.1 / 2012 R2
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19780"}, {"cum":4571703, "sec":4571723}],
  # 10 LTSB (AKA 10240)
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18666"}, {"cum":4571692}],
  # 10 1607 (AKA 14393) / Server 2016
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3866"}, {"cum":4571694}],
  # 10 1709
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.2045"}, {"cum":4571741}],
  # 10 1803
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1667"}, {"cum":4571709}],
  # 10 1809
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1397"}, {"cum":4565349}],
  # 10 1903
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1016"}, {"cum":4565351}],
  # 10 1909
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1016"}, {"cum":4565351}],
  # 10 2004
              [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.450"}, {"cum":4566782}]],

  # Aug 2020 Win 8.1 oob
  "08_2020_02" : [[{"os":"6.3", "sp":0, "path":"\system32", "file":"mprapi.dll", "version":"6.3.9600.19786"}, {"sec":4578013}]],

  "09_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20933"}, {"cum":4577064, "sec":4577070}],
              [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24560"}, {"cum":4577051, "sec":4577053}],
              [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23149"}, {"cum":4577038, "sec":4577048}],
              [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19812"}, {"cum":4577066, "sec":4577071}],
              [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18696"}, {"cum":4577049}],
              [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3930"}, {"cum":4577015}],
              [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.2107"}, {"cum":4577041}],
              [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1726"}, {"cum":4577032}],
              [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1457"}, {"cum":4570333}],
              [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1082"}, {"cum":4574727}],
              [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1082"}, {"cum":4574727}],
              [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.508"}, {"cum":4571756}]],

  "10_2020" : [[{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20953"}, {"cum":4580378, "sec":4580385}],
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24561"}, {"cum":4580345, "sec":4580387}],
            [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23176"}, {"cum":4580382, "sec":4580353}],
            [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19846"}, {"cum":4580347, "sec":4580358}],
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18725"}, {"cum":4580327}],
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.3986"}, {"cum":4580346}],
            [{"os":"10", "sp":0, "os_build":"16299", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.16299.2166"}, {"cum":4580328}],
            [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1792"}, {"cum":4580330}],
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1518"}, {"cum":4577668}],
            [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1139"}, {"cum":4577671}],
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1139"}, {"cum":4577671}],
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.572"}, {"cum":4579311}]],
  
  "11_2020" : [
            # notes 
            # - deleted "16299" is EOL: https://docs.microsoft.com/en-us/lifecycle/announcements/revised-end-of-service-windows-10-1709
            # - added 19042: https://support.microsoft.com/en-us/help/4581839
            # - alternate file 'cng.sys' was used. This driver was updated to resolve CVE-2020-17087 in the Nov 2020 update:
            #     https://bugs.chromium.org/p/project-zero/issues/detail?id=2104
            [{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20981"}, {"cum":4586807, "sec":4586817}],
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24562"}, {"cum":4586827, "sec":4586805}],
            [{"os":"6.2", "sp":0, "path":"\system32\drivers", "file":"cng.sys", "version":"6.2.9200.23199"}, {"cum":4586834, "sec":4586808}],
            [{"os":"6.3", "sp":0, "path":"\system32\drivers", "file":"cng.sys", "version":"6.3.9600.19871"}, {"cum":4586845, "sec":4586823}],
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18756"}, {"cum":4586787}],
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.4046"}, {"cum":4586830}],
            [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.1845"}, {"cum":4586785}],
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1577"}, {"cum":4586793}],
            [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1198"}, {"cum":4586786}],
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1198"}, {"cum":4586786}],
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.630"}, {"cum":4586781}],
            [{"os":"10", "sp":0, "os_build":"19042", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.630"}, {"cum": 4586781}]],

  "12_2020" : [
            # https://docs.microsoft.com/en-us/windows/release-information/
            [{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.20996"}, {"cum":4592498, "sec":4592504}],       # ESU - server 2008
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24563"}, {"cum":4592471, "sec":4592503}],       # ESU - server 2008r2
            [{"os":"6.2", "sp":0, "path":"\system32", "file":"gdiplus.dll", "version":"6.2.9200.23209"}, {"cum":4592468, "sec":4592497}],       # 2012
            [{"os":"6.3", "sp":0, "path":"\system32", "file":"gdiplus.dll", "version":"6.3.9600.19889"}, {"cum":4592484, "sec":4592495}],       # 2012r2
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18781"}, {"cum":4592464}], # 10 LTS
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.4104"}, {"cum":4593226}],  # 1607 / Server 2016
            [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"gdiplus.dll", "version":"10.0.17134.1902"}, {"cum":4592446}],  # 1709 / 1803 
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"gdiplus.dll", "version":"10.0.17763.1637"}, {"cum":4592440}],  # 1809
            [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1256"}, {"cum":4592449}],  # 1903
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1256"}, {"cum":4592449}],  # 1909
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.685"}, {"cum":4592438}],   # 2004
            [{"os":"10", "sp":0, "os_build":"19042", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.685"}, {"cum": 4562830}]],  # 2h2
  "01_2021" : [
            # https://docs.microsoft.com/en-us/windows/release-information/
            [{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.21026"}, {"cum":4598288, "sec":4598287}],       # ESU - server 2008
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24564"}, {"cum":4598279, "sec":4598289}],       # ESU - server 2008r2
            [{"os":"6.2", "sp":0, "path":"\system32", "file":"puiobj.dll", "version":"6.2.9200.23255"}, {"cum":4598278, "sec":4598297}],       # 2012 / win8rt
            [{"os":"6.3", "sp":0, "path":"\system32", "file":"puiobj.dll", "version":"6.3.9600.19920"}, {"cum":4598285, "sec":4598275}],       # 2012r2
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18818"}, {"cum":4598231}], # 10 LTS
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"gdiplus.dll", "version":"10.0.14393.4168"}, {"cum":4598243}],  # 1607 / Server 2016
            [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"gdiplus.dll", "version":"10.0.17134.1967"}, {"cum":4598245}],  # 1709 / 1803 
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"gdiplus.dll", "version":"10.0.17763.1697"}, {"cum":4598230}],  # 1809
            [{"os":"10", "sp":0, "os_build":"18362", "path":"\system32", "file":"gdiplus.dll", "version":"10.0.18362.1316"}, {"cum":4598229}],  # 1903
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"gdiplus.dll", "version":"10.0.18362.1316"}, {"cum":4598229}],  # 1909
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"gdiplus.dll", "version":"10.0.19041.746"}, {"cum":4598242}],   # 2004
            [{"os":"10", "sp":0, "os_build":"19042", "path":"\system32", "file":"gdiplus.dll", "version":"10.0.19041.746"}, {"cum":4598242}]],  # 2h2
  "02_2021" : [
            [{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.21045"}, {"cum":4601360, "sec":4601366}], # ESU - server 2008
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24565"}, {"cum":4601347, "sec":4601363}],  # ESU - server 2008r2
            [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23272"}, {"cum":4601348, "sec":4601357}], # 2012 / win8rt
            [{"os":"6.3", "sp":0, "path":"\system32", "file":"fxsmon.dll", "version":"6.3.9600.19941"}, {"cum":4601384, "sec":4601349}], # 2012r2
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18841"}, {"cum":4601331}], # 10 LTS
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.4225"}, {"cum":4601318}],  # 1607 / Server 2016
            [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.2026"}, {"cum":4601354}],   # 1709 / 1803 
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1757"}, {"cum":4601345}],   # 1809
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1377"}, {"cum":4601315}],   # 1909
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.804"}, {"cum":4601319}],   # 2004
            [{"os":"10", "sp":0, "os_build":"19042", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.804"}, {"cum":4601319}]],    # 2h2
# OOB 
"02_2021_2" : [
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32\drivers", "file":"nwifi.sys", "version":"10.0.18362.1379"}, {"cum": 5001028}] # oob w/ security patch is represented by a cumulative update
  ], 
  # (March 2021)
"03_2021" : [
            [{"os":"6.0", "sp":2, "path":"\system32", "file":"appinfo.dll", "version":"6.0.6003.21066"}, {"cum":5000844, "sec":5000856}], # ESU - server 2008 
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24566"}, {"cum":5000841, "sec":5000851}],  # ESU - server 2008r2
            [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23297"}, {"cum":5000847, "sec":5000840}], # 2012 / win8rt
            [{"os":"6.3", "sp":0, "path":"\system32", "file":"win32k.sys", "version":"6.3.9600.19968"}, {"cum":5000848, "sec": 5000853}], # 2012r2
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18874"}, {"cum":5000807, "oob":5001631}],  # 10 LTS / RTM?
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.4283"}, {"cum":5000803, "oob": 5001633}],   # 1607 / Server 2016 
            [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.2087"}, {"cum":5000809, "oob": 5001634}],    # 1709 / 1803 
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1817"}, {"cum":5000822, "oob": 5001638}],   # 1809 
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1440"}, {"cum":5000808, "oob": 5001566}],   # 1909 
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.867"}, {"cum":5000802, "oob": 5001649}],          # 2004
            [{"os":"10", "sp":0, "os_build":"19042", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.867"}, {"cum":5000802, "oob": 5001649}]          # 2h2  
],
  # (April 2021)
"04_2021" : [
            [{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.21095"}, {"cum":5001389, "sec":5001332}], # ESU - server 2008 
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"inetcomm.dll", "version":"6.1.7601.24576"}, {"cum":5001335, "sec":5001392}],  # ESU - server 2008r2
            [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23327"}, {"cum":5001387, "sec":5001401}], # 2012 / win8rt
            [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.19994"},  {"cum":5001382, "sec": 5001393}], # 2012r2 
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18906"}, {"cum":5001340}],  # 10 LTS
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.4350"}, {"cum":5001347}],   # 1607 / Server 2016 
            [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.2145"}, {"cum":5001339}],    # 1709 / 1803 
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1879"}, {"cum":5001342}],   # 1809 
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1500"}, {"cum":5001337}],   # 1909 
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.928"}, {"cum":5001330}],          # 2004
            [{"os":"10", "sp":0, "os_build":"19042", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.928"}, {"cum":5001330}]          # 2h2  
],
# (May 2021)
"05_2021" : [
            [{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.21115"}, {"cum":5003210, "sec":5003225}],  # ESU - server 2008 
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.24596"}, {"cum":5003233, "sec":5003228}], # ESU - server 2008r2
            [{"os":"6.2", "sp":0, "path":"\system32", "file":"oleaut32.dll", "version":"6.2.9200.23346"}, {"cum":5003208, "sec":5003203}], # 2012 / win8rt
            [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.20012"}, {"cum":5003209, "sec":5003220}], # 2012r2 
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18932"}, {"cum":5003172}], # 10 LTS
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.4402"}, {"cum":5003197}],  # 1607 / Server 2016 
            [{"os":"10", "sp":0, "os_build":"17134", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17134.2208"}, {"cum":5003174}], # 1709 / 1803 - EOL 05/11/2021
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1935"}, {"cum":5003171}], # 1809 
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1556"}, {"cum":5003169}],# 1909 
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.985"}, {"cum":5003173 }],          # 2004
            [{"os":"10", "sp":0, "os_build":"19042", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.985"}, {"cum":5003173 }]          # 2h2  
],
# (June 2021) - https://docs.microsoft.com/en-us/windows/release-health/release-information
"06_2021" : [
            [{"os":"6.0", "sp":2, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.0.6003.21137"}, {"cum":5003661, "sec":5003695}], # ESU - server 2008
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.1.7601.25631"}, {"cum":5003667, "sec":5003694}], # ESU - server 2008r2
            [{"os":"6.2", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.2.9200.23376"}, {"cum":5003697, "sec":5003696}], # 2012 / win8rt
            [{"os":"6.3", "sp":0, "path":"\system32", "file":"ntoskrnl.exe", "version":"6.3.9600.20040"}, {"cum":5003671, "sec":5003681}], # 2012r2
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.10240.18967"}, {"cum":5003687}],# 10 LTS
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.14393.4467"}, {"cum":5003638}], # 1607 / Server 2016
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.17763.1999"}, {"cum":5003646}], # 1809
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.18362.1621"}, {"cum":5003635}], # 1909
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.1052"}, {"cum":5003637 }], # 2004
            [{"os":"10", "sp":0, "os_build":"19042", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.1052"}, {"cum":5003637 }], # 2h2
            [{"os":"10", "sp":0, "os_build":"19043", "path":"\system32", "file":"ntoskrnl.exe", "version":"10.0.19041.1052"}, {"cum":5003637 }]  # 21h1
],
# (July OOB 2021) - https://docs.microsoft.com/en-us/windows/release-health/release-information
"06_2021_07_01" : [ # we consider everything prior to formal PT to be considered part of the prior month, so we use june 
            [{"os":"6.0", "sp":2, "path":"\system32", "file":"spoolsv.exe", "version":"6.0.6003.21138"}, {"cum":5004955, "sec":5004959}], # server 2008
            [{"os":"6.1", "sp":1, "path":"\system32", "file":"spoolsv.exe", "version":"6.1.7601.25633"}, {"cum":5004953, "sec":5004951}], # server 2008r2
            [{"os":"6.2", "sp":0, "path":"\system32", "file":"spoolsv.exe", "version":"6.2.9200.23383"}, {"cum":5004956, "sec":5004960}], # 2012 / win8rt
            [{"os":"6.3", "sp":0, "path":"\system32", "file":"localspl.dll", "version":"6.3.9600.20046"}, {"cum":5004954, "sec":5004958}], # 2012r2 
            [{"os":"10", "sp":0, "os_build":"10240", "path":"\system32", "file":"spoolsv.exe", "version":"10.0.10240.18969"}, {"cum":5004950}],# 10 LTS 1507 
            [{"os":"10", "sp":0, "os_build":"14393", "path":"\system32", "file":"spoolsv.exe", "version":"10.0.14393.4470"}, {"cum":5004948}], # 1607 / Server 2016
            [{"os":"10", "sp":0, "os_build":"17763", "path":"\system32", "file":"spoolsv.exe", "version":"10.0.17763.2029"}, {"cum":5004947}], # 1809 / Server 2019 / hyper-v
            [{"os":"10", "sp":0, "os_build":"18363", "path":"\system32", "file":"spoolsv.exe", "version":"10.0.18362.1646"}, {"cum":5004946}], # 1909
            [{"os":"10", "sp":0, "os_build":"19041", "path":"\system32", "file":"spoolsv.exe", "version":"10.0.19041.1083"}, {"cum":5004945 }], # 2004
            [{"os":"10", "sp":0, "os_build":"19042", "path":"\system32", "file":"spoolsv.exe", "version":"10.0.19041.1083"}, {"cum":5004945 }], # 2h2
            [{"os":"10", "sp":0, "os_build":"19043", "path":"\system32", "file":"spoolsv.exe", "version":"10.0.19041.1083"}, {"cum":5004945 }]  # 21h1
],
# July 2021
"07_2021" : [
            [{"os": "6.0", "sp": "2", "path": "\system32", "file": "ntoskrnl.exe", "version": "6.0.6003.21163"}, {"cum": 5004305, "sec":5004299}],
            [{"os": "6.1", "sp": "1", "path": "\system32", "file": "ntoskrnl.exe", "version": "6.1.7601.25661"}, {"sec": 5004307, "cum":5004289}],
            [{"os": "6.2", "sp": "0", "path": "\system32", "file": "win32k.sys", "version": "6.2.9200.23409"},   {"sec": 5004302, "cum":5004294}],
            [{"os": "6.3", "sp": "0", "path": "\system32", "file": "win32k.sys", "version": "6.3.9600.20069"},   {"cum": 5004298, "sec":5004285}],
            [{"os": "10", "sp": "0", "os_build": "10240", "path": "\system32", "file": "ntoskrnl.exe", "version": "10.0.10240.19003"}, {"cum": 5004249}],
            [{"os": "10", "sp": "0", "os_build": "14393", "path": "\system32", "file": "ntoskrnl.exe", "version": "10.0.14393.4530"}, {"cum": 5004238}],
            [{"os": "10", "sp": "0", "os_build": "17763", "path": "\system32", "file": "ntoskrnl.exe", "version": "10.0.17763.2061"}, {"cum": 5004244}],
            [{"os": "10", "sp": "0", "os_build": "18363", "path": "\system32", "file": "ntoskrnl.exe", "version": "10.0.18362.1679"}, {"cum": 5004245}],
            [{"os": "10", "sp": "0", "os_build": "19041", "path": "\system32", "file": "ntoskrnl.exe", "version": "10.0.19041.1110"}, {"cum": 5004237}],
            [{"os": "10", "sp": "0", "os_build": "19042", "path": "\system32", "file": "ntoskrnl.exe", "version": "10.0.19041.1110"}, {"cum": 5004237}],
            [{"os": "10", "sp": "0", "os_build": "19043", "path": "\system32", "file": "ntoskrnl.exe", "version": "10.0.19041.1110"}, {"cum": 5004237}]
]
};

function is_patched(os, sp, arch, os_build, file, version, dir, path, min_version, bulletin, kb, product, channel, channel_product, channel_version, rollup)
{
  local_var r, ver_report, report_text;
  local_var my_sp, my_os, my_arch, my_os_build, systemroot;

  my_os = get_kb_item("SMB/WindowsVersion");
  my_sp = get_kb_item("SMB/CSDVersion");
  my_arch = get_kb_item("SMB/ARCH");
  my_os_build = get_kb_item("SMB/WindowsVersionBuild");
  if ( my_sp )
  {
    my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else my_sp = 0;

  if ( os >!< my_os ) return 0;
  if ( ! isnull(sp) && my_sp != sp ) return 0;
  if ( ! isnull(arch) && my_arch != arch ) return 0;
  if ( ! isnull(os_build) && my_os_build != os_build ) return 0;

  systemroot = hotfix_get_systemroot();
  if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');
  hcf_report=NULL;
  r = hotfix_check_fversion(file:file, version:version, path:systemroot+path, min_version:min_version, bulletin:bulletin, kb:kb, product:product, channel:channel, channel_product:channel_product, channel_version:channel_version, rollup_check:rollup);

  if ( r == HCF_OLDER)
  {
    ver_report = hotfix_get_report();
    if (!empty_or_null(ver_report))
    {
      report_text = strstr(ver_report, rollup);
      if (!isnull(report_text))
      {
        # Remove rollup date and format the output for reporting
        report_text = report_text - rollup;
        report_text = report_text - '  - ';
        set_kb_item(name:"smb_rollup/version_report/"+rollup,value:report_text);
      }
    }
    return 0;
  }
  else
  {
    return 1;
  }
}

function rollupfix_installed()
{
  var file_ver, dism_rollupfix;
  if(!isnull(_FCT_ANON_ARGS[0])) file_ver = _FCT_ANON_ARGS[0];

  dism_rollupfix = get_kb_item("WMI/DISM/rollupfix");
  if(!isnull(dism_rollupfix) && !isnull(os_ver))
  {
    if(os_ver == "10")
      dism_rollupfix = os_ver + ".0." + dism_rollupfix;
    else
      dism_rollupfix = os_ver + "." + dism_rollupfix;
  }

  if(!isnull(dism_rollupfix) && ver_compare(ver:dism_rollupfix, fix:file_ver, strict:FALSE) >= 0)
    return TRUE;
}

function kb_installed()
{
  var kb, qfes, wevt_removed, dism;
  if(isnull(_FCT_ANON_ARGS[0])) return false;
  kb = "KB" + _FCT_ANON_ARGS[0];
  qfes = get_kb_item("SMB/Microsoft/qfes");
  dism = get_kb_item("WMI/DISM/installed");
  wevt_removed = get_kb_item("WMI/WEVTUTIL/removed");
  if((kb >< qfes) || get_kb_item("WMI/Installed/Hotfix/" + kb) || (kb >< dism) || (kb >< wevt_removed))
    return TRUE;
}

report = '';
latest_eff = '';
cur_date = '0.0';
last_date = '0.0';
latest_file = '';
latest_ver = '';
kb_str = '';
systemroot = hotfix_get_systemroot();
smb_qfes = get_kb_item('SMB/Microsoft/qfes');
wmi_qfes = get_kb_list('WMI/Installed/Hotfix/*');
global_var os_ver = get_kb_item("SMB/WindowsVersion");

foreach rollup_date (rollup_dates)
{
  patch_checks = rollup_patches[rollup_date];
  foreach patch_check (patch_checks)
  {
    file_check = patch_check[0];
    if(is_patched(os:file_check["os"],
                  sp:file_check["sp"],
                  os_build:file_check["os_build"],
                  file:file_check["file"],
                  version:file_check["version"],
                  dir:file_check["dir"],
                  path:file_check["path"],
                  rollup:rollup_date))
    {
      kb_list = patch_check[1];

      # 09_2020, 09_2020_2, 09_2020_02_1, etc
      if (rollup_date !~ "^[0-9]+_[0-9][0-9_]*$")
      {
        dbg::log(src:'rollup date loop', msg:'Rollup string failed regex check - rollup_date: ' + obj_rep(rollup_date));
        continue;
      }

      key_segs = split(rollup_date, sep:'_', keep:FALSE);
      int_var = key_segs[0];
      key_segs[0] = key_segs[1];
      key_segs[1] = int_var;
      cur_date = join(key_segs, sep:'.');

      if(kb_installed(kb_list["cum"]) || kb_installed(kb_list["pre"]) || max_index(kb_list["oob"]) > 0 || os_ver == "10" || rollupfix_installed(file_check["version"]))
      {
        if (empty_or_null(latest_eff)) latest_eff = rollup_date;

        # 09_2020, 09_2020_2, 09_2020_02_1, etc
        if (latest_eff !~ "^[0-9]+_[0-9][0-9_]*$")
        {
          dbg::log(src:'rollup date loop', msg:'Rollup string failed regex check - latest_eff: ' + obj_rep(latest_eff));
          continue;
        }
        key_segs = split(latest_eff, sep:'_', keep:FALSE);
        int_var = key_segs[0];
        key_segs[0] = key_segs[1];
        key_segs[1] = int_var;
        last_date = join(key_segs, sep:'.');

        if(ver_compare(ver:cur_date, fix:last_date, strict:FALSE) >=0)
        {
          latest_eff = rollup_date;
          latest_file = systemroot + file_check["path"] + "\" + file_check["file"];
          latest_ver = file_check["version"];

          kb_str =  kb_list["cum"];
          if(kb_list['oob']) kb_str += ", " + join(kb_list['oob'], sep:", ");
          if(kb_list['sec']) kb_str += ", " + kb_list['sec'];
          if(kb_list['pre']) kb_str += ", " + kb_list['pre'];

          set_kb_item(name:"smb_rollup/"+rollup_date+"/file", value:latest_file);
          set_kb_item(name:"smb_rollup/"+rollup_date+"/file_ver", value:latest_ver);
        }
      }

      if(os_ver == "10")
      {
        if(kb_installed(kb_list["cum"]))
        {
          report += '\n Cumulative Rollup : ' + rollup_date + ' [KB' + kb_list["cum"] + ']';
          set_kb_item(name:"smb_rollup/" + rollup_date + "/cum", value:kb_list["cum"]);
        }
        if(oob_installed)
        {
          foreach patch (kb_list["oob"])
          {
            if(kb_installed(patch))
            {
              report += '\n Cumulative Rollup : ' + rollup_date + ' [KB' + patch + ']';
              set_kb_item(name:"smb_rollup/" + rollup_date + "/oob", value:patch);
            }
          }
        }
        if(!kb_installed(kb_list["cum"]) && !oob_installed)
        {
          report += '\n Cumulative Rollup : ' + rollup_date;
          set_kb_item(name:"smb_rollup/" + rollup_date, value:1);
        }
      }
      else
      {
         if(kb_installed(kb_list["cum"]))
        {
          report += '\n Cumulative Rollup : ' + rollup_date + ' [KB' + kb_list["cum"] + ']';
          set_kb_item(name:"smb_rollup/" + rollup_date + "/cum", value:kb_list["cum"]);
        }

        if(kb_installed(kb_list["pre"]))
        {
          report += '\n Preview of Monthly Rollup : ' + rollup_date + ' [KB' + kb_list["pre"] + ']';
          set_kb_item(name:"smb_rollup/" + rollup_date + "/preview", value:kb_list["pre"]);
        }
        if(kb_installed(kb_list["sec"]))
        {
          report += '\n Security Rollup : ' + rollup_date + ' [KB' + kb_list["sec"] + ']';
          set_kb_item(name:"smb_rollup/" + rollup_date + "/sec", value:kb_list["sec"]);
          set_kb_item(name:"smb_rollup/"+rollup_date, value:1);
        }

        # If no qfes could be enumerated, but versions are right
        # defer to the version check.
        if(empty_or_null(smb_qfes) && empty_or_null(wmi_qfes))
        {
          set_kb_item(name:"smb_rollup/"+rollup_date, value:1);
        }
      }
    }
  }
}

# cleanup connection
NetUseDel();

set_kb_item(name:"smb_check_rollup/done", value:TRUE);

if(latest_eff == "" && report == "")
  exit(0, "No Microsoft rollups were found.");

ver = hotfix_get_fversion(path:latest_file);
if (ver['error'] == HCF_OK) latest_ver = join(ver['value'], sep:'.');

if(latest_eff == "")
{
  set_kb_item(name:"smb_rollup/latest", value:"none");
  report += '\n   No cumulative updates are installed.\n';
}
else
{
  report += '\n\n Latest effective update level : ' + latest_eff +
            '\n File checked                  : ' + latest_file +
            '\n File version                  : ' + latest_ver +
            '\n Associated KB                 : ' + kb_str + '\n';
  set_kb_item(name:"smb_rollup/latest", value:latest_eff);
}

port = kb_smb_transport();
if(!port)port = 445;

security_note(port:port, extra:report);
