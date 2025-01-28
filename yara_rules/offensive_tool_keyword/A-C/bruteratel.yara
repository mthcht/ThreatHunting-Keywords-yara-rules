rule bruteratel
{
    meta:
        description = "Detection patterns for the tool 'bruteratel' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bruteratel"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string1 = /\sadaptiveC2\.py/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string2 = /\sgetprivs\.c\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string3 = /\sgetprivs\.o\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string4 = " -ratel " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string5 = " Starting Adaptive C2 Server on " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string6 = /\sStarting\sBadger\sNotification\sHandler\sfor\s\%s\s\=\>\s\{LHOST\}\:\{LPORT\}/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string7 = " Starting external c2 server on " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string8 = /\.BruteRatel/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string9 = /\/adaptiveC2\.py/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string10 = /\/boxreflect\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string11 = /\/brc\-1\.2\.2\.git/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string12 = "/BRC4_rar" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string13 = "/bruteratel" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string14 = "/brute-ratel-armx64" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string15 = "/brute-ratel-linx64" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string16 = /\/brutereflect\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string17 = "/commander-runme"
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string18 = "/Process-Instrumentation-Syscall-Hook" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string19 = /\/vainject\.c/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string20 = /\[\+\]\sCallback\sforwarded\sto\sBrute\sRatel\sServer/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string21 = /\\adaptiveC2\.py/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string22 = /\\badger_x64\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string23 = /\\badger_x64_stealth_ret\.bin/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string24 = /\\badger_x64_stealth_rtl\.bin/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string25 = /\\badger_x64_stealth_wait\.bin/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string26 = /\\badger_x86\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string27 = /\\boxreflect\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string28 = /\\brc\.zip/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string29 = /\\brutereflect\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string30 = /\\harvester64\.o/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string31 = /\\harvester86\.o/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string32 = /\\pipe\\brutepipe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string33 = /\\proxylistener\.py/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string34 = /\\testEnvExit\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string35 = /\\windows\\system32\\badger\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string36 = /\]\sHarvesting\s\[\%d\]\sContacts/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string37 = "0b506ef32f58ee2b1e5701ca8e13c67584739ab1d00ee4a0c2f532c09a15836f" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string38 = "0b506ef32f58ee2b1e5701ca8e13c67584739ab1d00ee4a0c2f532c09a15836f" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string39 = "15e6c7dff42fb507621fddbcbf786ca0022e85ceb431685f607e3d5e07901faa" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string40 = "19aa5edc4fd83677bf6af63d5950707a6425a1550ef47ba8b00d629d95382750" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string41 = "1a279f5df4103743b823ec2a6a08436fdf63fe30" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string42 = "2545de06f2ac30aa79cbeedc5f952c2884506e2d82e0f70c640331d9a07da522" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string43 = "2b4cfde821fbe62d20d7e16e2cb8849a4847f446a7830a6f21905e791835e549" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string44 = "2cda68c8689a88d29b03ac53f3b10662971e95d2c6aa43970c76c0532a4dcfad" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string45 = "344d745c959810475c1d202f2348e644452905c1d58aaf404d1ae25e59e51d38" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string46 = "394d1e6fe47e5958c6cd1ea8a053b100d231c72cabd11f044f51007ef60f2ed4" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string47 = "3fd21b20d00000021c43d21b21b43de0a012c76cf078b8d06f4620c2286f5e" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string48 = "416e6c88a59d32162f3e1d0dfa0b9032b486063509ba4a4ed68f22fa868fb1a4" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string49 = "4773112ed8b41ef5fc0ad7b59134be3e5204b726154d1e97553e16f85fa2a045" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string50 = "48b5eeaaaca67edea0fea3c13d20e7e536ed0205b3b39b9afaf3ef251cfa16e7" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string51 = "49693e06c8e70eabe6a5e3cf8b1624e07462fc0cbb01f1bce18b75af8534c7e1" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string52 = "51d0a19dcb5fd8dc8c8a98666bb91341a15655de2789dfa842e891f2a71aa2e9" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string53 = "5b9e669bea90a5dacd7c2432e9d02f1a66d7ed4d531df6c2870cc3238847193c" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string54 = "74538a33411912829115fdbd71633c7e250b00fb2c1a936641c3d32c3e77ee8b" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string55 = "7e3de37367d5aaa89be6034e8afc57740bd50397b244fcf7690dde4299f724e9" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string56 = "8464129299b636de1a2a86eb3b7a1f1cbd577f50eb5e3758a7ded72c5d497f15" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string57 = "86965e72a87bd5b0fc8a897c6736b7a57ddd9d3ba5232a5ba626e3f16fec59e2" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string58 = "a02316234173d1704bae35ba6e194504049f563bd9aa51fef31850256e47ba9c" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string59 = "a6176293011e6a61923c609c63925c47b0f1f9b5465b451148e4813969d850b8" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string60 = "addpriv SeloadDrivePrivilege" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string61 = /addresshunter\.h/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string62 = "apt-get install libqt5webenginewidgets5 libqt5websockets5" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string63 = "b2a71ab4206470ed4091b90dc0541a8f9dd22ecf3c8db02997f29d407d5c317a" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string64 = "b2b344b380da8acc1b2409c079cac635df47700af3aa1193c94dae2487011442" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string65 = "b2b344b380da8acc1b2409c079cac635df47700af3aa1193c94dae2487011442" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string66 = "b68963ec0310b012dd393c583bd5f4062b63a749e3a457e4ce9e91db50ea726b" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string67 = "b8d9531ece7787f90d6b6bd5bf28e910d28bf3a5d6bb3deb0d0719cc01d2754b" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string68 = /badger_exports\.h/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string69 = /badger_svc\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string70 = /badger_template\.ps1/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string71 = /badger_x64\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string72 = /badger_x64_.{0,1000}\.bin/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string73 = /badger_x64_aws\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string74 = "BadgerAtoi" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string75 = "BadgerDispatch" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string76 = "BadgerDispatchW" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string77 = "BadgerMemcpy" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string78 = "BadgerMemset" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string79 = "BadgerStrcmp" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string80 = "BadgerStrlen" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string81 = "BadgerWcscmp" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string82 = "BadgerWcslen" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string83 = "bc3023b36063a7681db24681472b54fa11f0d4ec" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string84 = /bhttp_x64\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string85 = /Brc4ConfigExtractor\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string86 = "Brc4DecodeString" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string87 = "Bruteloader Box Reflected" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string88 = "bruteloader" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string89 = "brute-ratel-" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string90 = /BruteRatel.{0,1000}\.tar\.gz/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string91 = /BruteRatel.{0,1000}\.zip/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string92 = /bruteratel\.com\// nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string93 = "bruteratel/" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string94 = "Brute-Ratel-C4" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string95 = "c30d5ee79c92843970d8d413f7522569277e30ec2c4b73cbc42022f2945aa218" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string96 = "c70b1fd133737a21904159ed2a867e0105060ac74937472da5e4d0e1f6fa1645" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string97 = "c7afaf55e64fcbcae026383afb4f2576317dc3288fbda8652506e28fe71f10dc" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string98 = /coffexec\s.{0,1000}\.o\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string99 = "contact_harvester" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string100 = "crisis_monitor start" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string101 = "crisis_monitor stop" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string102 = "cryptvortex " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string103 = "dcsync_inject" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string104 = /detect\sntdll\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string105 = "e9e2d2794db9b02818784c075f2b71f980803c2c8b372936d0d02cd43f3d05a3" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string106 = /etwti\-hook\./ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string107 = "Ex_MiniDumpWriteDumpCallback" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string108 = "f3acbb6add19742a56784205264a699f6604e1e64b391b9bad26f4745d3d7ed1" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string109 = "f80759c36daba1a58c631ee2c3bf26652a6a27774e9ffe3067addbc15754b2bd" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string110 = /getEnvExitPtr\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string111 = /getprivs\.bin/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string112 = /getprivs\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string113 = /https\:\/\/bruteratel\.com\:65000\/activate/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string114 = "imp_Badger" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string115 = "krb5decoder" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string116 = /ldapsentinel\s.{0,1000}\sraw\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string117 = "ldapsentinel forest user" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string118 = "list_tcppivot" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string119 = /loaddll64\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string120 = "LocateBrc4Config" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string121 = /manasmbellani\/brc\-1\.2\.2/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string122 = "o_getprivs" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string123 = /objexec\s.{0,1000}\.o/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string124 = /paranoidninja\/badger\.bin/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string125 = /phantom_thread\s.{0,1000}\sshc\s/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string126 = "PIC-Get-Privileges" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string127 = /pivot_smb\s\\/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string128 = "pivot_winrm " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string129 = "Proxy-DLL-Loads" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string130 = /proxyDllLoads\.c/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string131 = /proxyDllLoads\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string132 = "psreflect " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string133 = /runshellcode\.asm/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string134 = /runshellcode\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string135 = /runshellcode\.o/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string136 = "samdump " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string137 = "ScanProcessForBadgerConfig" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string138 = "scdivert localhost " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string139 = /schtquery\s.{0,1000}\sfull/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string140 = /seatbelt\/hostnames\.txt/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string141 = "send badger response to ratel server and recv the next command" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string142 = /set_child\swerfault\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string143 = /set_objectpipe\s\\\\/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string144 = /set_wmiconfig\s\\/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string145 = "shadowclock" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string146 = "shadowclone " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string147 = "sharpinline " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string148 = "Sharpreflect " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string149 = "shinject_ex " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string150 = /StrongLoader_x64\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string151 = "suspended_run " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string152 = "threads all alertable" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string153 = /wmiexec\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string154 = "wmispawn select" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string155 = "xoxb-2144924547920-3382587054001-2xPrUBj0D8yf0D5BNDPh3nwY" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string156 = "xoxb-2144924547920-3393858142400-qEIcN8hBt0WgwRaJImILqMAj" nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string157 = "kerberoast " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string158 = /list_exports\s.{0,1000}\.dll/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string159 = "make_token " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string160 = "memdump " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string161 = /memex\s\/.{0,1000}\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string162 = "memhunt " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string163 = "psgrep " nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string164 = /set_child\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A Customized Command and Control Center for Red Team and Adversary Simulation
        // Reference: https://bruteratel.com/
        $string165 = /sharescan\s.{0,1000}\.txt/ nocase ascii wide

    condition:
        any of them
}
