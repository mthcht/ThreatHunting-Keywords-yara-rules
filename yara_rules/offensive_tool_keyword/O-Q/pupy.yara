rule pupy
{
    meta:
        description = "Detection patterns for the tool 'pupy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pupy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string1 = /\sclear_logs\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string2 = /\screddump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string3 = /\sdomcachedump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string4 = /\sdomcachedump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string5 = /\sexploit_suggester\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string6 = /\sgen\s\-f\sclient\s\-O\swindows\s\-A\sx64/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string7 = /\sgen\s\-S\s\-f\sclient\s\-O\swindows\s\-A\sx64/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string8 = /\simpacket\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string9 = /\sinteractive_shell\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string10 = /\skeylogger\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string11 = /\slinux_stealth\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string12 = /\smemorpy\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string13 = /\smimipy\.py\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string14 = /\smimipy\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string15 = /\smouselogger\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string16 = /\snbnsspoof\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string17 = /\s\-\-oneliner\-nothidden/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string18 = /\spersist_hkcu_run/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string19 = /\sport_scan\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string20 = /\sPupyCredentials/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string21 = /\spupylib\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string22 = /\spupysh\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string23 = /\spupysh\.sh/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string24 = /\sPupySocketStream/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string25 = /\sPupyTCPClient/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string26 = /\sPupyTCPServer/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string27 = /\sPupyWebServer/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string28 = /\sPupyWebSocketClient/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string29 = /\sPupyWebSocketServer/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string30 = /\spupyx64\.dll/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string31 = /\spupyx64\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string32 = /\spupyx64\.lin/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string33 = /\spupyx86\.dll/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string34 = /\spupyx86\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string35 = /\spush_payload/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string36 = /\spwdump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string37 = /\ssocks5proxy\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string38 = /\sstart_hidden_process/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string39 = /\/all\/pupyutils\/.{0,1000}\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string40 = /\/android\/pupydroid\// nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string41 = /\/beroot\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string42 = /\/bin\/pupysh/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string43 = /\/clear_logs\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string44 = /\/creddump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string45 = /\/creddump7\// nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string46 = /\/dnscnc\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string47 = /\/domcachedump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string48 = /\/exploit_suggester\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string49 = /\/interactive_shell\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string50 = /\/LaZagne\/Windows\// nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string51 = /\/linux_stealth\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string52 = /\/memory_exec\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string53 = /\/mimipy\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string54 = /\/mouselogger\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string55 = /\/n1nj4sec\/pupy/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string56 = /\/nbnsspoof\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string57 = /\/netcreds\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string58 = /\/netcreds\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string59 = /\/obfs3\/obfs3\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string60 = /\/port_scan\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string61 = /\/powerloader\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string62 = /\/ps1_oneliner\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string63 = /\/pupwinutils\/.{0,1000}\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string64 = /\/pupy\/.{0,1000}\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string65 = /\/pupy\/commands\// nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string66 = /\/pupy\/external\/creddump7/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string67 = /\/pupy\/memimporter\// nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string68 = /\/pupy\/output\/pupyx64.{0,1000}\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string69 = /\/pupy\/pupygen\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string70 = /\/pupy_load\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string71 = /\/PupyCmd\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string72 = /\/PupyCompile\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string73 = /\/pupygen\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string74 = /\/pupylib\/payloads\// nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string75 = /\/PupyOffload\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string76 = /\/pupyps\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string77 = /\/PupyServer\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string78 = /\/PupyService\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string79 = /\/pupysh\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string80 = /\/pupysh\.sh/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string81 = /\/PupyTriggers\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string82 = /\/PupyWeb\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string83 = /\/pupyx64\.dll/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string84 = /\/pupyx64\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string85 = /\/pupyx64d\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string86 = /\/pupyx86\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string87 = /\/pupyx86d\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string88 = /\/pwdump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string89 = /\/py_oneliner\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string90 = /\/Python\-dynload\-os\.h/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string91 = /\/share_enum\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string92 = /\/shell_exec\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string93 = /\/smbspider\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string94 = /\/socks5proxy\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string95 = /\/transports\/scramblesuit\/.{0,1000}\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string96 = /\/usniper\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string97 = /\/utils\/obfuscate\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string98 = /\/WinPwnage/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string99 = /\[\+\]\sBuild\spupysh\senvironment\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string100 = /\\clear_logs\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string101 = /\\creddump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string102 = /\\dns\-dump\.ps1/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string103 = /\\domcachedump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string104 = /\\domcachedump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string105 = /\\exploit_suggester\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string106 = /\\mimipy\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string107 = /\\mouselogger\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string108 = /\\nbnsspoof\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string109 = /\\netcreds\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string110 = /\\port_scan\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string111 = /\\pupwinutils\\/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string112 = /\\pupy\\external\\creddump7/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string113 = /\\pupyx64\.dll/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string114 = /\\pupyx64\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string115 = /\\pupyx64d\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string116 = /\\pupyx86\.dll/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string117 = /\\pupyx86\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string118 = /\\pupyx86d\.exe/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string119 = /\\pwdump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string120 = /\\socks5proxy\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string121 = /\\windows\\all\\winpwnage/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string122 = /\\windows\\creddump/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string123 = /_generate_bind_payloads_password/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string124 = /_generate_scramblesuit_passwd/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string125 = /_METERPRETER_BASE_INJECT_H/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string126 = /07aa565057af859bc4956df913246b3b5fe39e86823666d6ba77aa98a697b02a/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string127 = /10de4ed7588b4a7e75d01bb69f0b602b0c298a2f9f993a6a8f4e2248031699fb/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string128 = /18eeee347539926baae88b3bec52025a00b404301f60a8cbf4d77156fcfaf782/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string129 = /237f52a3509094464bb92f82a4908a60c7a4cc9db9748f0cc254e75311bb8b0d/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string130 = /2a8b77cd55cc43d79d9c4475cc9287360f6fd3dc47a07f83ff33853de1652f7d/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string131 = /3000b91468e3961b4e1a9ecd07007bfe02f50033d0d4a71dfb4e5b1de778bd13/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string132 = /335628fdb196d750906961db6ce9ec4c35fb7c16f6883c441c6c620468e273c1/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string133 = /35678541d1d3a394875f58f3add9b097f445dc15de0a720318da1db4d1de06e8/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string134 = /63dcdf6e5eb8252ec73b58bde6249db9d38272dc6870074d2569f7431a1ab32f/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string135 = /6b6aede14ee7f52374cf3fbc5d790afa32f23dc0791514ce26306514e4a22ee4/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string136 = /7c6f4b0023b62103aa803d4ddfe2736ed80f2911f7556ef16abc3be04674697b/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string137 = /aa3939fc357723135870d5036b12a67097b03309/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string138 = /b501b1a7f5d1ca09fa28d4c2d9e839a5d7e8a9f336d3698c947cac13b02a599a/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string139 = /bcfe13901d4207db340d957052cd5175e24481a5e2c5fc15d119fadedc664755/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string140 = /bypassuac_registry\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string141 = /bypassuac_token_imp\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string142 = /c439db633c51838ba79ec999e0f5b4533379b94d2afeb5944fd15250fa5a86de/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string143 = /cachedump\.py\s\// nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string144 = /ce70b1200ce76360dec6129189daa260779901d01f150868c9f19ec6cea77b36/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string145 = /Collect\ssecurity\stokens\sfrom\spipe\sserver\s\(\\\\\\\\\.\\\\pipe\\\\catcher\)/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string146 = /compress_encode_obfs/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string147 = /ConvertFrom\-UACValue/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string148 = /create\-workspace\.py\s\-E\sdocker\s\-P.{0,1000}\/pupyws/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string149 = /creddump\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string150 = /d02161cdc91cdee273f8b6e47f98a322756847ae3b5f4efe6d439fa5e13f9039/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string151 = /dotnet_serve_payload/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string152 = /eb6a95c5c92ae3923ae07b80feac9e215f68eaff1289303063fa575a92c27967/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string153 = /eb87d686b9a040238e563add68fb05c2776f52332c4798cae372638af3c7fca0/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string154 = /echo\:iex\(\[System\.Text\.Encoding\]\:\:ASCII\.GetString\(/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string155 = /exploit_suggester\s\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string156 = /exploit_suggester\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string157 = /exposed_get_password/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string158 = /fa7eba4a7edb75f644eace116b7072d9edddfa0af672bd99091d9035b974ba21/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string159 = /Find\-GPOComputerAdmin/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string160 = /Find\-InterestingFile/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string161 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string162 = /Find\-LocalAdminAccess/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string163 = /gen\s\-f\spy\sbind\s\-\-port/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string164 = /gen\s\-f\spy_oneliner\sconnect\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string165 = /generate_loader_cmd/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string166 = /generateInjectBinFile/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string167 = /Get\-ExploitableSystem/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string168 = /Get\-ExploitableSystem\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string169 = /import\sPupyConfig/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string170 = /Import\-DllImports\s\-PEInfo\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string171 = /Import\-DllInRemoteProcess/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string172 = /Invoke\-ACLScanner/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string173 = /Invoke\-DowngradeAccount/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string174 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string175 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string176 = /Invoke\-EnumerateLocalAdmin/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string177 = /Invoke\-EventHunter/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string178 = /Invoke\-FileFinder/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string179 = /Invoke\-ProcessHunter/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string180 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string181 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string182 = /Invoke\-ReflectivePEInjection\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string183 = /Invoke\-ShareFinder/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string184 = /Invoke\-StealthUserHunter/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string185 = /Invoke\-StealthUserHunter/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string186 = /Invoke\-UserHunter/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string187 = /loot_memory\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string188 = /nbnsspoof\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string189 = /New\-GPOImmediateTask/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string190 = /pack_py_payload/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string191 = /privesc_checker/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string192 = /privesc_checker\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string193 = /privesc_checker\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string194 = /pupwinutils\.shellcode/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string195 = /pupy.{0,1000}\/checkvm\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string196 = /pupy\/external\/Inveigh/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string197 = /pupy\/external\/LaZagne/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string198 = /pupy\/external\/linux\-exploit\-suggester/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string199 = /pupy\/external\/mimipy/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string200 = /pupy\/external\/pyopus/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string201 = /pupy\/external\/pywerview/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string202 = /pupy\/external\/winpty/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string203 = /pupy\/external\/WinPwnage/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string204 = /pupy\/payload_/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string205 = /pupy\/pupy\/external\/BeRoot/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string206 = /PupyCmdLoop/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string207 = /PupyCredentials\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string208 = /PupyDnsCnc\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string209 = /PupyDnsCommandServerHandler/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string210 = /pupygen\.py\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string211 = /PupyKCPSocketStream/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string212 = /pupylib\.payloads\.ps1/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string213 = /PupyLoaderTemplate\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string214 = /PupyOffloadDNS/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string215 = /PupyOffloadSocket/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string216 = /PupySocketStream\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string217 = /PupyVirtualStream\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string218 = /pyexec\s\-c\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string219 = /pyexec\s\-\-file/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string220 = /ReflectiveDllInjection\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string221 = /ReflectiveLoader\.c/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string222 = /ReflectiveLoader\.h/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string223 = /registry_hijacking_eventvwr/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string224 = /registry_hijacking_fodhelper/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string225 = /rubber_ducky\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string226 = /run\s.{0,1000}\spyshell/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string227 = /run\sandroid_cam\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string228 = /run\s\-\-bg\sshell_exec/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string229 = /run\sinteractive_shell/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string230 = /run\skeylogger/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string231 = /run\smemory_exec\s.{0,1000}\./ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string232 = /run\smouselogger/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string233 = /run\spyexec\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string234 = /run\sshell_exec\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string235 = /run\sshellcode_exec/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string236 = /send_ps1_payload/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string237 = /serve_ps1_payload/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string238 = /shellcode_exec\.py/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string239 = /smbspider\s/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string240 = /start_nbnsspoof/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string241 = /webcamsnap\s\-v/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string242 = /winpwnage\.functions/ nocase ascii wide
        // Description: Pupy is a  C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string243 = /pupysh/ nocase ascii wide

    condition:
        any of them
}
