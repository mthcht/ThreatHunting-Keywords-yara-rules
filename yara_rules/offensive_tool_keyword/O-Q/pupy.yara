rule pupy
{
    meta:
        description = "Detection patterns for the tool 'pupy' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pupy"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string1 = /\sgen\s\-f\sclient\s\-O\swindows\s\-A\sx64/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string2 = /\sgen\s\-S\s\-f\sclient\s\-O\swindows\s\-A\sx64/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string3 = /\simpacket\./ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string4 = /\skeylogger\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string5 = /\smemorpy\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string6 = /\s\-\-oneliner\-nothidden/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string7 = /\spersist_hkcu_run/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string8 = /\sPupyCredentials/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string9 = /\spupylib\./ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string10 = /\sPupySocketStream/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string11 = /\sPupyTCPClient/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string12 = /\sPupyTCPServer/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string13 = /\sPupyWebServer/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string14 = /\sPupyWebSocketClient/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string15 = /\sPupyWebSocketServer/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string16 = /\spupyx64\.lin/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string17 = /\spush_payload/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string18 = /\sstart_hidden_process/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string19 = /\/all\/pupyutils\/.{0,1000}\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string20 = /\/android\/pupydroid\// nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string21 = /\/beroot\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string22 = /\/bin\/pupysh/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string23 = /\/creddump7\// nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string24 = /\/dnscnc\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string25 = /\/interactive_shell\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string26 = /\/LaZagne\/Windows\// nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string27 = /\/memory_exec\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string28 = /\/mimipy\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string29 = /\/mouselogger\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string30 = /\/n1nj4sec\/pupy/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string31 = /\/netcreds\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string32 = /\/obfs3\/obfs3\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string33 = /\/powerloader\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string34 = /\/ps1_oneliner\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string35 = /\/pupwinutils\/.{0,1000}\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string36 = /\/pupy\/.{0,1000}\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string37 = /\/pupy\/commands\// nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string38 = /\/pupy\/memimporter\// nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string39 = /\/pupy\/output\/pupyx64.{0,1000}\.exe/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string40 = /\/pupy\/pupygen\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string41 = /\/pupy_load\./ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string42 = /\/PupyCmd\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string43 = /\/PupyCompile\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string44 = /\/pupygen\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string45 = /\/pupylib\/payloads\// nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string46 = /\/PupyOffload\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string47 = /\/pupyps\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string48 = /\/PupyServer\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string49 = /\/PupyService\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string50 = /\/pupysh\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string51 = /\/PupyTriggers\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string52 = /\/PupyWeb\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string53 = /\/py_oneliner\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string54 = /\/Python\-dynload\-os\.h/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string55 = /\/share_enum\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string56 = /\/shell_exec\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string57 = /\/smbspider\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string58 = /\/transports\/scramblesuit\/.{0,1000}\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string59 = /\/usniper\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string60 = /\/utils\/obfuscate\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string61 = /\/WinPwnage/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string62 = /_generate_bind_payloads_password/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string63 = /_generate_scramblesuit_passwd/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string64 = /aa3939fc357723135870d5036b12a67097b03309/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string65 = /bypassuac_registry\./ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string66 = /bypassuac_token_imp\./ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string67 = /compress_encode_obfs/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string68 = /creddump\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string69 = /dotnet_serve_payload/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string70 = /exploit_suggester\s\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string71 = /exploit_suggester\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string72 = /exposed_get_password/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string73 = /gen\s\-f\spy\sbind\s\-\-port/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string74 = /gen\s\-f\spy_oneliner\sconnect\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string75 = /generate_loader_cmd/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string76 = /generateInjectBinFile/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string77 = /import\sPupyConfig/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string78 = /Import\-DllImports\s\-PEInfo\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string79 = /Import\-DllInRemoteProcess/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string80 = /Invoke\-ReflectivePEInjection/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string81 = /Invoke\-ReflectivePEInjection\./ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string82 = /loot_memory\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string83 = /nbnsspoof\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string84 = /pack_py_payload/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string85 = /privesc_checker/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string86 = /privesc_checker\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string87 = /pupy.{0,1000}\/checkvm\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string88 = /pupy\/payload_/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string89 = /PupyCmdLoop/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string90 = /PupyCredentials\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string91 = /PupyDnsCnc\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string92 = /PupyDnsCommandServerHandler/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string93 = /pupygen\.py\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string94 = /PupyKCPSocketStream/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string95 = /PupyLoaderTemplate\./ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string96 = /PupyOffloadDNS/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string97 = /PupyOffloadSocket/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string98 = /PupySocketStream\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string99 = /PupyVirtualStream\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string100 = /pyexec\s\-c\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string101 = /pyexec\s\-\-file/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string102 = /ReflectiveDllInjection\./ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string103 = /ReflectiveLoader\.c/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string104 = /ReflectiveLoader\.h/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string105 = /registry_hijacking_eventvwr/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string106 = /registry_hijacking_fodhelper/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string107 = /rubber_ducky\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string108 = /run\s.{0,1000}\spyshell/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string109 = /run\sandroid_cam\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string110 = /run\s\-\-bg\sshell_exec/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string111 = /run\sinteractive_shell/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string112 = /run\skeylogger/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string113 = /run\smemory_exec\s.{0,1000}\./ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string114 = /run\smouselogger/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string115 = /run\spyexec\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string116 = /run\sshell_exec\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string117 = /run\sshellcode_exec/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string118 = /send_ps1_payload/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string119 = /serve_ps1_payload/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string120 = /shellcode_exec\.py/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string121 = /smbspider\s/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string122 = /start_nbnsspoof/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string123 = /webcamsnap\s\-v/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string124 = /winpwnage\.functions/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string125 = /pupysh/ nocase ascii wide

    condition:
        any of them
}
