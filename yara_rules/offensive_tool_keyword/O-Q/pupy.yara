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
        $string1 = /.{0,1000}\sgen\s\-f\sclient\s\-O\swindows\s\-A\sx64.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string2 = /.{0,1000}\sgen\s\-S\s\-f\sclient\s\-O\swindows\s\-A\sx64.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string3 = /.{0,1000}\simpacket\..{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string4 = /.{0,1000}\skeylogger\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string5 = /.{0,1000}\smemorpy\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string6 = /.{0,1000}\s\-\-oneliner\-nothidden.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string7 = /.{0,1000}\spersist_hkcu_run.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string8 = /.{0,1000}\sPupyCredentials.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string9 = /.{0,1000}\spupylib\..{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string10 = /.{0,1000}\sPupySocketStream.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string11 = /.{0,1000}\sPupyTCPClient.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string12 = /.{0,1000}\sPupyTCPServer.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string13 = /.{0,1000}\sPupyWebServer.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string14 = /.{0,1000}\sPupyWebSocketClient.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string15 = /.{0,1000}\sPupyWebSocketServer.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string16 = /.{0,1000}\spupyx64\.lin.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string17 = /.{0,1000}\spush_payload.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string18 = /.{0,1000}\sstart_hidden_process.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string19 = /.{0,1000}\/all\/pupyutils\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string20 = /.{0,1000}\/android\/pupydroid\/.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string21 = /.{0,1000}\/beroot\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string22 = /.{0,1000}\/bin\/pupysh.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string23 = /.{0,1000}\/creddump7\/.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string24 = /.{0,1000}\/dnscnc\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string25 = /.{0,1000}\/interactive_shell\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string26 = /.{0,1000}\/LaZagne\/Windows\/.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string27 = /.{0,1000}\/memory_exec\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string28 = /.{0,1000}\/mimipy\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string29 = /.{0,1000}\/mouselogger\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string30 = /.{0,1000}\/n1nj4sec\/pupy.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string31 = /.{0,1000}\/netcreds\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string32 = /.{0,1000}\/obfs3\/obfs3\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string33 = /.{0,1000}\/powerloader\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string34 = /.{0,1000}\/ps1_oneliner\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string35 = /.{0,1000}\/pupwinutils\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string36 = /.{0,1000}\/pupy\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string37 = /.{0,1000}\/pupy\/commands\/.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string38 = /.{0,1000}\/pupy\/memimporter\/.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string39 = /.{0,1000}\/pupy\/output\/pupyx64.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string40 = /.{0,1000}\/pupy\/pupygen\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string41 = /.{0,1000}\/pupy_load\..{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string42 = /.{0,1000}\/PupyCmd\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string43 = /.{0,1000}\/PupyCompile\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string44 = /.{0,1000}\/pupygen\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string45 = /.{0,1000}\/pupylib\/payloads\/.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string46 = /.{0,1000}\/PupyOffload\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string47 = /.{0,1000}\/pupyps\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string48 = /.{0,1000}\/PupyServer\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string49 = /.{0,1000}\/PupyService\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string50 = /.{0,1000}\/pupysh\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string51 = /.{0,1000}\/PupyTriggers\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string52 = /.{0,1000}\/PupyWeb\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string53 = /.{0,1000}\/py_oneliner\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string54 = /.{0,1000}\/Python\-dynload\-os\.h.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string55 = /.{0,1000}\/share_enum\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string56 = /.{0,1000}\/shell_exec\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string57 = /.{0,1000}\/smbspider\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string58 = /.{0,1000}\/transports\/scramblesuit\/.{0,1000}\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string59 = /.{0,1000}\/usniper\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string60 = /.{0,1000}\/utils\/obfuscate\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string61 = /.{0,1000}\/WinPwnage.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string62 = /.{0,1000}_generate_bind_payloads_password.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string63 = /.{0,1000}_generate_scramblesuit_passwd.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string64 = /.{0,1000}aa3939fc357723135870d5036b12a67097b03309.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string65 = /.{0,1000}bypassuac_registry\..{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string66 = /.{0,1000}bypassuac_token_imp\..{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string67 = /.{0,1000}compress_encode_obfs.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string68 = /.{0,1000}creddump\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string69 = /.{0,1000}dotnet_serve_payload.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string70 = /.{0,1000}exploit_suggester\s\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string71 = /.{0,1000}exploit_suggester\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string72 = /.{0,1000}exposed_get_password.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string73 = /.{0,1000}gen\s\-f\spy\sbind\s\-\-port.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string74 = /.{0,1000}gen\s\-f\spy_oneliner\sconnect\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string75 = /.{0,1000}generate_loader_cmd.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string76 = /.{0,1000}generateInjectBinFile.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string77 = /.{0,1000}import\sPupyConfig.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string78 = /.{0,1000}Import\-DllImports\s\-PEInfo\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string79 = /.{0,1000}Import\-DllInRemoteProcess.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string80 = /.{0,1000}Invoke\-ReflectivePEInjection.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string81 = /.{0,1000}Invoke\-ReflectivePEInjection\..{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string82 = /.{0,1000}loot_memory\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string83 = /.{0,1000}nbnsspoof\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string84 = /.{0,1000}pack_py_payload.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string85 = /.{0,1000}privesc_checker.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string86 = /.{0,1000}privesc_checker\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string87 = /.{0,1000}pupy.{0,1000}\/checkvm\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string88 = /.{0,1000}pupy\/payload_.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string89 = /.{0,1000}PupyCmdLoop.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string90 = /.{0,1000}PupyCredentials\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string91 = /.{0,1000}PupyDnsCnc\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string92 = /.{0,1000}PupyDnsCommandServerHandler.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string93 = /.{0,1000}pupygen\.py\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string94 = /.{0,1000}PupyKCPSocketStream.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string95 = /.{0,1000}PupyLoaderTemplate\..{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string96 = /.{0,1000}PupyOffloadDNS.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string97 = /.{0,1000}PupyOffloadSocket.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string98 = /.{0,1000}PupySocketStream\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string99 = /.{0,1000}PupyVirtualStream\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string100 = /.{0,1000}pyexec\s\-c\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string101 = /.{0,1000}pyexec\s\-\-file.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string102 = /.{0,1000}ReflectiveDllInjection\..{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string103 = /.{0,1000}ReflectiveLoader\.c.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string104 = /.{0,1000}ReflectiveLoader\.h.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string105 = /.{0,1000}registry_hijacking_eventvwr.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string106 = /.{0,1000}registry_hijacking_fodhelper.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string107 = /.{0,1000}rubber_ducky\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string108 = /.{0,1000}run\s.{0,1000}\spyshell.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string109 = /.{0,1000}run\sandroid_cam\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string110 = /.{0,1000}run\s\-\-bg\sshell_exec.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string111 = /.{0,1000}run\sinteractive_shell.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string112 = /.{0,1000}run\skeylogger.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string113 = /.{0,1000}run\smemory_exec\s.{0,1000}\..{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string114 = /.{0,1000}run\smouselogger.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string115 = /.{0,1000}run\spyexec\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string116 = /.{0,1000}run\sshell_exec\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string117 = /.{0,1000}run\sshellcode_exec.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string118 = /.{0,1000}send_ps1_payload.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string119 = /.{0,1000}serve_ps1_payload.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string120 = /.{0,1000}shellcode_exec\.py.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string121 = /.{0,1000}smbspider\s.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string122 = /.{0,1000}start_nbnsspoof.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string123 = /.{0,1000}webcamsnap\s\-v.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string124 = /.{0,1000}winpwnage\.functions.{0,1000}/ nocase ascii wide
        // Description: Pupy is an opensource. cross-platform (Windows. Linux. OSX. Android) C2 and post-exploitation framework written in python and C
        // Reference: https://github.com/n1nj4sec/pupy
        $string125 = /pupysh/ nocase ascii wide

    condition:
        any of them
}
