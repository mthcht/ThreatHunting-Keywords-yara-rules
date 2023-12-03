rule venom
{
    meta:
        description = "Detection patterns for the tool 'venom' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "venom"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string1 = /.{0,1000}\skimi\.py\s.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string2 = /.{0,1000}\s\-NoPRo\s\-wIN\s1\s\-nONi\s\-eN\sSh33L.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string3 = /.{0,1000}\/\/Lh0St\/InJ3C.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string4 = /.{0,1000}\/\/RRh0St\/InJ3C.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string5 = /.{0,1000}\/avet_fabric\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string6 = /.{0,1000}\/evil_pdf\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string7 = /.{0,1000}\/exec_bin\.c.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string8 = /.{0,1000}\/exec_dll\.c.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string9 = /.{0,1000}\/exec_psh\.c.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string10 = /.{0,1000}\/exec0\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string11 = /.{0,1000}\/GetBrowsers\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string12 = /.{0,1000}\/hta_attack\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string13 = /.{0,1000}\/kimi\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string14 = /.{0,1000}\/NewPhish\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string15 = /.{0,1000}\/persistence2\.rc.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string16 = /.{0,1000}\/phishing\/.{0,1000}\.html.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string17 = /.{0,1000}\/powerglot\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string18 = /.{0,1000}\/ps2exe\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string19 = /.{0,1000}\/r00t\-3xp10it.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string20 = /.{0,1000}\/Rat_Generator.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string21 = /.{0,1000}\/shellcode_samples\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string22 = /.{0,1000}\/venom\.git.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string23 = /.{0,1000}\/venom\.sh\s.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string24 = /.{0,1000}\/venom\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string25 = /.{0,1000}\\bin\\shepard\\.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string26 = /.{0,1000}\\BrowserEnum\.log.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string27 = /.{0,1000}\\CredsPhish\.log.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string28 = /.{0,1000}\\evil_pdf\\.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string29 = /.{0,1000}\\GetBrowsers\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string30 = /.{0,1000}\\NewPhish\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string31 = /.{0,1000}\\powerglot\\.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string32 = /.{0,1000}\\ps2exe\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string33 = /.{0,1000}\\PS2EXE\\.{0,1000}\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string34 = /.{0,1000}\\shellcode_samples\\.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string35 = /.{0,1000}\\SillyRAT\\.{0,1000}\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string36 = /.{0,1000}0evilpwfilter.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string37 = /.{0,1000}0evilpwfilter\.dll.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string38 = /.{0,1000}aux\/dump_credentials.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string39 = /.{0,1000}aux\/enum_system\.rc.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string40 = /.{0,1000}aux\/msf\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string41 = /.{0,1000}aux\/persistence\.rc/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string42 = /.{0,1000}aux\/privilege_escalation\..{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string43 = /.{0,1000}aux\/Start\-Webserver\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string44 = /.{0,1000}bin\/.{0,1000}\/PS2EXE\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string45 = /.{0,1000}bin\/icmpsh\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string46 = /.{0,1000}bin\/SillyRAT\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string47 = /.{0,1000}bin\/void\.zip.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string48 = /.{0,1000}bin\\SillyRAT.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string49 = /.{0,1000}bin\\void\.zip.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string50 = /.{0,1000}CarbonCopy\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string51 = /.{0,1000}ChaitanyaHaritash\/kimi.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string52 = /.{0,1000}CommandCam\.exe.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string53 = /.{0,1000}CredsPhish\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string54 = /.{0,1000}DarkRCovery\.exe.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string55 = /.{0,1000}dll_hijack_detect_x64.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string56 = /.{0,1000}dll_hijack_detect_x86.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string57 = /.{0,1000}encodeScriptPolyglot.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string58 = /.{0,1000}enigma_fileless_uac_bypass.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string59 = /.{0,1000}exploit_suggester\..{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string60 = /.{0,1000}firefox\/FakeUpdate_files\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string61 = /.{0,1000}hta\-to\-javascript\-crypter.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string62 = /.{0,1000}http:\/\/LhOsT\/FiLNaMe\..{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string63 = /.{0,1000}import\sImpactDecoder.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string64 = /.{0,1000}import\sImpactPacket.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string65 = /.{0,1000}install_winrar_wine32\.exe.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string66 = /.{0,1000}install_winrar_wine64\..{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string67 = /.{0,1000}InvokeMeter\.bat.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string68 = /.{0,1000}Invoke\-Phant0m.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string69 = /.{0,1000}InvokePS1\.bat.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string70 = /.{0,1000}Invoke\-Shellcode.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string71 = /.{0,1000}keylooger\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string72 = /.{0,1000}kimi_MDPC\/kimi\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string73 = /.{0,1000}linux_hostrecon.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string74 = /.{0,1000}linux_hostrecon\..{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string75 = /.{0,1000}make_avet\s\-l\s.{0,1000}\.exe\s.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string76 = /.{0,1000}make_avetsvc\s.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string77 = /.{0,1000}Meterpreter\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string78 = /.{0,1000}meterpreter_loader.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string79 = /.{0,1000}METERPRETER_STAGER.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string80 = /.{0,1000}mimiRatz.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string81 = /.{0,1000}mozlz4\-win32\.exe.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string82 = /.{0,1000}msf\-auxiliarys.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string83 = /.{0,1000}obfuscate\/shellter.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string84 = /.{0,1000}perl\-reverse\-shell\..{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string85 = /.{0,1000}PEScrambler\.exe.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string86 = /.{0,1000}POST_EXPLOIT_DIR.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string87 = /.{0,1000}powerglot\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string88 = /.{0,1000}pyherion\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string89 = /.{0,1000}rapid7\.github\.io\/metasploit\-framework\/api\/.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string90 = /.{0,1000}reshacker_setup\.exe.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string91 = /.{0,1000}SHELLCODE\sGENERATOR.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string92 = /.{0,1000}shellter\.exe.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string93 = /.{0,1000}shepardsbind_recv\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string94 = /.{0,1000}shepbind_serv\.exe.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string95 = /.{0,1000}sherlock\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string96 = /.{0,1000}SluiEOP\.ps1.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string97 = /.{0,1000}turn_keylogger.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string98 = /.{0,1000}vbs\-obfuscator\.py.{0,1000}/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string99 = /.{0,1000}wifi_dump_linux.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
