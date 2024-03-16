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
        $string1 = /\skimi\.py\s/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string2 = /\s\-NoPRo\s\-wIN\s1\s\-nONi\s\-eN\sSh33L/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string3 = /\/\/Lh0St\/InJ3C/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string4 = /\/\/RRh0St\/InJ3C/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string5 = /\/avet_fabric\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string6 = /\/evil_pdf\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string7 = /\/exec_bin\.c/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string8 = /\/exec_dll\.c/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string9 = /\/exec_psh\.c/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string10 = /\/exec0\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string11 = /\/GetBrowsers\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string12 = /\/hta_attack\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string13 = /\/kimi\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string14 = /\/NewPhish\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string15 = /\/persistence2\.rc/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string16 = /\/phishing\/.{0,1000}\.html/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string17 = /\/powerglot\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string18 = /\/ps2exe\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string19 = /\/r00t\-3xp10it/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string20 = /\/Rat_Generator/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string21 = /\/shellcode_samples\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string22 = /\/venom\.git/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string23 = /\/venom\.sh\s/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string24 = /\\bin\\shepard\\/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string25 = /\\BrowserEnum\.log/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string26 = /\\CredsPhish\.log/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string27 = /\\evil_pdf\\/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string28 = /\\GetBrowsers\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string29 = /\\NewPhish\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string30 = /\\powerglot\\/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string31 = /\\ps2exe\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string32 = /\\PS2EXE\\.{0,1000}\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string33 = /\\shellcode_samples\\/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string34 = /\\SillyRAT\\.{0,1000}\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string35 = /0evilpwfilter/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string36 = /0evilpwfilter\.dll/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string37 = /aux\/dump_credentials/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string38 = /aux\/enum_system\.rc/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string39 = /aux\/msf\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string40 = /aux\/persistence\.rc/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string41 = /aux\/privilege_escalation\./ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string42 = /aux\/Start\-Webserver\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string43 = /bin\/.{0,1000}\/PS2EXE\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string44 = /bin\/icmpsh\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string45 = /bin\/SillyRAT\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string46 = /bin\/void\.zip/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string47 = /bin\\SillyRAT/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string48 = /bin\\void\.zip/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string49 = /CarbonCopy\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string50 = /ChaitanyaHaritash\/kimi/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string51 = /CommandCam\.exe/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string52 = /CredsPhish\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string53 = /DarkRCovery\.exe/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string54 = /dll_hijack_detect_x64/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string55 = /dll_hijack_detect_x86/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string56 = /encodeScriptPolyglot/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string57 = /enigma_fileless_uac_bypass/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string58 = /exploit_suggester\./ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string59 = /firefox\/FakeUpdate_files\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string60 = /hta\-to\-javascript\-crypter/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string61 = /http\:\/\/LhOsT\/FiLNaMe\./ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string62 = /import\sImpactDecoder/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string63 = /import\sImpactPacket/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string64 = /install_winrar_wine32\.exe/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string65 = /install_winrar_wine64\./ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string66 = /InvokeMeter\.bat/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string67 = /Invoke\-Phant0m/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string68 = /InvokePS1\.bat/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string69 = /Invoke\-Shellcode/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string70 = /keylooger\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string71 = /kimi_MDPC\/kimi\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string72 = /linux_hostrecon/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string73 = /linux_hostrecon\./ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string74 = /make_avet\s\-l\s.{0,1000}\.exe\s/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string75 = /make_avetsvc\s/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string76 = /Meterpreter\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string77 = /meterpreter_loader/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string78 = /METERPRETER_STAGER/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string79 = /mimiRatz/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string80 = /mozlz4\-win32\.exe/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string81 = /msf\-auxiliarys/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string82 = /obfuscate\/shellter/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string83 = /perl\-reverse\-shell\./ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string84 = /PEScrambler\.exe/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string85 = /POST_EXPLOIT_DIR/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string86 = /powerglot\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string87 = /pyherion\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string88 = /rapid7\.github\.io\/metasploit\-framework\/api\// nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string89 = /reshacker_setup\.exe/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string90 = /SHELLCODE\sGENERATOR/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string91 = /shellter\.exe/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string92 = /shepardsbind_recv\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string93 = /shepbind_serv\.exe/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string94 = /sherlock\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string95 = /SluiEOP\.ps1/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string96 = /turn_keylogger/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string97 = /vbs\-obfuscator\.py/ nocase ascii wide
        // Description: venom - C2 shellcode generator/compiler/handler
        // Reference: https://github.com/r00t-3xp10it/venom
        $string98 = /wifi_dump_linux/ nocase ascii wide

    condition:
        any of them
}
