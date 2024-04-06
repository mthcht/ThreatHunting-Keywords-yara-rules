rule Slackor
{
    meta:
        description = "Detection patterns for the tool 'Slackor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Slackor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string1 = /\sC\:\\Users\\Public\\build\.bat/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string2 = /\sC\:\\Users\\Public\\build\.vbs/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string3 = /\sC\:\\Users\\Public\\DtcInstall\.txt/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string4 = /\sgoldenPac\.py\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string5 = /\sgoldenPac\.py\s\-c\s.{0,1000}\.exe/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string6 = /\spython\sgoldenPac\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string7 = /\s\-RemoveDefinitions\s\-All\sSet\-MpPreference\s\-DisableIOAVProtection\s\$true/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string8 = /\sSet\-MpPreference\s\-DisableIOAVProtection\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string9 = /\%APPDATA\%\\Windows\:winrm\.vbs/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string10 = /\.EXE\sMeterpreter\sReverse\sHTTP\sand\sHTTPS\sloader/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string11 = /\.HTA\sloader\swith\s\.HTML\sextension\sfor\sspecific\scommand/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string12 = /\/common\/beacon\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string13 = /\/defanger\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string14 = /\/keyscan\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string15 = /\/metasploit\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string16 = /\/minidump\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string17 = /\/samdump\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string18 = /\/Slackor\.git/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string19 = /\/Slackor\.git/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string20 = /\/Slackor\// nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string21 = /\/SpookFlare\.git/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string22 = /\\metasploit\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string23 = /\\Users\\Public\\DtcInstall\.txt/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string24 = /029558a5c334d67b479885be83f0e0dc856189d1de14ad1d4136b7d451498daa/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string25 = /19f900f1332f1cb5895c079d90c982f7eae6cb67f989116a3cbba5101fbbe9b1/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string26 = /21f7c3a31ac72448d1e1aa4624672d7c3f7644fe7598ff109f2f87fd8de48cd7/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string27 = /23c71cff513e2be636c1084f3c8646f9601eef18b83a8010c84e824e5fd9ffba/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string28 = /3cc61a5e594a228e108fdbfb991ac45838ad15bf632f112cc185c356889e322d/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string29 = /4\.5\.6\.7\:1337/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string30 = /5013e8763027aeb90e09aa70c4d29f548facb761f6c6ba6a43fe4d9ca9d58a71/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string31 = /535656aca26402527106fc7630aa58d64544975120b7ad1e21b91797b38db760/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string32 = /5872afc30ecad98baad85351941c0f0d573fed08d224d038138b7dac77ba6ea1/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string33 = /5d3f3909639924fe921e0ff58be252bd671db7d2c2c0cf56d301f4ea48548306/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string34 = /64d2905609b4275f692466d0aacdd3f9c7da7860e9ed6dd7047e6dbcec851d99/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string35 = /65e2792774eff8fec2ccb9280300fca6f465c06df13c4bcebb553b18c4aafc2b/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string36 = /74ae919aa5d393c04fd5b2a8048b8df764e871f1e652099d50c5ea63fb06a2e1/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string37 = /77b1042ad03c451d66b967673277d153869dafec091c3b43167c309722af44db/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string38 = /81b115a9e1d6c8333dbac2759eadbd56badd489ecc04eadff97217671d789776/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string39 = /86dc38ec63d7ddfab38fe655ac2296f328b1fcf43a070bad92cb6c1d3d721d49/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string40 = /9521c213fdd6e0b58f1288a67dbbc2b178233e2d46d09feb8da1727520340d48/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string41 = /aa3a685af2d72ed748f21a0190d6d08e226f717c8eea6b5694c2ad74a331a285/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string42 = /appdata.{0,1000}\\Windows\:svchost\.exe/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string43 = /appdata.{0,1000}\\Windows\:winrm\.vbs/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string44 = /Attacking\sdomain\scontroller\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string45 = /Brute\sforcing\sSIDs\sat\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string46 = /bypassuac\sfodhelper/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string47 = /C\:\\ASEC\.log/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string48 = /C\:\\Users\\Public\\.{0,1000}\.dmp/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string49 = /c2NodGFza3MgL2NyZWF0ZSAvdG4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC90ciAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMiIC9zYyBEQUlMWQ/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string50 = /c2NodGFza3MgL2NyZWF0ZSAvdG4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC90ciAid3NjcmlwdCAlQVBQREFUQSVcV2luZG93czp3aW5ybS52YnMiIC9zYyBPTlNUQVJUIC9ydSBzeXN0ZW0/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string51 = /c2NodGFza3MgL2RlbGV0ZSAvVE4gIk9uZURyaXZlIFN0YW5kYWxvbmUgVXBkYXRlIFRhc2siIC9m/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string52 = /c4209649986c6f8b14571e8f08553cd89046c45a1a03d1ab1b69b03d4b745eb9/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string53 = /c9a56e555aa154cca1e25d511e2201cc522307ca09b54346860d375447ec7929/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string54 = /cdd1184f3b6ee040bb0f668cb15a4691d327009942857bd0c62b11cd0e3d0f50/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string55 = /Coalfire\-Research\/Slackor/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string56 = /Coalfire\-Research\/Slackor/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string57 = /Could\snot\sparse\s\.dmp\sfile\swith\spypykatz/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string58 = /defanger\sexclusion/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string59 = /defanger\srealtime/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string60 = /defanger\ssignature/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string61 = /dist\/agent\.upx\.exe/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string62 = /dist\/agent\.windows\.exe/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string63 = /do_metasploit\(/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string64 = /do_pyinject/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string65 = /Done\sdumping\sSAM\shashes\sfor\shost\:\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string66 = /e6e37edd595cc04216682cda2af0ef0d0580fd3c8c808fb65df547c432ee9a43/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string67 = /e954e3675ef895c2a316f74b5801d9966597c35bf728020add026fc9e56473e6/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string68 = /e984f5efade9dcf131cc020a3c3ebf27f7b191eede39b09969be4d36a1ba9fb2/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string69 = /fb808cc0dbbe0b6cd1a58631befb038483fc3043175232cf7d5f9a0d29b31895/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string70 = /fc62634b7cdf7a2397165512a48feafc25c2f1e80d7579dfca7e8a773c58a5c3/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string71 = /fe8a247e683cf8041cb460365a29793bacf26f8214b82a7b44d2f8fad3b0af12/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string72 = /ff5a3bf00aa5f5664da20030aaafd09333f2a75830d3e7df3666d8c9fea9eaaa/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string73 = /Hit\sSlack\sAPI\srate\slimit\s\!\!\!/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string74 = /\'https\:\/\/slack\.com\/api\/channels\.create\'/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string75 = /\-just\-dc\-user\snot\scompatible\sin\sLOCAL\smode/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string76 = /\-just\-dc\-user\sswitch\sis\snot\ssupported\sin\sVSS\smode/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string77 = /keyscan\sdump/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string78 = /keyscan\sstart/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string79 = /keyscan\sstop/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string80 = /lsassdump\.dmp/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string81 = /metasploit\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string82 = /n00py\/Slackor/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string83 = /Opening\sPSEXEC\sshell\sat\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string84 = /powershell\s.{0,1000}C\:\\Users\\Public\\.{0,1000}\.exe.{0,1000}\sforfiles\.exe\s\/p\s.{0,1000}\\system32\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string85 = /pypykatzClass/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string86 = /pypykatzfile/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string87 = /python\sraiseChild\.py\s\-/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string88 = /raiseChild\.py\s\-target\-exec\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string89 = /reg\.exe\ssave\sHKLM\\SAM\ssam_/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string90 = /reg\.exe\ssave\sHKLM\\SECURITY\ssecurity_/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string91 = /reg\.exe\ssave\sHKLM\\SYSTEM\ssys/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string92 = /Requesting\sS4U2Proxy/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string93 = /Requesting\sS4U2self/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string94 = /resuming\sa\sprevious\sNTDS\.DIT\sdump\ssession\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string95 = /SAM\shashes\sextraction\sfailed\:\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string96 = /samdump\(bearer\,\scommands/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string97 = /slackor\.db/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string98 = /Slackor\\impacket/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string99 = /spookflare\.py/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string100 = /ticketer\.py\s\-nthash\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string101 = /windows\/samdump\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string102 = /windows\\samdump\.go/ nocase ascii wide

    condition:
        any of them
}
