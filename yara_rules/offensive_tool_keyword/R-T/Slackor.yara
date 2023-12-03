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
        $string1 = /.{0,1000}\sC:\\Users\\Public\\build\.bat.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string2 = /.{0,1000}\sC:\\Users\\Public\\build\.vbs.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string3 = /.{0,1000}\sC:\\Users\\Public\\DtcInstall\.txt.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string4 = /.{0,1000}\sSet\-MpPreference\s\-DisableIOAVProtection\s.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string5 = /.{0,1000}\/common\/beacon\.go.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string6 = /.{0,1000}\/defanger\.go.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string7 = /.{0,1000}\/keyscan\.go.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string8 = /.{0,1000}\/minidump\.go.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string9 = /.{0,1000}\/samdump\.go.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string10 = /.{0,1000}\/Slackor\.git.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string11 = /.{0,1000}\/Slackor\/.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string12 = /.{0,1000}\/SpookFlare\.git.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string13 = /.{0,1000}4\.5\.6\.7:1337.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string14 = /.{0,1000}appdata.{0,1000}\\Windows:svchost\.exe.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string15 = /.{0,1000}appdata.{0,1000}\\Windows:winrm\.vbs.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string16 = /.{0,1000}bypassuac\sfodhelper.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string17 = /.{0,1000}C:\\Users\\Public\\.{0,1000}\.dmp.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string18 = /.{0,1000}Coalfire\-Research\/Slackor.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string19 = /.{0,1000}defanger\sexclusion.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string20 = /.{0,1000}defanger\srealtime.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string21 = /.{0,1000}defanger\ssignature.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string22 = /.{0,1000}dist\/agent\.upx\.exe.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string23 = /.{0,1000}dist\/agent\.windows\.exe.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string24 = /.{0,1000}do_pyinject.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string25 = /.{0,1000}keyscan\sdump.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string26 = /.{0,1000}keyscan\sstart.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string27 = /.{0,1000}keyscan\sstop.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string28 = /.{0,1000}lsassdump\.dmp.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string29 = /.{0,1000}metasploit\.go.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string30 = /.{0,1000}n00py\/Slackor.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string31 = /.{0,1000}powershell\s.{0,1000}C:\\Users\\Public\\.{0,1000}\.exe.{0,1000}\sforfiles\.exe\s\/p\s.{0,1000}\\system32\s.{0,1000}\.exe.{0,1000}.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string32 = /.{0,1000}pypykatzClass.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string33 = /.{0,1000}pypykatzfile.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string34 = /.{0,1000}reg\.exe\ssave\sHKLM\\SAM\ssam_.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string35 = /.{0,1000}reg\.exe\ssave\sHKLM\\SECURITY\ssecurity_.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string36 = /.{0,1000}reg\.exe\ssave\sHKLM\\SYSTEM\ssys.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string37 = /.{0,1000}slackor\.db.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string38 = /.{0,1000}spookflare\.py.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
