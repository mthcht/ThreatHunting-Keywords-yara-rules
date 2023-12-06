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
        $string1 = /\sC:\\Users\\Public\\build\.bat/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string2 = /\sC:\\Users\\Public\\build\.vbs/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string3 = /\sC:\\Users\\Public\\DtcInstall\.txt/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string4 = /\sSet\-MpPreference\s\-DisableIOAVProtection\s/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string5 = /\/common\/beacon\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string6 = /\/defanger\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string7 = /\/keyscan\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string8 = /\/minidump\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string9 = /\/samdump\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string10 = /\/Slackor\.git/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string11 = /\/Slackor\// nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string12 = /\/SpookFlare\.git/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string13 = /4\.5\.6\.7:1337/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string14 = /appdata.{0,1000}\\Windows:svchost\.exe/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string15 = /appdata.{0,1000}\\Windows:winrm\.vbs/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string16 = /bypassuac\sfodhelper/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string17 = /C:\\Users\\Public\\.{0,1000}\.dmp/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string18 = /Coalfire\-Research\/Slackor/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string19 = /defanger\sexclusion/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string20 = /defanger\srealtime/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string21 = /defanger\ssignature/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string22 = /dist\/agent\.upx\.exe/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string23 = /dist\/agent\.windows\.exe/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string24 = /do_pyinject/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string25 = /keyscan\sdump/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string26 = /keyscan\sstart/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string27 = /keyscan\sstop/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string28 = /lsassdump\.dmp/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string29 = /metasploit\.go/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string30 = /n00py\/Slackor/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string31 = /powershell\s.{0,1000}C:\\Users\\Public\\.{0,1000}\.exe.{0,1000}\sforfiles\.exe\s\/p\s.{0,1000}\\system32\s.{0,1000}\.exe.{0,1000}/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string32 = /pypykatzClass/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string33 = /pypykatzfile/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string34 = /reg\.exe\ssave\sHKLM\\SAM\ssam_/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string35 = /reg\.exe\ssave\sHKLM\\SECURITY\ssecurity_/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string36 = /reg\.exe\ssave\sHKLM\\SYSTEM\ssys/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string37 = /slackor\.db/ nocase ascii wide
        // Description: A Golang implant that uses Slack as a command and control server
        // Reference: https://github.com/Coalfire-Research/Slackor
        $string38 = /spookflare\.py/ nocase ascii wide

    condition:
        any of them
}
