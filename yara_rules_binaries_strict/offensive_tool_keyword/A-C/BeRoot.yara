rule BeRoot
{
    meta:
        description = "Detection patterns for the tool 'BeRoot' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BeRoot"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string1 = /\sbeRoot\.exe/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string2 = /\sbeRoot\.py/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string3 = /\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sGet\sSystem\sPriv\swith\sWebClient\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string4 = /\/beRoot\.exe/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string5 = /\/BeRoot\.git/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string6 = /\/beRoot\.py/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string7 = /\/beRoot\.zip/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string8 = /\/BeRoot\/Linux\// nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string9 = /\/beroot\/modules\/.{0,100}\.py/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string10 = /\/gtfobins\.py/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string11 = /\\beRoot\.exe/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string12 = /\\beRoot\.zip/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string13 = /\\beroot\\modules\\.{0,100}\.py/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string14 = /\\DLL_Hijacking\./ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string15 = /52B0FF57\-7E0A\-4CA9\-84D4\-58DFA2456BA5/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string16 = /AlessandroZ\/BeRoot/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string17 = /beRoot\.exe\s\-/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string18 = /beroot\.py\s\-/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string19 = /BeRoot\-master/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string20 = /from\s\.modules\.exploit\simport\sExploit/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string21 = /from\s\.secretsdump\simport\sRemoteOperations/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string22 = /Getting\spermissions\sof\ssensitive\sfiles\./ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string23 = /import\scheck_currrent_user_privilege/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string24 = /import\scheck_sudoers_misconfigurations/ nocase ascii wide
        // Description: Privilege Escalation Project - Windows / Linux / Mac 
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string25 = /linux\-exploit\-suggester/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string26 = /modules\.gtfobins\simport\sGTFOBins/ nocase ascii wide
        // Description: BeRoot Project is a post exploitation tool to check common misconfigurations to find a way to escalate our privilege.
        // Reference: https://github.com/AlessandroZ/BeRoot
        $string27 = /modules\.interesting_files\simport\sInterestingFiles/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
