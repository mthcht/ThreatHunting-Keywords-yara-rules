rule PEASS
{
    meta:
        description = "Detection patterns for the tool 'PEASS' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PEASS"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string1 = " import LinpeasBaseBuilder" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string2 = " import LinpeasBuilder" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string3 = " import PEASLoaded" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string4 = " import PEASRecord" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string5 = /\slinpeas\.sh\s/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string6 = " -linpeas=http://" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string7 = /\s\-linpeas\=http\:\/\/127\.0\.0\.1\/linpeas\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string8 = " WinPEAS - Windows local Privilege Escalation Awesome Script" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string9 = /\/linpeas\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string10 = /\/linpeas\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string11 = /\/linpeas\.txt/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string12 = /\/linpeasBaseBuilder\.py/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string13 = /\/linpeasBuilder\.py/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string14 = /\/PEASS\-ng\.git/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string15 = "/PEASS-ng/" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string16 = /\[\+\]\sBuilding\sGTFOBins\slists/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string17 = /\[\+\]\sBuilding\slinux\sexploit\ssuggesters/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string18 = /\[\+\]\sDownloading\sFat\sLinpeas\sbinaries/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string19 = /\\PEASS\-ng/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string20 = /\\winPEAS\.sln/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string21 = /\\winPEASexe\\/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string22 = "66AA4619-4D0F-4226-9D96-298870E9BB50" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string23 = "builder/linpeas_parts/" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string24 = "D934058E-A7DB-493F-A741-AE8E3DF867F4" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string25 = /gather\/peass\.rb/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string26 = /linpeas_builder\.py/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string27 = "linpeas_darwin_amd64" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string28 = "linpeas_darwin_arm64" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string29 = /linpeas_fat\.sh/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string30 = "linpeas_linux_386" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string31 = "linpeas_linux_amd64" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string32 = "linpeas_linux_arm64" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string33 = /metasploit\/peass\.rb/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string34 = "PEASS-ng-master" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string35 = /winPEAS\.bat/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string36 = /WinPEAS\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string37 = /winPEAS\.ps1/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string38 = /winPEASany\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string39 = /winPEASany_ofs\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string40 = "winPEAS-Obfuscated" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string41 = "winPEASps1" nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string42 = /winPEASx64\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string43 = /winPEASx64_ofs\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string44 = /winPEASx86\.exe/ nocase ascii wide
        // Description: PEASS - Privilege Escalation Awesome Scripts SUITE
        // Reference: https://github.com/carlospolop/PEASS-ng
        $string45 = /winPEASx86_ofs\.exe/ nocase ascii wide
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
