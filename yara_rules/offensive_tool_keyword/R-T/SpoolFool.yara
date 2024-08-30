rule SpoolFool
{
    meta:
        description = "Detection patterns for the tool 'SpoolFool' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SpoolFool"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string1 = /\s\-dll\sadd_user\.dll\s\-dir\s/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string2 = /\s\-dll\sadd_user\.dll\s\-printer\s/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string3 = /\sSpoolFool\.ps1/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string4 = /\/SpoolFool\.exe/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string5 = /\/SpoolFool\.git/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string6 = /\/SpoolFool\.ps1/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string7 = /\[\+\]\sSuccessfully\sset\sthe\sspool\sdirectory\sto\:\s/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string8 = /\\AddUser\.dll/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string9 = /\\AddUser\.sln/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string10 = /\\Release\\SpoolFool\.pdb/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string11 = /\\SpoolFool\.exe/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string12 = /\\SpoolFool\.ps1/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string13 = /\\SpoolFool\.sln/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string14 = /\\SpoolFool\-main/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string15 = /\]\sGranting\sread\sand\sexecute\sto\sSYSTEM\son\sDLL\:\s/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string16 = /11a92a7c6a84715416eb8a1c033a6a8db9a70494bfc08c9f09734e599be76cef/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string17 = /4c7714ee\-c58d\-4ef7\-98f2\-b162baec0ee0/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string18 = /4f715f37eddadb3d8f5680f7075e695e99496b91473f17d4507568518dd4284d/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string19 = /50388787c5a5da5c25ca1f6bfdaf3f09c3c78d9f0306e87b7e7d191bf679d870/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string20 = /69ab4c2375c28b0520090c3ce7c3f033d5429aee8a0ef2f7b5f54edee2a759b7/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string21 = /7cd4a538c3d1242ede7dcbea8dfdba84031e232e4327ed3c89292714032da91c/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string22 = /b979225195d70240e32deae75233b82e05ceb32bab4d08d970399065fba8ea88/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string23 = /c0a7a797f39b509fd2d895b5731e79b57b350b85b20be5a51c0a1bda19321bd0/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string24 = /e347df6964e8d7ac73e12d28773f260a80109fb1049bc106ae90800381927cee/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string25 = /EC49A1B1\-4DAA\-47B1\-90D1\-787D44C641C0/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string26 = /Invoke\-SpoolFool/ nocase ascii wide
        // Description: Exploit for CVE-2022-21999 - Windows Print Spooler Elevation of Privilege Vulnerability (LPE)
        // Reference: https://github.com/ly4k/SpoolFool
        $string27 = /ly4k\/SpoolFool/ nocase ascii wide

    condition:
        any of them
}
