rule quarkspwdump
{
    meta:
        description = "Detection patterns for the tool 'quarkspwdump' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "quarkspwdump"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string1 = " --dump-bitlocker " nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string2 = " --dump-bitlocker" nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string3 = " --dump-hash-domain --with-history" nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string4 = " --dump-hash-domain" nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string5 = " --dump-hash-domain-cached" nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string6 = " --dump-hash-domain-cached" nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string7 = " --dump-hash-local" nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string8 = " --ntds-file " nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string9 = /\/quarkspwdump\.git/ nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string10 = /\/quarkspwdump\.git/ nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string11 = /\[\+\]\sLSAKEY\(s\)\sretrieving/ nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string12 = /\[\+\]\sParsing\sSAM\sregistry\shive/ nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string13 = /\[\+\]\sParsing\sSAM\sregistry\shive/ nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string14 = /\[\+\]\sParsing\sSECURITY\sregistry\shive/ nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string15 = /\[\+\]\sParsing\sSECURITY\sregistry\shive/ nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string16 = /\[\+\]\sSYSKEY\srestrieving/ nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string17 = /\[\+\]\sSYSKEY\srestrieving/ nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string18 = /\\QuarksADDumper\./ nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string19 = /\\QuarksPwDump/ nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string20 = /\\QUARKS\-SAM/ nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string21 = /\\SAM\-.{0,1000}\.dmp/ nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string22 = /\\SAM\-.{0,1000}\.dmp\.LOG/ nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string23 = "07a00b5f4f4d8fd3328b5454dc101d4e76126d9e2600ca2d6fd677452bf624d7" nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string24 = "07a00b5f4f4d8fd3328b5454dc101d4e76126d9e2600ca2d6fd677452bf624d7" nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string25 = /ATT_BITLOCKER_MSFVE_RECOVERY_PASSWORD.{0,1000}ATTm591788/ nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string26 = /azizjon\.m\@gmail\.com/ nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string27 = "d14884d8a7f74e96a4450e1b1e65636b3a2810274963e4a6eb28e161effe1216" nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string28 = "d14884d8a7f74e96a4450e1b1e65636b3a2810274963e4a6eb28e161effe1216" nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string29 = /\-\-dump\-bitlocker.{0,1000}\-\-ntds\-file\s/ nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string30 = "E0362605-CC11-4CD5-AFF7-B50934438658" nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string31 = "E0362605-CC11-4CD5-AFF7-B50934438658" nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string32 = "No cached domain password found!" nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string33 = "peterdocter/quarkspwdump" nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string34 = "QuarksADDumper" nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string35 = "quarkslab/quarkspwdump" nocase ascii wide
        // Description: Quarks PwDump is a native Win32 tool to extract credentials from Windows operating systems
        // Reference: https://github.com/peterdocter/quarkspwdump
        $string36 = /quarks\-pwdump\.exe/ nocase ascii wide
        // Description: Dump various types of Windows credentials without injecting in any process
        // Reference: https://github.com/quarkslab/quarkspwdump
        $string37 = /quarks\-pwdump\.exe/ nocase ascii wide

    condition:
        any of them
}
