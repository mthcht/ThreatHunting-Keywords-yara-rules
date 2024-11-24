rule Disable_TamperProtection
{
    meta:
        description = "Detection patterns for the tool 'Disable-TamperProtection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Disable-TamperProtection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string1 = " /v DisableAntiSpyware /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string2 = " /v DisableBehaviorMonitoring /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string3 = " /v DisableIOAVProtection /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string4 = " /v DisableOnAccessProtection /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string5 = " /v DisableScanOnRealtimeEnable /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string6 = /\/Disable\-TamperProtection\.git/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string7 = "/v DisableAntiSpyware /t REG_DWORD /d 1 /f" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string8 = /\[\+\]\sWdFilter\sAltitude\sRegistry\skey\shas\sbeen\ssuccessfully\sdeleted/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string9 = /\\Disable\-TamperProtection\\/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string10 = "AlteredSecurity/Disable-TamperProtection" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string11 = "cb0b0fa30345d487f99dce16cb07ef0094938dbf7eedfe48e2a0ad7f2973a7bb" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string12 = /Disable\-TamperProtection\.cpp/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string13 = /Disable\-TamperProtection\.exe/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string14 = "E192C3DF-AE34-4E32-96BA-3D6B56EA76A4" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string15 = /reg\.exe\sadd\s\\\\"HKLM\\\\SOFTWARE\\\\Microsoft\\\\Windows\sDefender\\\\Features\\\\"\s\/v\sTamperProtection\s\/t\sREG_DWORD\s\/d\s4\s\/f/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string16 = /reg\.exe\sdelete\s.{0,1000}HKLM\\\\SYSTEM\\\\CurrentControlSet\\\\Services\\\\WdFilter\\\\Instances\\\\WdFilter\sInstance.{0,1000}\s\/v\sAltitude\s\/f/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string17 = /reg\.exe\sdelete\s.{0,1000}HKLM\\SYSTEM\\CurrentControlSet\\Services\\WdFilter\\Instances\\WdFilter\sInstance.{0,1000}\s\/v\sAltitude\s\/f/ nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string18 = "Spawning registry with TrustedInstaller privileges to delete WdFilter " nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string19 = "Spawning registry with TrustedInstaller privileges to Disable 'DisableIOAVProtection' regkey" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string20 = "Spawning registry with TrustedInstaller privileges to Disable 'RealtimeMonitoring' regkey" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string21 = "Spawning registry with TrustedInstaller privileges to Enable 'TamperProtection' regkey" nocase ascii wide
        // Description: disable TamperProtection and other Defender / MDE components
        // Reference: https://github.com/AlteredSecurity/Disable-TamperProtection
        $string22 = /WDFilter\shas\sbeen\ssuccessfully\sunloaded\,\suse\soption\s2\sto\sdisable\sTamper\sProtection\./ nocase ascii wide

    condition:
        any of them
}
