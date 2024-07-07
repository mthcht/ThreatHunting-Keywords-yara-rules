rule Powerlurk
{
    meta:
        description = "Detection patterns for the tool 'Powerlurk' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Powerlurk"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string1 = /\sAdd\-KeeThiefLurker\.ps1/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string2 = /\s\-EventName\sKeeThief\s\-WMI/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string3 = /\s\-EventName\sWmiBackdoor\s\-PermanentCommand\s/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string4 = /\sPowerLurk\.ps1/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string5 = /\/Add\-KeeThiefLurker\.ps1/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string6 = /\/PowerLurk\.git/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string7 = /\/PowerLurk\.ps1/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string8 = /\\Add\-KeeThiefLurker\.ps1/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string9 = /\\PowerLurk\.ps1/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string10 = /\\PowerLurk\-main/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string11 = /238111f4c27f2bad38c5b5eac85aacf4305baaa7c854911e3cbffe7a58cc9964/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string12 = /7b0HYBxJliUmL23Ke39K9UrX4HShCIBgEyTYkEAQ7MGIzeaS7B1pRyMpqyqBymVWZV1mFkDM7Z28995777333nvvvfe6O51OJ/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string13 = /81c3f4341d0cecc16beaae19c88e54dda2730a4eaf06cc0fea0119822d7482c3/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string14 = /Add\-KeeThiefLurker\s/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string15 = /Find\-KeePassconfig\s/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string16 = /function\sFind\-KeePassconfig/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string17 = /function\sLocal\:Get\-KeePassINIFields/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string18 = /Get\-KeePassDatabaseKey\s/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string19 = /Register\-MaliciousWmiEvent/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string20 = /Registry\sKeeTheifLurker\s.{0,1000}\sCreated/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string21 = /Remove\-KeeThiefLurker\s/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string22 = /Remove\-TemplateLurker\s\-EventName\s/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string23 = /Sw4mpf0x\/PowerLurk/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string24 = /WMI\sKeeTheifLurker\s/ nocase ascii wide
        // Description: PowerLurk is a PowerShell toolset for building malicious WMI Event Subsriptions
        // Reference: https://github.com/Sw4mpf0x/PowerLurk
        $string25 = /WMI\sKeeTheifLurker\s.{0,1000}\sCreated/ nocase ascii wide

    condition:
        any of them
}
