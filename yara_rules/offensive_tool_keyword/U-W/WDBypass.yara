rule WDBypass
{
    meta:
        description = "Detection patterns for the tool 'WDBypass' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "WDBypass"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // Reference: https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $string1 = /\"Starting\sElevating\sto\sSYSTEM\"/ nocase ascii wide
        // Description: Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // Reference: https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $string2 = /\"Starting\sWD\sDisable\"/ nocase ascii wide
        // Description: Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // Reference: https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $string3 = /\\DisableWD\.7z/ nocase ascii wide
        // Description: Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // Reference: https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $string4 = /\\Silent\.7z/ nocase ascii wide
        // Description: Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // Reference: https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $string5 = /A220F564\-41CB\-46F5\-9938\-FEFD87819771/ nocase ascii wide
        // Description: Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // Reference: https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $string6 = /F1E836C1\-2279\-49B3\-84CC\-ED8B048FCC44/ nocase ascii wide
        // Description: Disable Windows Defender (+ UAC Bypass, + Upgrade to SYSTEM)
        // Reference: https://bitbucket.org/evilgreyswork/wd-uac/downloads/
        $string7 = /https\:\/\/bitbucket\.org\/evilgreyswork\// nocase ascii wide

    condition:
        any of them
}
