rule mhydeath
{
    meta:
        description = "Detection patterns for the tool 'mhydeath' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mhydeath"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string1 = /\/mhydeath\.git/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string2 = /\/mhydeath\.sln/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string3 = /\/mhydeath\/main\.cpp/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string4 = /\/process_killer\.cpp/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string5 = /\\mhydeath64/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string6 = /\\process_killer\.cpp/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string7 = /0D17A4B4\-A7C4\-49C0\-99E3\-B856F9F3B271/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string8 = /mhydeath\.exe/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string9 = /mhydeath\-master/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string10 = /process_killer\.exe/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string11 = /zer0condition\/mhydeath/ nocase ascii wide

    condition:
        any of them
}
