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
        $string1 = /.{0,1000}\/mhydeath\.git.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string2 = /.{0,1000}\/mhydeath\.sln.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string3 = /.{0,1000}\/mhydeath\/main\.cpp.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string4 = /.{0,1000}\/process_killer\.cpp.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string5 = /.{0,1000}\\mhydeath64.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string6 = /.{0,1000}\\process_killer\.cpp.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string7 = /.{0,1000}0D17A4B4\-A7C4\-49C0\-99E3\-B856F9F3B271.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string8 = /.{0,1000}mhydeath\.exe.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string9 = /.{0,1000}mhydeath\-master.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string10 = /.{0,1000}process_killer\.exe.{0,1000}/ nocase ascii wide
        // Description: Abusing mhyprotect to kill AVs / EDRs / XDRs / Protected Processes.
        // Reference: https://github.com/zer0condition/mhydeath
        $string11 = /.{0,1000}zer0condition\/mhydeath.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
