rule FakeAMSI
{
    meta:
        description = "Detection patterns for the tool 'FakeAMSI' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "FakeAMSI"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Technically. AMSI is a set of DLLs being asked for a buffer evaluation (saying it's safe/unsafe). It means. processes (such as powershell.exe) load such DLLs when want to use AMSI. And it sounds like perfect opportunity to misuse such DLL as a method of persistence
        // Reference: https://github.com/gtworek/PSBits/tree/master/FakeAMSI
        $string1 = /FakeAMSI\.c/ nocase ascii wide
        // Description: Technically. AMSI is a set of DLLs being asked for a buffer evaluation (saying it's safe/unsafe). It means. processes (such as powershell.exe) load such DLLs when want to use AMSI. And it sounds like perfect opportunity to misuse such DLL as a method of persistence
        // Reference: https://github.com/gtworek/PSBits/tree/master/FakeAMSI
        $string2 = /FakeAMSI\.dll/ nocase ascii wide
        // Description: Technically. AMSI is a set of DLLs being asked for a buffer evaluation (saying it's safe/unsafe). It means. processes (such as powershell.exe) load such DLLs when want to use AMSI. And it sounds like perfect opportunity to misuse such DLL as a method of persistence
        // Reference: https://github.com/gtworek/PSBits/tree/master/FakeAMSI
        $string3 = /FakeAMSI\.exe/ nocase ascii wide

    condition:
        any of them
}
