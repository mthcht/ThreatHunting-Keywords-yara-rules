rule Jomungand
{
    meta:
        description = "Detection patterns for the tool 'Jomungand' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Jomungand"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string1 = /\-\-\-\-\-\sLOADLIBRARYA\sHOOK\s\-\-\-\-\-/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string2 = /\-\-\-\-\-\sSLEEP\sHOOK\s\-\-\-\-\-/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string3 = /\-\-\-\-\-\sVIRTUALALLOC\sHOOK\s\-\-\-\-\-/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string4 = /\/Jomungand\.git/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string5 = /\/Jormungand\.sln/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string6 = /\[\!\]\sCan\'t\sremove\sthe\sHWBP\-Hook\sfor\sVirtualAlloc\s\!/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string7 = /\\Jormungand\.sln/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string8 = /88B40068\-B3DB\-4C2F\-86F9\-8EADC52CFE58/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string9 = /Jomungand\\vstudio\-project/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string10 = /Jomungand\-main/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string11 = /Jormungand\.exe/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string12 = /Jormungand\.vcxproj/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string13 = /Redirect\sLoadLibraryA\sto\sLdrLoadDll\swith\sspoofed\sret\saddr\s\!/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string14 = /RtlDallas\/Jomungand/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string15 = /Sleep\sfor\s.{0,1000}\sms.{0,1000}\sredirect\sto\sKrakenMask\s\!/ nocase ascii wide

    condition:
        any of them
}
