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
        $string1 = /.{0,1000}\-\-\-\-\-\sLOADLIBRARYA\sHOOK\s\-\-\-\-\-.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string2 = /.{0,1000}\-\-\-\-\-\sSLEEP\sHOOK\s\-\-\-\-\-.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string3 = /.{0,1000}\-\-\-\-\-\sVIRTUALALLOC\sHOOK\s\-\-\-\-\-.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string4 = /.{0,1000}\/Jomungand\.git.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string5 = /.{0,1000}\/Jormungand\.sln.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string6 = /.{0,1000}\[\!\]\sCan\'t\sremove\sthe\sHWBP\-Hook\sfor\sVirtualAlloc\s\!.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string7 = /.{0,1000}\\Jormungand\.sln.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string8 = /.{0,1000}88B40068\-B3DB\-4C2F\-86F9\-8EADC52CFE58.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string9 = /.{0,1000}Jomungand\\vstudio\-project.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string10 = /.{0,1000}Jomungand\-main.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string11 = /.{0,1000}Jormungand\.exe.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string12 = /.{0,1000}Jormungand\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string13 = /.{0,1000}Redirect\sLoadLibraryA\sto\sLdrLoadDll\swith\sspoofed\sret\saddr\s\!.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string14 = /.{0,1000}RtlDallas\/Jomungand.{0,1000}/ nocase ascii wide
        // Description: Shellcode Loader with memory evasion
        // Reference: https://github.com/RtlDallas/Jomungand
        $string15 = /.{0,1000}Sleep\sfor\s.{0,1000}\sms.{0,1000}\sredirect\sto\sKrakenMask\s\!.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
