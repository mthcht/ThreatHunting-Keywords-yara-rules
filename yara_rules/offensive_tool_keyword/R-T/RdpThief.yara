rule RdpThief
{
    meta:
        description = "Detection patterns for the tool 'RdpThief' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RdpThief"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RdpThief by itself is a standalone DLL that when injected in the mstsc.exe process. will perform API hooking. extract the clear-text credentials and save them to a file. An aggressor script accompanies it. which is responsible for managing the state. monitoring for new processes and injecting the shellcode in mstsc.exe. The DLL has been converted to shellcode using the sRDI project (https://github.com/monoxgas/sRDI). When enabled. RdpThief will get the process list every 5 seconds. search for mstsc.exe. and inject to it
        // Reference: https://github.com/0x09AL/RdpThief
        $string1 = /.{0,1000}RdpThief.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
