rule NtRemoteLoad
{
    meta:
        description = "Detection patterns for the tool 'NtRemoteLoad' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NtRemoteLoad"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string1 = /\/HWSyscalls\.cpp/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string2 = /\/NtRemoteLoad\.exe/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string3 = /\/NtRemoteLoad\.git/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string4 = /\\donut\\VanillaProgram\.bin/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string5 = /\\HWSyscalls\.cpp/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string6 = /\\HWSyscalls\-Example\./ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string7 = /\\NtRemoteLoad\.exe/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string8 = /\\NtRemoteLoad\.sln/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string9 = /40B05F26\-6A2F\-40BC\-88DE\-F40D4BC77FB0/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string10 = /florylsk\/NtRemoteLoad/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string11 = /NtRemoteLoad\-main/ nocase ascii wide

    condition:
        any of them
}
