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
        $string1 = /.{0,1000}\/HWSyscalls\.cpp.{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string2 = /.{0,1000}\/NtRemoteLoad\.exe.{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string3 = /.{0,1000}\/NtRemoteLoad\.git.{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string4 = /.{0,1000}\\donut\\VanillaProgram\.bin.{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string5 = /.{0,1000}\\HWSyscalls\.cpp.{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string6 = /.{0,1000}\\HWSyscalls\-Example\..{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string7 = /.{0,1000}\\NtRemoteLoad\.exe.{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string8 = /.{0,1000}\\NtRemoteLoad\.sln.{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string9 = /.{0,1000}40B05F26\-6A2F\-40BC\-88DE\-F40D4BC77FB0.{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string10 = /.{0,1000}florylsk\/NtRemoteLoad.{0,1000}/ nocase ascii wide
        // Description: Remote Shellcode Injector
        // Reference: https://github.com/florylsk/NtRemoteLoad
        $string11 = /.{0,1000}NtRemoteLoad\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
