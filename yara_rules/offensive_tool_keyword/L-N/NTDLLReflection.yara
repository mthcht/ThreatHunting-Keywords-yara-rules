rule NTDLLReflection
{
    meta:
        description = "Detection patterns for the tool 'NTDLLReflection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "NTDLLReflection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string1 = /.{0,1000}\sNtCr3at3Thr3adEx\s\@\s.{0,1000}/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string2 = /.{0,1000}\/NTDLLReflection\.git.{0,1000}/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string3 = /.{0,1000}9D365106\-D7B8\-4B5E\-82CC\-6D6ABCDCA2B8.{0,1000}/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string4 = /.{0,1000}NTDLLReflection\-main.{0,1000}/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string5 = /.{0,1000}NtWa1tF0rS1ngle0bj3ct\sExecuted.{0,1000}/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string6 = /.{0,1000}ReflectiveNTDLL\.cpp.{0,1000}/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string7 = /.{0,1000}ReflectiveNTDLL\.exe.{0,1000}/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string8 = /.{0,1000}ReflectiveNTDLL\.sln.{0,1000}/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string9 = /.{0,1000}ReflectiveNTDLL\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string10 = /.{0,1000}TheD1rkMtr\/NTDLLReflection.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
