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
        $string1 = /\sNtCr3at3Thr3adEx\s\@\s/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string2 = /\/NTDLLReflection\.git/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string3 = /9D365106\-D7B8\-4B5E\-82CC\-6D6ABCDCA2B8/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string4 = /NTDLLReflection\-main/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string5 = /NtWa1tF0rS1ngle0bj3ct\sExecuted/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string6 = /ReflectiveNTDLL\.cpp/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string7 = /ReflectiveNTDLL\.exe/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string8 = /ReflectiveNTDLL\.sln/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string9 = /ReflectiveNTDLL\.vcxproj/ nocase ascii wide
        // Description: Bypass Userland EDR hooks by Loading Reflective Ntdll in memory from a remote server based on Windows ReleaseID to avoid opening a handle to ntdll and trigger exported APIs from the export table
        // Reference: https://github.com/TheD1rkMtr/NTDLLReflection
        $string10 = /TheD1rkMtr\/NTDLLReflection/ nocase ascii wide

    condition:
        any of them
}
