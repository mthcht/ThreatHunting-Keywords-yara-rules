rule RefleXXion
{
    meta:
        description = "Detection patterns for the tool 'RefleXXion' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RefleXXion"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string1 = /.{0,1000}\/RefleXXion\.git.{0,1000}/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string2 = /.{0,1000}hlldz\/RefleXXion.{0,1000}/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string3 = /.{0,1000}RefleXXion.{0,1000}ntdll\.dll.{0,1000}/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string4 = /.{0,1000}RefleXXion\.sln.{0,1000}/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string5 = /.{0,1000}RefleXXion\-DLL.{0,1000}/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string6 = /.{0,1000}RefleXXion\-EXE.{0,1000}/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string7 = /.{0,1000}RefleXXion\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
