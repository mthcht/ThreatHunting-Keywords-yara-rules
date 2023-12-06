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
        $string1 = /\/RefleXXion\.git/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string2 = /hlldz\/RefleXXion/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string3 = /RefleXXion.{0,1000}ntdll\.dll/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string4 = /RefleXXion\.sln/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string5 = /RefleXXion\-DLL/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string6 = /RefleXXion\-EXE/ nocase ascii wide
        // Description: RefleXXion is a utility designed to aid in bypassing user-mode hooks utilised by AV/EPP/EDR etc. In order to bypass the user-mode hooks. it first collects the syscall numbers of the NtOpenFile. NtCreateSection. NtOpenSection and NtMapViewOfSection found in the LdrpThunkSignature array.
        // Reference: https://github.com/hlldz/RefleXXion
        $string7 = /RefleXXion\-main/ nocase ascii wide

    condition:
        any of them
}
