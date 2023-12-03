rule SetProcessInjection
{
    meta:
        description = "Detection patterns for the tool 'SetProcessInjection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SetProcessInjection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // Reference: https://github.com/OtterHacker/SetProcessInjection
        $string1 = /.{0,1000}\/SetProcessInjection\.git.{0,1000}/ nocase ascii wide
        // Description: alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // Reference: https://github.com/OtterHacker/SetProcessInjection
        $string2 = /.{0,1000}\[\+\]\sYour\spayload\smust\sbe\sexecuted\snow\s\!.{0,1000}/ nocase ascii wide
        // Description: alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // Reference: https://github.com/OtterHacker/SetProcessInjection
        $string3 = /.{0,1000}\[x\]\sCannot\sload\sNTDLL\.DLL.{0,1000}/ nocase ascii wide
        // Description: alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // Reference: https://github.com/OtterHacker/SetProcessInjection
        $string4 = /.{0,1000}azfvgayqKwtFApcvyRedpUXculaeCCGA.{0,1000}/ nocase ascii wide
        // Description: alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // Reference: https://github.com/OtterHacker/SetProcessInjection
        $string5 = /.{0,1000}CA280845\-1F10\-4E65\-9DE7\-D9C6513BBD91.{0,1000}/ nocase ascii wide
        // Description: alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // Reference: https://github.com/OtterHacker/SetProcessInjection
        $string6 = /.{0,1000}OtterHacker\/SetProcessInjection.{0,1000}/ nocase ascii wide
        // Description: alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // Reference: https://github.com/OtterHacker/SetProcessInjection
        $string7 = /.{0,1000}payload\/encryptor_remote\.py.{0,1000}/ nocase ascii wide
        // Description: alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // Reference: https://github.com/OtterHacker/SetProcessInjection
        $string8 = /.{0,1000}SetProcessInjection.{0,1000}encryptor\.py.{0,1000}/ nocase ascii wide
        // Description: alternate technique allowing execution at an arbitrary memory address on a remote process that can be used to replace the standard CreateRemoteThread call.
        // Reference: https://github.com/OtterHacker/SetProcessInjection
        $string9 = /.{0,1000}SetProcessInjection\-main.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
