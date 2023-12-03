rule RunAsWinTcb
{
    meta:
        description = "Detection patterns for the tool 'RunAsWinTcb' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "RunAsWinTcb"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string1 = /.{0,1000}\/dllexploit\.cpp.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string2 = /.{0,1000}\/dllexploit\.exe.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string3 = /.{0,1000}\/POC_DLL\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string4 = /.{0,1000}\/RunAsWinTcb\.git.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string5 = /.{0,1000}\/RunAsWinTcb\.iml.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string6 = /.{0,1000}\\dllexploit\.cpp.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string7 = /.{0,1000}\\dllexploit\.exe.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string8 = /.{0,1000}\\POC_DLL\.vcxproj.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string9 = /.{0,1000}33BF8AA2\-18DE\-4ED9\-9613\-A4118CBFC32A.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string10 = /.{0,1000}Choosing\sDLL\sto\shijack\..{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string11 = /.{0,1000}POC_DLL\.dll.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string12 = /.{0,1000}RunAsWinTcb\.exe.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string13 = /.{0,1000}RunAsWinTcb\-master.{0,1000}/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string14 = /.{0,1000}tastypepperoni\/RunAsWinTcb.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
