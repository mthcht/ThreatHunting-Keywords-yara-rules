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
        $string1 = /\/dllexploit\.cpp/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string2 = /\/dllexploit\.exe/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string3 = /\/POC_DLL\.vcxproj/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string4 = /\/RunAsWinTcb\.git/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string5 = /\/RunAsWinTcb\.iml/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string6 = /\\dllexploit\.cpp/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string7 = /\\dllexploit\.exe/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string8 = /\\POC_DLL\.vcxproj/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string9 = /33BF8AA2\-18DE\-4ED9\-9613\-A4118CBFC32A/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string10 = /Choosing\sDLL\sto\shijack\./ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string11 = /POC_DLL\.dll/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string12 = /RunAsWinTcb\.exe/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string13 = /RunAsWinTcb\-master/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string14 = /tastypepperoni\/RunAsWinTcb/ nocase ascii wide

    condition:
        any of them
}