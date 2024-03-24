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
        $string8 = /\\POC_DLL\.dll/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string9 = /\\POC_DLL\.vcxproj/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string10 = /\\RunAsWinTcb\\/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string11 = /33BF8AA2\-18DE\-4ED9\-9613\-A4118CBFC32A/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string12 = /cb291da763f1ac7b8221be536e9d110a4c937c749da51b15151975c1b84f8b6d/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string13 = /Choosing\sDLL\sto\shijack\./ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string14 = /RunAsWinTcb\.exe/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string15 = /RunAsWinTcb\-master/ nocase ascii wide
        // Description: RunAsWinTcb uses an userland exploit to run a DLL with a protection level of WinTcb-Light.
        // Reference: https://github.com/tastypepperoni/RunAsWinTcb
        $string16 = /tastypepperoni\/RunAsWinTcb/ nocase ascii wide

    condition:
        any of them
}
