rule PrivFu
{
    meta:
        description = "Detection patterns for the tool 'PrivFu' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PrivFu"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string1 = /\/PrivFu\.git/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string2 = /\/TokenStealing/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string3 = /\/WfpTokenDup\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string4 = /\\\\\.\\pipe\\PrivFu/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string5 = /\\PrintSpoofer\.cs/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string6 = /\\PrivEditor\\/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string7 = /\\PrivFu\.txt/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string8 = /\\TokenDump\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string9 = /\\TrustExec\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string10 = /\\WfpTokenDup\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string11 = /04FC654C\-D89A\-44F9\-9E34\-6D95CE152E9D/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string12 = /449CE476\-7B27\-47F5\-B09C\-570788A2F261/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string13 = /4C574B86\-DC07\-47EA\-BB02\-FD50AE002910/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string14 = /6F99CB40\-8FEF\-4B63\-A35D\-9CEEC71F7B5F/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string15 = /daem0nc0re\/PrivFu/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string16 = /NamedPipeImpersonation\.cs/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string17 = /NamedPipeImpersonation\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string18 = /printspoofer\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string19 = /PrivEditor\.dll/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string20 = /PrivFu\-main\.zip/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string21 = /PrivFu\-master/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string22 = /S4uDelegator\./ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string23 = /SwitchPriv\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string24 = /TokenDump\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string25 = /TokenStealing\.cs/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string26 = /TokenStealing\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string27 = /TokenViewer\.exe/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string28 = /WfpTokenDup\.exe\s\-/ nocase ascii wide

    condition:
        any of them
}
