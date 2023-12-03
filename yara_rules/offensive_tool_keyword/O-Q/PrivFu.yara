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
        $string1 = /.{0,1000}\/PrivFu\.git.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string2 = /.{0,1000}\/TokenStealing.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string3 = /.{0,1000}\/WfpTokenDup\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string4 = /.{0,1000}\\PrintSpoofer\.cs.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string5 = /.{0,1000}\\PrivEditor\\.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string6 = /.{0,1000}\\TokenDump\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string7 = /.{0,1000}\\TrustExec\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string8 = /.{0,1000}\\WfpTokenDup\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string9 = /.{0,1000}04FC654C\-D89A\-44F9\-9E34\-6D95CE152E9D.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string10 = /.{0,1000}449CE476\-7B27\-47F5\-B09C\-570788A2F261.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string11 = /.{0,1000}4C574B86\-DC07\-47EA\-BB02\-FD50AE002910.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string12 = /.{0,1000}6F99CB40\-8FEF\-4B63\-A35D\-9CEEC71F7B5F.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string13 = /.{0,1000}daem0nc0re\/PrivFu.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string14 = /.{0,1000}NamedPipeImpersonation\.cs.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string15 = /.{0,1000}NamedPipeImpersonation\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string16 = /.{0,1000}printspoofer\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string17 = /.{0,1000}PrivEditor\.dll.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string18 = /.{0,1000}PrivFu\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string19 = /.{0,1000}PrivFu\-master.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string20 = /.{0,1000}S4uDelegator\..{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string21 = /.{0,1000}SwitchPriv\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string22 = /.{0,1000}TokenDump\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string23 = /.{0,1000}TokenStealing\.cs.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string24 = /.{0,1000}TokenStealing\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string25 = /.{0,1000}TokenViewer\.exe.{0,1000}/ nocase ascii wide
        // Description: Kernel mode WinDbg extension and PoCs for token privilege investigation.
        // Reference: https://github.com/daem0nc0re/PrivFu/
        $string26 = /.{0,1000}WfpTokenDup\.exe\s\-.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
