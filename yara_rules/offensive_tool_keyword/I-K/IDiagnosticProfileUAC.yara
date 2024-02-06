rule IDiagnosticProfileUAC
{
    meta:
        description = "Detection patterns for the tool 'IDiagnosticProfileUAC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IDiagnosticProfileUAC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: UAC bypass using auto-elevated COM object Virtual Factory for DiagCpl
        // Reference: https://github.com/Wh04m1001/IDiagnosticProfileUAC
        $string1 = /\/IDiagnosticProfileUAC/ nocase ascii wide
        // Description: UAC bypass using auto-elevated COM object Virtual Factory for DiagCpl
        // Reference: https://github.com/Wh04m1001/IDiagnosticProfileUAC
        $string2 = /\\IDiagnosticProfileUAC/ nocase ascii wide
        // Description: UAC bypass using auto-elevated COM object Virtual Factory for DiagCpl
        // Reference: https://github.com/Wh04m1001/IDiagnosticProfileUAC
        $string3 = /C\:\\Uac\\results\.cab/ nocase ascii wide
        // Description: UAC bypass using auto-elevated COM object Virtual Factory for DiagCpl
        // Reference: https://github.com/Wh04m1001/IDiagnosticProfileUAC
        $string4 = /IDiagnosticProfileUAC\.git/ nocase ascii wide
        // Description: UAC bypass using auto-elevated COM object Virtual Factory for DiagCpl
        // Reference: https://github.com/Wh04m1001/IDiagnosticProfileUAC
        $string5 = /IDiagnosticProfileUAC\-main/ nocase ascii wide

    condition:
        any of them
}
