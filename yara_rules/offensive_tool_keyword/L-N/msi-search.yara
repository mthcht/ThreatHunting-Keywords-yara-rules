rule msi_search
{
    meta:
        description = "Detection patterns for the tool 'msi-search' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "msi-search"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string1 = /\/msi_search\.ps1/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string2 = /\/msi\-search\.git/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string3 = /\\msi_search\.c/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string4 = /\\msi_search\.exe/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string5 = /\\msi_search\.ps1/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string6 = /\\msi_search\.x64\.o/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string7 = /\\msi_search\.x86\.o/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string8 = /mandiant\/msi\-search/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string9 = /msi\-search\-main\.zip/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string10 = /Search\scached\sMSI\sfiles\sin\sC\:\/Windows\/Installer\// nocase ascii wide

    condition:
        any of them
}
