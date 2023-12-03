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
        $string1 = /.{0,1000}\/msi_search\.ps1.{0,1000}/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string2 = /.{0,1000}\/msi\-search\.git.{0,1000}/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string3 = /.{0,1000}\\msi_search\.c.{0,1000}/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string4 = /.{0,1000}\\msi_search\.exe.{0,1000}/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string5 = /.{0,1000}\\msi_search\.ps1.{0,1000}/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string6 = /.{0,1000}\\msi_search\.x64\.o.{0,1000}/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string7 = /.{0,1000}\\msi_search\.x86\.o.{0,1000}/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string8 = /.{0,1000}mandiant\/msi\-search.{0,1000}/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string9 = /.{0,1000}msi\-search\-main\.zip.{0,1000}/ nocase ascii wide
        // Description: This tool simplifies the task for red team operators and security teams to identify which MSI files correspond to which software and enables them to download the relevant file to investigate local privilege escalation vulnerabilities through MSI repairs
        // Reference: https://github.com/mandiant/msi-search
        $string10 = /.{0,1000}Search\scached\sMSI\sfiles\sin\sC:\/Windows\/Installer\/.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
