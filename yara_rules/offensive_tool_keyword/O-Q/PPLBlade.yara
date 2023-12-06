rule PPLBlade
{
    meta:
        description = "Detection patterns for the tool 'PPLBlade' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PPLBlade"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string1 = /\s\-\-dumpmode\snetwork\s\-\-network\sraw\s\-\-ip\s.{0,1000}\s\-\-port\s/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string2 = /\s\-\-dumpmode\snetwork\s\-\-network\ssmb\s/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string3 = /\s\-\-dumpname\slsass\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string4 = /\s\-\-key\sPPLBlade/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string5 = /\s\-\-mode\sdecrypt\s\-\-dumpname\s.{0,1000}\.dmp\s\-\-key\s/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string6 = /\s\-\-mode\sdump\s\-\-name\s.{0,1000}\.exe\s\-\-handle\sprocexp\s\-\-obfuscate/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string7 = /\s\-\-mode\sdump\s\-\-name\slsass\.exe/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string8 = /\/decrypted\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string9 = /\/PPLBlade\.git/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string10 = /\[\+\]\sDeobfuscated\sdump\ssaved\sin\sfile\sdecrypted\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string11 = /\\decrypted\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string12 = /\\PPLBlade\-main/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string13 = /dothatlsassthing/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string14 = /PPLBlade\.dmp/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string15 = /PPLBlade\.exe/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string16 = /PPLBlade\-main\./ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string17 = /tastypepperoni\/PPLBlade/ nocase ascii wide

    condition:
        any of them
}
