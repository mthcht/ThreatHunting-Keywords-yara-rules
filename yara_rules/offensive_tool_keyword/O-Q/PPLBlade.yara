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
        $string1 = /.{0,1000}\s\-\-dumpmode\snetwork\s\-\-network\sraw\s\-\-ip\s.{0,1000}\s\-\-port\s.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string2 = /.{0,1000}\s\-\-dumpmode\snetwork\s\-\-network\ssmb\s.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string3 = /.{0,1000}\s\-\-dumpname\slsass\.dmp.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string4 = /.{0,1000}\s\-\-key\sPPLBlade.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string5 = /.{0,1000}\s\-\-mode\sdecrypt\s\-\-dumpname\s.{0,1000}\.dmp\s\-\-key\s.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string6 = /.{0,1000}\s\-\-mode\sdump\s\-\-name\s.{0,1000}\.exe\s\-\-handle\sprocexp\s\-\-obfuscate.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string7 = /.{0,1000}\s\-\-mode\sdump\s\-\-name\slsass\.exe.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string8 = /.{0,1000}\/decrypted\.dmp.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string9 = /.{0,1000}\/PPLBlade\.git.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string10 = /.{0,1000}\[\+\]\sDeobfuscated\sdump\ssaved\sin\sfile\sdecrypted\.dmp.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string11 = /.{0,1000}\\decrypted\.dmp.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string12 = /.{0,1000}\\PPLBlade\-main.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string13 = /.{0,1000}dothatlsassthing.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string14 = /.{0,1000}PPLBlade\.dmp.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string15 = /.{0,1000}PPLBlade\.exe.{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string16 = /.{0,1000}PPLBlade\-main\..{0,1000}/ nocase ascii wide
        // Description: Protected Process Dumper Tool that support obfuscating memory dump and transferring it on remote workstations without dropping it onto the disk.
        // Reference: https://github.com/tastypepperoni/PPLBlade
        $string17 = /.{0,1000}tastypepperoni\/PPLBlade.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
