rule esxcli
{
    meta:
        description = "Detection patterns for the tool 'esxcli' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "esxcli"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string1 = "esxcli network firewall set -enabled f" nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string2 = "esxcli network firewall set --enabled f" nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string3 = "esxcli system account add" nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string4 = "esxcli system account remove" nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string5 = /esxcli\ssystem\saccount\sset\s\-i\s.{0,1000}\s\-s\st/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string6 = "esxcli system auditrecords local disable" nocase ascii wide
        // Description: disable the Core Dump file using ESXCLI 
        // Reference: https://unit42.paloaltonetworks.com/threat-assessment-howling-scorpius-akira-ransomware/
        $string7 = "esxcli system coredump file set --unconfigure" nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string8 = "esxcli system permission list" nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string9 = "esxcli system settings encryption set - require-exec-installed-only=F" nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string10 = "esxcli system settings encryption set - require-secure-boot=F" nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string11 = "esxcli system settings kernel set -s execInstalledOnly -v F" nocase ascii wide
        // Description: disable logging with ESXCLI 
        // Reference: https://unit42.paloaltonetworks.com/threat-assessment-howling-scorpius-akira-ransomware/
        $string12 = "esxcli system syslog config set --logdir=/tmp" nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string13 = "esxcli vm process kill " nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string14 = "esxcli vm process list" nocase ascii wide

    condition:
        any of them
}
