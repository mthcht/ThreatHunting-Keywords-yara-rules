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
        $string1 = /esxcli\snetwork\sfirewall\sset\s\-enabled\sf/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string2 = /esxcli\ssystem\saccount\sadd/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string3 = /esxcli\ssystem\saccount\sremove/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string4 = /esxcli\ssystem\saccount\sset\s\-i\s.{0,1000}\s\-s\st/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string5 = /esxcli\ssystem\sauditrecords\slocal\sdisable/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string6 = /esxcli\ssystem\spermission\slist/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string7 = /esxcli\ssystem\ssettings\sencryption\sset\s\-\srequire\-exec\-installed\-only\=F/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string8 = /esxcli\ssystem\ssettings\sencryption\sset\s\-\srequire\-secure\-boot\=F/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string9 = /esxcli\ssystem\ssettings\skernel\sset\s\-s\sexecInstalledOnly\s\-v\sF/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string10 = /esxcli\svm\sprocess\skill\s/ nocase ascii wide
        // Description: commands used by ransomware targeting ESXi hosts
        // Reference: https://medium.com/detect-fyi/detecting-and-responding-to-esxi-compromise-with-splunk-f33998ce7823
        $string11 = /esxcli\svm\sprocess\slist/ nocase ascii wide

    condition:
        any of them
}
