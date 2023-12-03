rule Zloader
{
    meta:
        description = "Detection patterns for the tool 'Zloader' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Zloader"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string1 = /.{0,1000}\sflash\.bat.{0,1000}/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string2 = /.{0,1000}cmd\.exe\s\/c\szoom1\.msi.{0,1000}/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string3 = /.{0,1000}flashupdate\.ps1.{0,1000}/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string4 = /.{0,1000}powershell\sInvoke\-WebRequest\shttp.{0,1000}\.bat\s.{0,1000}/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://www.mcafee.com/blogs/other-blogs/mcafee-labs/zloader-with-a-new-infection-technique/
        $string5 = /.{0,1000}Zloader\-FCVP.{0,1000}/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string6 = /.{0,1000}zoom1\.msi\.gpg.{0,1000}/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string7 = /.{0,1000}zoom2\.dll\.gpg.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
