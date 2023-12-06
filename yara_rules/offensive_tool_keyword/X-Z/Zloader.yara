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
        $string1 = /\sflash\.bat/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string2 = /cmd\.exe\s\/c\szoom1\.msi/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string3 = /flashupdate\.ps1/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string4 = /powershell\sInvoke\-WebRequest\shttp.{0,1000}\.bat\s/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://www.mcafee.com/blogs/other-blogs/mcafee-labs/zloader-with-a-new-infection-technique/
        $string5 = /Zloader\-FCVP/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string6 = /zoom1\.msi\.gpg/ nocase ascii wide
        // Description: Zloader Installs Remote Access Backdoors and Delivers Cobalt Strike
        // Reference: https://news.sophos.com/en-us/2022/01/19/zloader-installs-remote-access-backdoors-and-delivers-cobalt-strike/
        $string7 = /zoom2\.dll\.gpg/ nocase ascii wide

    condition:
        any of them
}
