rule xcopy
{
    meta:
        description = "Detection patterns for the tool 'xcopy' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "xcopy"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: command used by Doina trojan
        // Reference: N/A
        $string1 = "cmd /c xcopy /s /i /h /e /q /y /d" nocase ascii wide
        // Description: copying Ie4uinit.exe in another folder for dll sideloading
        // Reference: https://thedfirreport.com/2024/12/02/the-curious-case-of-an-egg-cellent-resume/
        $string2 = /xcopy\s\/Y\s\/C\s\/Q\sC\:\\Windows\\system32\\.{0,1000}\.exe\s.{0,1000}Ie4uinit\.exe/ nocase ascii wide
        // Description: command abused by attackers - exfiltraiton to remote host with xcopy
        // Reference: N/A
        $string3 = /xcopy\sc\:\\.{0,1000}\s\\\\.{0,1000}\\c\$/ nocase ascii wide

    condition:
        any of them
}
