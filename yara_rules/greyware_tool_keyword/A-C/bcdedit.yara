rule bcdedit
{
    meta:
        description = "Detection patterns for the tool 'bcdedit' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bcdedit"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Bcdedit is a command-line tool that enables users to view and make changes to boot configuration data (BCD) settings in Windows systems. Adversaries may leverage bcdedit to modify boot settings. such as enabling debug mode or disabling code integrity checks. as a means to bypass security mechanisms and gain persistence on the compromised system. By modifying the boot configuration. adversaries can evade detection and potentially maintain access to the system even after reboots.
        // Reference: N/A
        $string1 = /bcdedit.{0,1000}\s\/set\s\{default\}\sbootstatuspolicy\signoreallfailures/ nocase ascii wide
        // Description: Bcdedit is a command-line tool that enables users to view and make changes to boot configuration data (BCD) settings in Windows systems. Adversaries may leverage bcdedit to modify boot settings. such as enabling debug mode or disabling code integrity checks. as a means to bypass security mechanisms and gain persistence on the compromised system. By modifying the boot configuration. adversaries can evade detection and potentially maintain access to the system even after reboots.
        // Reference: N/A
        $string2 = /bcdedit.{0,1000}\s\/set\s\{default\}\srecoveryenabled\sNo/ nocase ascii wide

    condition:
        any of them
}
