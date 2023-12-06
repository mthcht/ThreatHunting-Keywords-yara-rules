rule Invoke_Phant0m
{
    meta:
        description = "Detection patterns for the tool 'Invoke-Phant0m' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Invoke-Phant0m"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: This script walks thread stacks of Event Log Service process (spesific svchost.exe) and identify Event Log Threads to kill Event Log Service Threads. So the system will not be able to collect logs and at the same time the Event Log Service will appear to be running. I have made this script for two reasons. First. This script will help to Red Teams and Penetration Testers. Second. I want to learn Powershell and Low-Level things on Powershell for cyber security field
        // Reference: https://github.com/hlldz/Invoke-Phant0m
        $string1 = /Invoke\-Phant0m/ nocase ascii wide

    condition:
        any of them
}
