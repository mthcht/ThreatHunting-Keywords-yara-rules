rule APTSimulator
{
    meta:
        description = "Detection patterns for the tool 'APTSimulator' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "APTSimulator"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: APT Simulator is a Windows Batch script that uses a set of tools and output files to make a system look as if it was compromised. In contrast to other adversary simulation tools. APT Simulator is deisgned to make the application as simple as possible. You don't need to run a web server. database or any agents on set of virtual machines. Just download the prepared archive. extract and run the contained Batch file as Administrator. Running APT Simulator takes less than a minute of your time.
        // Reference: https://github.com/NextronSystems/APTSimulator
        $string1 = /APTSimulator/ nocase ascii wide

    condition:
        any of them
}
