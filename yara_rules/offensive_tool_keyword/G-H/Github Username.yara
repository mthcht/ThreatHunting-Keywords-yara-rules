rule Github_Username
{
    meta:
        description = "Detection patterns for the tool 'Github Username' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Github Username"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: github Penetration tester repo hosting malicious code
        // Reference: https://github.com/attackercan/
        $string1 = "/attackercan/" nocase ascii wide
        // Description: Github username of known powershell offensive modules and scripts
        // Reference: https://github.com/Ben0xA
        $string2 = "/Ben0xA/" nocase ascii wide
        // Description: Open source testing tools for the SDR & security community
        // Reference: https://github.com/BastilleResearch
        $string3 = "BastilleResearch" nocase ascii wide
        // Description: Cybersecurity Engineers and Offensive Security enthusiasts actively maintaining/updating Powershell Empire in our spare time.
        // Reference: https://github.com/BC-SECURITY
        $string4 = "BC-SECURITY" nocase ascii wide
        // Description: Welcome to the Infection Monkey! The Infection Monkey is an open source security tool for testing a data centers resiliency to perimeter breaches and internal server infection. The Monkey uses various methods to self propagate across a data center and reports success to a centralized Monkey Island server
        // Reference: https://github.com/h0nus
        $string5 = /guardicore.{0,1000}monkey/ nocase ascii wide
        // Description: s7scan is a tool that scans networks. enumerates Siemens PLCs and gathers basic information about them. such as PLC firmware and hardwaare version. network configuration and security parameters. It is completely written on Python.
        // Reference: https://github.com/klsecservices/s7scan
        $string6 = "s7scan" nocase ascii wide

    condition:
        any of them
}
