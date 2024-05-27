rule Atera
{
    meta:
        description = "Detection patterns for the tool 'Atera' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Atera"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string1 = /\/Agent\/AcknowledgeCommands\// nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string2 = /\/Agent\/GetCommandsFallback\// nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string3 = /\/Agent\/GetEnvironmentStatus\// nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string4 = /\/Agent\/GetRecurringPackages\// nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string5 = /\\AlphaControlAgent\\obj\\Release\\AteraAgent\.pdb/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string6 = /\\atera_agent\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string7 = /\\Program\sFiles\s\(x86\)\\Atera\sNetworks/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string8 = /\\Program\sFiles\\Atera\sNetworks/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string9 = /\\Services\\AteraAgent/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string10 = /\\TEMP\\AteraUpgradeAgentPackage\\/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string11 = /acontrol\.atera\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string12 = /agent\-api\.atera\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string13 = /AgentPackageInternalPooler\\log\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string14 = /AgentPackageRunCommandInteractive\\log\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string15 = /AlphaControlAgent\.CloudLogsManager\+\<\>/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string16 = /atera_del\.bat/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string17 = /atera_del2\.bat/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: https://thedfirreport.com/2023/09/25/from-screenconnect-to-hive-ransomware-in-61-hours/
        $string18 = /AteraAgent.{0,1000}AgentPackageRunCommandInteractive\.exe/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string19 = /AteraSetupLog\.txt/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string20 = /http.{0,1000}\/agent\-api\-.{0,1000}\.atera\.com/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string21 = /Monitoring\s\&\sManagement\sAgent\sby\sATERA/ nocase ascii wide
        // Description: control remote machines- abused by threat actors
        // Reference: N/A
        $string22 = /SOFTWARE\\ATERA\sNetworks\\AlphaAgent/ nocase ascii wide

    condition:
        any of them
}
