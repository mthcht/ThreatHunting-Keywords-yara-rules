rule BarracudaRMM
{
    meta:
        description = "Detection patterns for the tool 'BarracudaRMM' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "BarracudaRMM"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string1 = /\.apitest\.barracudamsp\.com/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string2 = /\/Applications\/Managed\sWorkplace\/Onsite\sManager\/logs\// nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string3 = /\\BRMM_2024\.1\-Release/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string4 = /\\MWDiagnosticCollector\.exe/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string5 = /\\MWDiagnosticCollectorResult_.{0,1000}\.zip/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string6 = /\\Program\sFiles\s\(x86\)\\Barracuda\sRMM\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string7 = /\\Program\sFiles\s\(x86\)\\Level\sPlatforms\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string8 = /\\Program\sFiles\\Barracuda\sRMM\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string9 = /\\Program\sFiles\\Level\sPlatforms\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string10 = /\\ProgramData\\Barracuda\sMSP\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string11 = /\\SOFTWARE\\Level\sPlatforms\\Managed\sWorkplace\\/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string12 = /\>Barracuda\sMSP\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string13 = /\>Barracuda\sNetworks\,\sInc\./ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string14 = /\>Barracuda\sRMM\sSetup\sAutoRun\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string15 = /\>Barracuda\sRMM\sSetup\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string16 = /\>Barracuda\sRMM.{0,1000}\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string17 = /\>LPI\sLevel\sPlatforms\</ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string18 = /Barracuda\sRMM\sOnsite\sManager\s\-\sInstallShield\sWizard/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string19 = /Barracuda\sRMM\sOnsite\sManager\.msi/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string20 = /rmm\.barracudamsp\.com/ nocase ascii wide
        // Description: Deliver remote support services - formely AVG
        // Reference: https://www.barracudamsp.com/products/rmm/barracuda-rmm
        $string21 = /whatsmyip\.ccrmm\.avg\.com/ nocase ascii wide

    condition:
        any of them
}
