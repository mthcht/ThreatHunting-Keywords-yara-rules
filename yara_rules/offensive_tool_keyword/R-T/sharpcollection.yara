rule sharpcollection
{
    meta:
        description = "Detection patterns for the tool 'sharpcollection' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "sharpcollection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1 = /\/EDD\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string2 = /\/Group3r\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string3 = /\/Grouper2\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string4 = /\/SharpCollection\// nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string5 = /\/Watson\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string6 = /\\EDD\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string7 = /\\Group3r\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string8 = /\\Grouper2\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string9 = /ADCollector\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string10 = /ADCSPwn\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string11 = /ADFSDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string12 = /ADSearch\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string13 = /BetterSafetyKatz\./ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string14 = /Certify\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string15 = /DeployPrinterNightmare\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string16 = /ForgeCert\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string17 = /Inveigh\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string18 = /KrbRelay\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string19 = /KrbRelayUp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string20 = /LockLess\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string21 = /PassTheCert\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string22 = /PurpleSharp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string23 = /Rubeus\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string24 = /SafetyKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string25 = /SauronEye\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string26 = /SearchOutlook\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string27 = /Seatbelt\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string28 = /SharpAllowedToAct\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string29 = /SharpAppLocker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string30 = /SharpBypassUAC\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string31 = /SharpChisel\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string32 = /SharpChrome\sbackupkey/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string33 = /SharpChrome\.cs/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string34 = /SharpChrome\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string35 = /SharpChromium\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string36 = /SharpCloud\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string37 = /SharpCOM\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string38 = /SharpCookieMonster\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string39 = /SharpCrashEventLog\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string40 = /SharpDir\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string41 = /SharpDPAPI\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string42 = /SharpDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string43 = /SharpEDRChecker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string44 = /SharPersist\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string45 = /SharpExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string46 = /SharpGPOAbuse\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string47 = /SharpHandler\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string48 = /SharpHose\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string49 = /SharpHound\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string50 = /SharpKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string51 = /SharpLAPS\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string52 = /SharpMapExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string53 = /SharpMiniDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string54 = /SharpMove\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string55 = /SharpNamedPipePTH\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string56 = /SharpNoPSExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string57 = /SharpPrinter\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string58 = /SharpRDP\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string59 = /SharpReg\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string60 = /SharpSCCM\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string61 = /SharpSearch\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string62 = /SharpSecDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string63 = /SharpShares\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string64 = /Sharp\-SMBExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string65 = /SharpSniper\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string66 = /SharpSphere\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string67 = /SharpSpray\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string68 = /SharpSQLPwn\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string69 = /SharpStay\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string70 = /SharpSvc\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string71 = /SharpTask\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string72 = /SharpUp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string73 = /SharpView\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string74 = /SharpWebServer\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string75 = /SharpWifiGrabber\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string76 = /SharpWMI\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string77 = /SharpZeroLogon\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string78 = /Shhmon\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string79 = /Snaffler\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string80 = /StickyNotesExtract\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string81 = /SweetPotato\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string82 = /ThunderFox\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string83 = /TokenStomp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string84 = /TruffleSnout\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string85 = /Whisker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string86 = /winPEAS\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string87 = /WMIReg\.exe/ nocase ascii wide

    condition:
        any of them
}