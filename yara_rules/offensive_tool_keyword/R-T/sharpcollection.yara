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
        $string1 = /.{0,1000}\/EDD\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string2 = /.{0,1000}\/Group3r\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string3 = /.{0,1000}\/Grouper2\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string4 = /.{0,1000}\/SharpCollection\/.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string5 = /.{0,1000}\/Watson\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string6 = /.{0,1000}\\EDD\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string7 = /.{0,1000}\\Group3r\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string8 = /.{0,1000}\\Grouper2\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string9 = /.{0,1000}ADCollector\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string10 = /.{0,1000}ADCSPwn\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string11 = /.{0,1000}ADFSDump\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string12 = /.{0,1000}ADSearch\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string13 = /.{0,1000}BetterSafetyKatz\..{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string14 = /.{0,1000}Certify\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string15 = /.{0,1000}DeployPrinterNightmare\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string16 = /.{0,1000}ForgeCert\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string17 = /.{0,1000}Inveigh\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string18 = /.{0,1000}KrbRelay\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string19 = /.{0,1000}KrbRelayUp\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string20 = /.{0,1000}LockLess\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string21 = /.{0,1000}PassTheCert\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string22 = /.{0,1000}PurpleSharp\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string23 = /.{0,1000}Rubeus\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string24 = /.{0,1000}SafetyKatz\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string25 = /.{0,1000}SauronEye\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string26 = /.{0,1000}SearchOutlook\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string27 = /.{0,1000}Seatbelt\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string28 = /.{0,1000}SharpAllowedToAct\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string29 = /.{0,1000}SharpAppLocker\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string30 = /.{0,1000}SharpBypassUAC\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string31 = /.{0,1000}SharpChisel\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string32 = /.{0,1000}SharpChrome\sbackupkey.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string33 = /.{0,1000}SharpChrome\.cs.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string34 = /.{0,1000}SharpChrome\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string35 = /.{0,1000}SharpChromium\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string36 = /.{0,1000}SharpCloud\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string37 = /.{0,1000}SharpCOM\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string38 = /.{0,1000}SharpCookieMonster\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string39 = /.{0,1000}SharpCrashEventLog\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string40 = /.{0,1000}SharpDir\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string41 = /.{0,1000}SharpDPAPI\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string42 = /.{0,1000}SharpDump\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string43 = /.{0,1000}SharpEDRChecker\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string44 = /.{0,1000}SharPersist\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string45 = /.{0,1000}SharpExec\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string46 = /.{0,1000}SharpGPOAbuse\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string47 = /.{0,1000}SharpHandler\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string48 = /.{0,1000}SharpHose\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string49 = /.{0,1000}SharpHound\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string50 = /.{0,1000}SharpKatz\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string51 = /.{0,1000}SharpLAPS\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string52 = /.{0,1000}SharpMapExec\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string53 = /.{0,1000}SharpMiniDump\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string54 = /.{0,1000}SharpMove\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string55 = /.{0,1000}SharpNamedPipePTH\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string56 = /.{0,1000}SharpNoPSExec\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string57 = /.{0,1000}SharpPrinter\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string58 = /.{0,1000}SharpRDP\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string59 = /.{0,1000}SharpReg\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string60 = /.{0,1000}SharpSCCM\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string61 = /.{0,1000}SharpSearch\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string62 = /.{0,1000}SharpSecDump\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string63 = /.{0,1000}SharpShares\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string64 = /.{0,1000}Sharp\-SMBExec\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string65 = /.{0,1000}SharpSniper\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string66 = /.{0,1000}SharpSphere\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string67 = /.{0,1000}SharpSpray\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string68 = /.{0,1000}SharpSQLPwn\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string69 = /.{0,1000}SharpStay\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string70 = /.{0,1000}SharpSvc\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string71 = /.{0,1000}SharpTask\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string72 = /.{0,1000}SharpUp\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string73 = /.{0,1000}SharpView\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string74 = /.{0,1000}SharpWebServer\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string75 = /.{0,1000}SharpWifiGrabber\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string76 = /.{0,1000}SharpWMI\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string77 = /.{0,1000}SharpZeroLogon\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string78 = /.{0,1000}Shhmon\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string79 = /.{0,1000}Snaffler\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string80 = /.{0,1000}StickyNotesExtract\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string81 = /.{0,1000}SweetPotato\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string82 = /.{0,1000}ThunderFox\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string83 = /.{0,1000}TokenStomp\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string84 = /.{0,1000}TruffleSnout\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string85 = /.{0,1000}Whisker\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string86 = /.{0,1000}winPEAS\.exe.{0,1000}/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string87 = /.{0,1000}WMIReg\.exe.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
