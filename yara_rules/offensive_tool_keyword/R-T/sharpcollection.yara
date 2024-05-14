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
        $string1 = /\sSeatbelt\.Commands\.Windows/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string2 = /\/ADCollector\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string3 = /\/ADCSPwn\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string4 = /\/ADFSDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string5 = /\/ADSearch\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string6 = /\/AtYourService\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string7 = /\/BetterSafetyKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string8 = /\/DeployPrinterNightmare\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string9 = /\/EDD\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string10 = /\/ForgeCert\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string11 = /\/GMSAPasswordReader\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string12 = /\/Group3r\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string13 = /\/Group3r\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string14 = /\/Grouper2\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string15 = /\/Grouper2\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string16 = /\/Inveigh\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string17 = /\/KrbRelay\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string18 = /\/KrbRelayUp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string19 = /\/LockLess\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string20 = /\/Moriarty\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string21 = /\/net_4\.0_32_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string22 = /\/net_4\.0_32SharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string23 = /\/net_4\.0_32sharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string24 = /\/net_4\.0_64_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string25 = /\/net_4\.0_64SharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string26 = /\/net_4\.0_64sharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string27 = /\/net_4\.0_Any_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string28 = /\/net_4\.0_AnySharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string29 = /\/net_4\.0_Anysharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string30 = /\/net_4\.5_32_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string31 = /\/net_4\.5_32SharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string32 = /\/net_4\.5_32sharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string33 = /\/net_4\.5_64_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string34 = /\/net_4\.5_64SharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string35 = /\/net_4\.5_64sharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string36 = /\/net_4\.5_Any_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string37 = /\/net_4\.5_AnySharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string38 = /\/net_4\.5_Anysharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string39 = /\/net_4\.7_32_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string40 = /\/net_4\.7_64_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string41 = /\/net_4\.7_Any_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string42 = /\/PassTheCert\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string43 = /\/PurpleSharp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string44 = /\/Rubeus\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string45 = /\/SafetyKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string46 = /\/SauronEye\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string47 = /\/Seatbelt\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string48 = /\/ShadowSpray\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string49 = /\/SharpAllowedToAct\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string50 = /\/SharpApplocker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string51 = /\/SharpBlock\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string52 = /\/SharpBypassUAC\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string53 = /\/SharpChisel\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string54 = /\/SharpChrome\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string55 = /\/SharpChromium\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string56 = /\/SharpCloud\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string57 = /\/SharpCollection\.git/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string58 = /\/SharpCollection\// nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string59 = /\/SharpCOM\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string60 = /\/SharpCookieMonster\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string61 = /\/SharpCrashEventLog\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string62 = /\/SharpDir\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string63 = /\/SharpDPAPI\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string64 = /\/SharpDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string65 = /\/SharpEDRChecker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string66 = /\/SharPersist\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string67 = /\/SharpExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string68 = /\/SharpFinder\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string69 = /\/SharpGPOAbuse\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string70 = /\/SharpHandler\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string71 = /\/SharpHose\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string72 = /\/SharpHound\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string73 = /\/SharpKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string74 = /\/SharpLAPS\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string75 = /\/SharpMapExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string76 = /\/SharpMiniDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string77 = /\/SharpMove\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string78 = /\/SharpNamedPipePTH\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string79 = /\/SharpNoPSExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string80 = /\/SharpPrinter\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string81 = /\/SharpRDP\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string82 = /\/SharpReg\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string83 = /\/SharpSCCM\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string84 = /\/SharpSearch\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string85 = /\/SharpSecDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string86 = /\/SharpShares\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string87 = /\/Sharp\-SMBExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string88 = /\/SharpSniper\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string89 = /\/SharpSphere\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string90 = /\/SharpSpray\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string91 = /\/SharpSQLPwn\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string92 = /\/SharpStay\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string93 = /\/SharpSvc\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string94 = /\/SharpTask\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string95 = /\/SharpTokenFinder\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string96 = /\/SharpUp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string97 = /\/SharpView\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string98 = /\/SharpWebServer\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string99 = /\/SharpWifiGrabber\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string100 = /\/SharpWMI\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string101 = /\/SharpZeroLogon\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string102 = /\/Shhmon\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string103 = /\/Snaffler\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string104 = /\/StickyNotesExtract\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string105 = /\/SweetPotato\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string106 = /\/TokenStomp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string107 = /\/TruffleSnout\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string108 = /\/Watson\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string109 = /\/Watson\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string110 = /\/Whisker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string111 = /\/winPEAS\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string112 = /\/WMIReg\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string113 = /\\ADCollector\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string114 = /\\ADCSPwn\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string115 = /\\ADFSDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string116 = /\\ADSearch\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string117 = /\\AtYourService\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string118 = /\\BetterSafetyKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string119 = /\\DeployPrinterNightmare\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string120 = /\\EDD\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string121 = /\\ForgeCert\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string122 = /\\GMSAPasswordReader\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string123 = /\\Group3r\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string124 = /\\Group3r\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string125 = /\\Grouper2\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string126 = /\\Grouper2\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string127 = /\\Inveigh\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string128 = /\\KrbRelay\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string129 = /\\KrbRelayUp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string130 = /\\LockLess\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string131 = /\\Moriarty\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string132 = /\\net_4\.0_32_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string133 = /\\net_4\.0_32SharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string134 = /\\net_4\.0_32sharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string135 = /\\net_4\.0_64_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string136 = /\\net_4\.0_64SharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string137 = /\\net_4\.0_64sharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string138 = /\\net_4\.0_Any_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string139 = /\\net_4\.0_AnySharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string140 = /\\net_4\.0_Anysharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string141 = /\\net_4\.5_32_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string142 = /\\net_4\.5_32SharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string143 = /\\net_4\.5_32sharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string144 = /\\net_4\.5_64_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string145 = /\\net_4\.5_64SharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string146 = /\\net_4\.5_64sharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string147 = /\\net_4\.5_Any_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string148 = /\\net_4\.5_AnySharpDoor\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string149 = /\\net_4\.5_Anysharpfiles\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string150 = /\\net_4\.7_32_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string151 = /\\net_4\.7_64_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string152 = /\\net_4\.7_Any_RunasCs\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string153 = /\\PassTheCert\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string154 = /\\pspasswd\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string155 = /\\pspasswd64\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string156 = /\\PurpleSharp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string157 = /\\Rubeus\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string158 = /\\SafetyKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string159 = /\\SauronEye\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string160 = /\\Seatbelt\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string161 = /\\ShadowSpray\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string162 = /\\SharpAllowedToAct\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string163 = /\\SharpApplocker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string164 = /\\SharpBlock\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string165 = /\\SharpBypassUAC\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string166 = /\\SharpChisel\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string167 = /\\SharpChrome\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string168 = /\\SharpChromium\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string169 = /\\SharpCloud\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string170 = /\\SharpCOM\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string171 = /\\SharpCookieMonster\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string172 = /\\SharpCrashEventLog\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string173 = /\\SharpDir\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string174 = /\\SharpDPAPI\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string175 = /\\SharpDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string176 = /\\SharpEDRChecker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string177 = /\\SharPersist\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string178 = /\\SharpExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string179 = /\\SharpFinder\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string180 = /\\SharpGPOAbuse\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string181 = /\\SharpHandler\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string182 = /\\SharpHose\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string183 = /\\SharpHound\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string184 = /\\SharpKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string185 = /\\SharpLAPS\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string186 = /\\SharpMapExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string187 = /\\SharpMiniDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string188 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string189 = /\\SharpNamedPipePTH\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string190 = /\\SharpNoPSExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string191 = /\\SharpPrinter\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string192 = /\\SharpRDP\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string193 = /\\SharpReg\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string194 = /\\SharpSCCM\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string195 = /\\SharpSearch\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string196 = /\\SharpSecDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string197 = /\\SharpShares\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string198 = /\\Sharp\-SMBExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string199 = /\\SharpSniper\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string200 = /\\SharpSphere\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string201 = /\\SharpSpray\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string202 = /\\SharpSQLPwn\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string203 = /\\SharpStay\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string204 = /\\SharpSvc\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string205 = /\\SharpTask\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string206 = /\\SharpTokenFinder\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string207 = /\\SharpUp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string208 = /\\SharpView\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string209 = /\\SharpWebServer\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string210 = /\\SharpWifiGrabber\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string211 = /\\SharpWMI\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string212 = /\\SharpZeroLogon\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string213 = /\\Shhmon\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string214 = /\\Snaffler\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string215 = /\\StickyNotesExtract\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string216 = /\\SweetPotato\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string217 = /\\TokenStomp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string218 = /\\TruffleSnout\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string219 = /\\Watson\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string220 = /\\Whisker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string221 = /\\winPEAS\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string222 = /\\WMIReg\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string223 = /004126d3014ab8a47172a1b7b0c88673283f9f245e1ce550846ef71bcac84524/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string224 = /00a5af2d7b92becb455b7c5f00faba0aaf6176143601b2cf69cfe2d1ade75f69/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string225 = /00b810771a57f7aab571f2e63288ef88e4929b941108dd5e5ae9bedebf4ef49b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string226 = /01ac77412cfd1be301554bc8db9e5f499337ff1ee631f1ed43a3454d60d25a48/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string227 = /02091a63c2130e04b47ea5947c12d3c850616d21da8d628f0ae91e2cf43f7f4b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string228 = /026a94e75aa94054623b3e2d617c8c59ce6e63edce3e739cbe94283a1eca394a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string229 = /027954d28fd8fa98e06be72439e5a987d2d280a8e3c8d2ab91a4a55d39cbe846/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string230 = /02947e9a3759fea352b81bdf4390b6dfb5ea5823ed4836e1e7a46e5d9b65263c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string231 = /03600de62239db741db7a1d072a4e8504c25b64b7d398d5c80d467452aefbfad/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string232 = /040f67227ccb5fad854663f4162556c6c154d2ef4c0465e62d0ccef37ac4637a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string233 = /04387d7368c1a46d5dc11600b888fbe5890e30a793019d408bde0565a6a3dadb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string234 = /048c215b812c16ffa4d64a8f3da77e2418457e7d8eb89b2716bdb65f176a665a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string235 = /0599c7537d4b728cd234412440a11a6cc54297b3c7af59c1d0309850aca0da53/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string236 = /05fd2d9fd3a8ebed7848e8acc758d0c7964b6d3c85ce81cdbbe93d679fe1acac/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string237 = /061d593aaf747fa8db9674c17bc8d2baa9459b825a196f457b006ff00d4be696/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string238 = /064d0c20e561c1208898028b84dcebf37861b15f33c0a4828ea14ee055ba3f98/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string239 = /065c05950f37c55ceff48bc70d2733424e7e92687faefc803719ff22a5e0156f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string240 = /0817f34dc2b4937f2ea352171e08852bf635b147f6bd77f1c9bdc2dde9f145b9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string241 = /088358bbd95bde68104156dc538c8c7d7e77e06dbd5887c6deefea79f48c2fa4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string242 = /08ca5b5dae3c18f7a5bed317a0650f8f015207facf43ec829b9a3cf7fa63ffa2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string243 = /0968703e426943707b405b5c5bb0ca14ce2e21c8f125954d8ab26c808f45dc47/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string244 = /09764c124174dfc424e00b57c8464025dc6bbfcae62e709bf505a7eece480173/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string245 = /099b726fb0a1160c72e7f8ea20313721f9a060b48eb95bb9c5b7aaee948439c2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string246 = /09b3f22e8ad0fe1b6c07c202f07816fe3d4014835f3311620ca3b0bd5f710fe7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string247 = /09c297ffdf475a85c46c9332884fc3343d2512318f9be43b21bf45f522d12956/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string248 = /09e9ba137516adc361f33e2131db31841edb2f83c133a4e2790878997344e4ba/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string249 = /0a235cd4c61c042f550e1b348ed8f8ca3bd8254bb72213ecf7ec172eec7edba5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string250 = /0a99e30e751c3a01ffe34efaa615c55a6cbbc42038f7004ac356dad5dbba1ada/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string251 = /0aaf0c9b2f4f67ea3012cef59464ce4899556e29920bdbec219f469e1b8fe935/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string252 = /0ae12dd51a6faf674521da0fbb3cb8aba5425934aee91b6e204386b38505ab49/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string253 = /0af1e638d78ecb998aa44a6716084ce830af74c68c641bc1634a9841de3caa76/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string254 = /0bcce0874f30d8d38fabb4fcc1bb44fc60d811c7ff1ae3d3869601d44d65a80a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string255 = /0bdf933e7adf4960c337d0badbd044ccf14ab36731360c5c92001c9c5feded21/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string256 = /0c2b8e134f235970726f41712824ce62f42635e4bd647dfcdb58c8fff88cff36/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string257 = /0c7fdc11cd301457131335dc023726493d839cd18ab659c9ab3a53fbe24269c1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string258 = /0cb5af2ee5239ef9d399446af3088fd26fff2e012b9f8b7e7e59569c8d7d6369/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string259 = /0cffe83538d449fae070161c557a89aad53f47d7472eb22c2cfc3c2671852fa6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string260 = /0dbce336ba4f98f26b89fc110bee0b43aed24002c2fba5df9a7675d168aad12d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string261 = /0ebce776a2758cb99ecc9a6ba97fc432e40925fbe1a4e068bbc7a273f6064269/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string262 = /0ec459ed281c0ee777046a0a31b59500843a74f776a459a12438d6412f146001/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string263 = /0ecd88de5d2728034f25bc04fcf9553198453fb46bbb93a00a74e6e74747435b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string264 = /0f0840b7da6f223c52f15ae1793c5a2942ce0d09ff493967b497a5d839eaaaa5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string265 = /0f2d3c56a917f455906ba339ee8058b5f89138b8605b673eb669c1c6d0bebb5e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string266 = /0f7390905abc132889f7b9a6d5b42701173aafbff5b8f8882397af35d8c10965/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string267 = /0fa2d98ba9b3da4ccc9fbc07e0e9f29aea12fe878ad83dd0c8c83564849433e4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string268 = /10db57856d86b6cef6402c0897efb13cbd5455158f5bfb4497fed570ced9b93c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string269 = /1145de7228a8791659911e809cf8841fea94a38ade1488a647310857201344a5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string270 = /115309fcd130393cc85154585caf9ef08f101133c5fa27307469f02f3e8c1461/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string271 = /11754456d43dc010e48cc2b5294d3a7d84f3a28bd27fd8183a3162ede955e30b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string272 = /125d5bee94f4a04a39b54ec1bcccb5256e0f34abc0ac991af803b1dc525cfbd7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string273 = /13116f7c3441519cd91e74061f0490c15b1b99f32a5209ec52b9cc4ef3fb67de/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string274 = /14551c1d7c781b632e6722cfde0abb62c0698a657bf621ebe6e931a197e81715/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string275 = /14d0b48fef0484e290504ebd35fcca973fde787ef3db70b70de8b3070b287d46/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string276 = /15bc39581933d59dcdb7a264d149cf9bec398e04d18ab0b52f596861614c37b3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string277 = /16461494c864ffe95bb32a01a8db0aa7d46e9db9d6fa0546fdaf75044eb299fa/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string278 = /16e75a6be0f951622988cb5c7875151c9d4638e595a91c43be7a35d4d4f2cd50/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string279 = /17179c8931a5dc7a470485097f4a8f35fcf55bc4fa57d34c865ab76cd382ca74/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string280 = /17395a3b51f21d23c817cb84d56e915026fbf18fb34fc74c8b0377cd0e12ef94/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string281 = /173fddaeb3faa3256a8a6606775eb319ef5d70082f3b7c5ffab9d004b66b1c0d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string282 = /179c7bc7caed085cdfd1db94e54b75dabb2a8943430be82f590143f2b4303b5d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string283 = /17a96dd3f358c5b165d40422c6e218c1b3e9d27182e5202b8d0ad611a874c6d8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string284 = /182e514745c25c47038513979fa80e3744d792f121089cffce1f5de3c5799202/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string285 = /193d4af4e5b7459ad252eb2484692dcc30f2f57bd3e6e8078c144229ba4ceafa/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string286 = /199c57a85711459c0b0fbc8883b19829cec8c64588f50bb4a6b2611f6ad4d62b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string287 = /19d2b32e9801a4f959ce59e251879d9a42ac749e2e702a8ceab2ddee2d71bbb1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string288 = /1a4a751f7044db4952d7e6607f24ade9ebbddbf2c6665de8cae3e7027df28dd2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string289 = /1aa9f8c15c189d98c2f6e05c511bd3452543a3ba700d9a6b5f3279ce8a1fcaea/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string290 = /1af9e71cddf3b8cc8d9bd5004d29fc594400452a727856db23af24a0e3999de7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string291 = /1b38d47cdafe878dabc195a125987f06d04730fa8ac836ffad80e5f3d5721a8a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string292 = /1d015455d5d224c4a3a39c9f43d7c057bd5aebad39b04e831d2fa517d94add09/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string293 = /1d3480472e9ab2c37d65f2278d4ca4a2fe32ac65953c828fbedddb371ae44cc7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string294 = /1db4fad9a062ba7ef43ec84f312716f72842c934ce7709d0ff2ede56c156517b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string295 = /1e5feda37def8d6575efcd1ba2c545dd0355f1810b4a7a6051bdd9d3701fdb95/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string296 = /1e944ac6fd16e486ddf69e61510c37b8df113ace0e346223e8d6394c544b32bf/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string297 = /1ee8207a97428b801b4587c40011193816bd114849e1ddfccc3a313260c20c0c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string298 = /1ef141bd8ce85451d8764a862ed5d16d3140735f868843cb2f96a15cd7623df6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string299 = /1f182f07f495949b4d2fbeb4582e7e30ee75ff7da5f1fe4773a9893c90d0f9cb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string300 = /1f5376413ef092ba7c8e6e6e0eab87024923fbf52600180c6452c247ada39cfe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string301 = /1fbe379890b750ffed5f6702f7d69be790d592ccb2a29872155cadee91dd5268/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string302 = /1ff55dc3672f99ad539c438efcaac7d6311afbe8b0dd8828d20e15c9b0d6e595/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string303 = /1ffe0ceded7146d5b921b40dc941e4e1db10feb40e68dbd4919da143541b9614/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string304 = /2012e8f15dd0989f2b07b0471aa7162f04a9f1fbbee9e3dd0455b090aa8eb6c4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string305 = /20da9df37baa7ae4e08eb46269a8684cee14983f22a31827a51cc3573b3d666f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string306 = /211a24a768f959cb3089aeeb0ed1062c056b15a3ec43e9a4278a5a5f263adbda/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string307 = /21c01746c200094f58a104a378b055484d3230adf28e44a60608834e945643b0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string308 = /22379d19123e498aef75b4ed162a7c94361c1c23745cbae792e2242540997a61/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string309 = /234208515c308c4f71b418b498fd8674f60e2e2e70049e5b80e9615ce8a814d0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string310 = /2364f199ecada6b55a841e967f23934f3da7c22060003d96874bd9b05c28209a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string311 = /237ee4007c3014829ab2635b0caa1ee4c89c3cbf71e43e76b3c1e2da0931aa00/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string312 = /241390219a0a773463601ca68b77af97453c20af00a66492a7a78c04d481d338/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string313 = /247b2e43787899a0235e4c0e97d819f0e05d3403c30e2d87c8b0a8ca80a74e8d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string314 = /2532d6935c32487a273e2f360f73df80c2a9f57620c865d8cc10b9ccf7a9d629/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string315 = /25879dae8a91b9cb647c49ace109e948db08e6198565f167233a45fb14bfe5bb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string316 = /25c0d247d2a85d8372a542255d8ef45a41f6b43633b0a6869b62cab393490d81/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string317 = /25d4635f8b5fea969f8c93a459f6fd0b0e333150254df3fc8963a7d19dd9a754/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string318 = /25d74d144c6c9bfd48b8746e20868ac4d699d4514baa136e53ee5f60ed02b962/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string319 = /26c6bb7444c17775d6d8ade749c26de554949030dabb6b04b73d69fc5cb10a03/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string320 = /26ea3ae0e97214aa81bdb686d78a7ac4f30debec364a682992ec767fcc45fbc1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string321 = /270a5bef7babe4f56bdb59cb9af2b506d019e33b1d9399f42f361bf5655007b1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string322 = /276920b603e0c97637aa451452128bdfa855a7144d71fff6849db6f078b6f4dd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string323 = /2779330e5c98c950e2a6f60c24efed1824ed30deb5862399f3e3da8a0c7fca92/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string324 = /277a6480b44c253c13a117b1c62717c7ec7f0053a0f69f57c9a4c9c5f9283d5d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string325 = /27c9fbfb654f5b01c554dd9883ec3764c17a56bdc34a701ebd5ae8f2a8fb074a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string326 = /286b57ee049f0d59eac77af0171bbe4d21c5e2e6ea89a0b1847c5b1fea2a9cb0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string327 = /29036ee321d9b71ca990840cc14527ea83a24b968d0443b155a18c388f667244/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string328 = /291e64d8729dd0c25a58e3ed6b377e519c3cdbfa962ee88b15f950e1449363f5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string329 = /293425d211b70219ee0ca753b3fcd56b44c369db44d9a7509614d31505b7e0e4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string330 = /29b1014789a969ec7aafc64bd17de1483775e2199de791b622718bb11be69729/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string331 = /2a306de4565a13893b191df6e8d43b7570c0e3a3d9aa841d6d65cd843f66d220/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string332 = /2a363206ab10c7d679055b32bbd73782aff91263f9325e179a2f03f6bca0f55a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string333 = /2a7c53ab30b10ad3b6c82d1f057a094ecd68975f7c81becd2ba1f9519e8cf340/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string334 = /2bdfb1a641d40f9036e7f68adb158f4acd83a358af9a888e4e3e6ae757ea9b8d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string335 = /2c08ea21df4710665340d0e5c3166db390dbc1edeb5ea9cd00f3d80c2523ac07/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string336 = /2c46b513f01db94c79b9bf4a15b2965c38bbdd8272ad7e10266f5e04a67f16d0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string337 = /2c4c004c2c1a3864c15b74aacb0c9ecf069aa673c59194fd18667aeace3a07fd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string338 = /2da209fc877acf2adcbd7339bb759f38509ce4601bd8ed750648bf75cbed0e97/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string339 = /2e5237ac119b03045080bb330d818526fd76971f28d3ad932277ec529d9aa525/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string340 = /2e7c3414d7bdcd4d36e50ac91be10d6025972c8f1e5e79cb0186c1d2b7c3e94f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string341 = /2e805512f5ed6105f23c5b3295fa9ffb087ec05ea3d46e1f046ca66d4be09076/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string342 = /2ee46ca99e6fe3e38dc9e62bed1519080a75b35d947db0f27435a062375f51f4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string343 = /2ef7b1aa5f0700ffeabf8464a961bc844a884fe75103a322b8c9d4d135eea212/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string344 = /2feda61b4bfe2c6f693f3201ddaec6f08a2df01c63234e933d9041a2e37a7045/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string345 = /303d4a01829c4696281be3b506ed99c978f5cd2a093af588b6a6aa7d5eee2096/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string346 = /307298c8eaa57cbc7357324ea06076f648904d20bb3cfdb2fc26c21f6913ec62/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string347 = /30d2134d69653bfb682dd27c1d6e6e7121080c7e60409237fd15e38314a11bca/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string348 = /30e5dea7e4567756d55f7bd13dfbbf4b12d9e585d8d47cd18c700fc632ffdff0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string349 = /3150f104ac2f5f1eead627411f14fdc43e50e18aaba185cdfba03cd99475dfac/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string350 = /31fd2609d81f188c2a778d818c851f56d845d346036cd76283ae7c12d17f05cf/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string351 = /3243a9062544c25918f589d8dbc60e49295bb60cf906e10b532ae83f7ad8cc12/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string352 = /32abb6de73930ce62b7110f0834327b96444fb25939b2ffc4af153faac836d84/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string353 = /32e696d3b380f40adea08a359da80575df34f9130b392f10666fdff9e443769e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string354 = /32e852ed61681e0f498dfd901863b26277f5f0313e4469b4243991be4f3bea07/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string355 = /332346668c99d0c6bd383f9a0f6c32e7ea3cedf4788468d1d373d3f106f4469d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string356 = /33a286f3a77dd581011f646b2b96e6ac55f2d6a7cca7fdc3d4a0b45d063d912b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string357 = /33b7357209a182696c26be19723b759608d453a6492e9ee57abf619c7c44de61/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string358 = /340ce55adab1112723a9947962c3557daeb2ed12fdb535f99dd8b66682356ebf/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string359 = /340df9bf5aa4527010e535905f4e4926e70b7d6b7716491638a920c37d717a34/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string360 = /3425d6a0a29537eb9bc8e98680cff7dd16280122f59ef4eb03d7a48760c053a7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string361 = /349f76bc4ae2326df15117c4b0c20a5e8a0f3491e83e7ea15fdbd02d67e45e8e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string362 = /355c68b197356e23687866e8ea8068ac29b62e3bb4657b9180729eebce44d7a9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string363 = /35d295a5f04094a88ddf9c0704c8555bcaf980d9eb15505549f2ace647324cd6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string364 = /35d9023ac28fe49540ae16d224a8edc09c97a12edfea883e48de778730cc2d3a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string365 = /3655a757ef5f8d849bb61132c30e20848cd88ce2233abf1ca71e029ec7572fc4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string366 = /366294485d6a2c872b0ebf033cb129a23ed2fce4ca2dc3e7905cb49a808ba7a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string367 = /36b45b5ab3cbd980c5ca2c3bd229525e7dd937a0eb2e53347dfa2671cf27d859/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string368 = /36c6bc3f7f5efd96f7bf472d30119cf22142383adaf774b96732b27ecefe9159/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string369 = /36fa3d212c2159c8e1b769bed63fd12c77cdff60f3d13e0b36a554d8e82d6f17/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string370 = /370acf4cc5645e10b1633c5df10fd5331bef377ea731e3c97e05b5538b4266d5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string371 = /3768f75f13bf1f58b77046be2174d666f05006a8a139cdca85bc5cd291a81fa8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string372 = /379331177374643353a85fea9cd5934f1207a0fc6bb2370b658090240263ccbd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string373 = /37f414a4928417fe375e6ba23c4028681bdfb1dd8d0130b20260caf3a4d33485/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string374 = /381135de47985bd9d5079830dae251313b9f08458da9e8185b6253d8e477fd9c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string375 = /38189c5fd3ff9946f4498d31e11bb47e49e276e445050f1b9ba9d84b40e55c65/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string376 = /385a18846808ae7f07d1be33dfe8c850736eec33910e1366fdff14bb4384b690/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string377 = /390b859b5bb058c09998a5eb532d819b4977924c81a2f3ddd4f36c4b9d26f2bf/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string378 = /394cd66a9040e0c75a2faa3f9108029689df136927665573bf4a457f58c9a798/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string379 = /3951c1b03367cc1dc4de8290ec9507dad9f239a53b815f09691dea5a78c00901/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string380 = /39666b5eecc134e2d6c22ef6233faee7f8556383c82368b98d85ff106931f751/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string381 = /39b7a8fec13a9cee773a09c4f277a490b07fd2dd3009a7ee9092165688d7da32/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string382 = /3a04d62f46cebdb6a568e6a9099106314ca6398f9dedd2e5433e3a890505f62e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string383 = /3a2b0667b9d4537180ef1bb22133b58ddb0f6dbd9941e603277d293884c9c2c9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string384 = /3a45bdd0bae1a480040acc8ac74814d9abb904240b4c43e2fc8e730c69114fc9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string385 = /3aa2845ca86220e20ba6e4f2f08ff1aad9aa4c2cb47c38213bbf21e7fdd87b03/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string386 = /3b2aea9615c1f94c724af17885c4587e9818652ff92e4debd002522e7be96a58/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string387 = /3b486b14426ff6bb3e2c4e9d5d92821a50d5ef26f32e9ba244ca73fdfd81ec66/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string388 = /3bcdf1c4ea5d312b3cd0fab543836f842e6121997c9ef1ac2c68e68779745213/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string389 = /3d63505863fa5f18ff990c4686a21d17fd618da9ca2490c22d0f7f5045f3581f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string390 = /3d99d90feac8540dcb9639318d5e3ef96726b11f58d418d08023117ff7fcd9fc/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string391 = /3d9b9f20cf22e17016d2e46bbf85f4e1dbb605959e8ed288bac7daf67cbff731/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string392 = /3ebdcf2fcbe2c7439b0b0e3bc4dcd00a4fd4df7f02e88b160f085b35f5d2f350/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string393 = /3f58f14b7d8ecab48c17849a6c6660dee3f39e95ba3799f9d77339fa6b7914ed/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string394 = /3f79ab9728d5e9501fe4e9d744aa42f755f2f085c3edd087747c88b8b1bb31cb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string395 = /40af7b934df0673c434a4a92effc1928ad6294fc0ebc627718883645f0f42b58/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string396 = /40ed4b2a45d5609b78ee36ff6779e51e932bfc50363ca6ec7c4f598d44407bdc/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string397 = /41150be536a30cd95e14bffabff19ac925a283b03425f69cdb0609e428b2ef3a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string398 = /4161e74ca12ad3a932dba34cf3f9eb2759b66f3a00cfda052381be4304454250/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string399 = /41d36c482530d7d3a3876cb5d8f5e3a7ba35d154dfc0ea4f73f9f8793f92c387/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string400 = /423fb953bce17ed5848e1fd48440846cb259a2981fb61906f94491d64e131728/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string401 = /42565c3d95ecec212407c937415035ad9beff85f000036ff05fd9c39022a57b7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string402 = /429be1a6cfaedaf84394b9c8364ccbfc353788f2332d6143b0131d48d39eac22/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string403 = /4370e110d8731b6b6fbb98d9ae2ffae6a3b00a8329b2700e86b15e1bd97166c1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string404 = /43b5fbace7d714684822e05f4ceb05e77ca3dc638861003086a5ea96bd7b0257/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string405 = /43c1a32158fa01f876c670e53c90f43ebdf4cf61f7b8cc683f06c0c76250bb1a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string406 = /441ad151017dbc879fa10de0f4b090d296ec028cbdd5587bb72a62e521c21157/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string407 = /44321a4dc67e158e93fd037ef197dddfc4e454cacfd87f13964032edcb4b3478/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string408 = /4477af81ed3e1c76c637314311b3923f8155896ea2e18d5ab2fa6508f46d3b4a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string409 = /4563bdbbc58eb60d27a45341223221e593db4873f378a3b018f86998187debe7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string410 = /4581d0993624a9dab870f29d66f0acb39db89b818de62d8f345de3155340066f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string411 = /45cc6eff2c3a6facb1aa9e31f2ce7d45d7b5527633c54d9deb5de1f19ffc906d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string412 = /45ea038d3721285f2759d8c8f3740cbb9cb9400a0cf76d11d84e089bd99ed1a9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string413 = /46281222e0c038fb6b34921405aa98b5adc07d97f0074e1eb9488cab9b6b7778/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string414 = /469796062be14876fd4a7f37c4cab22bac6ccee6a9c3e90c696b5901fe22f13a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string415 = /46c816bb93ab1d318a84b7295969a7b9d2b8a728f5a6af52126119cc74d26d0a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string416 = /47164ef76a78406a70ee1b88ae4e31230ace7ee2ba6c3a56b0b9771b75e14fff/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string417 = /47ab8ed046a22fb188930af037aa05a7f74e3e39331d56c32d736589f7ac78b2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string418 = /482882bd61c051edd33a9b31d03430d6090bcf031102779c66c7adfc1790d7ee/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string419 = /48356997a701c96f9b96b1d2dfc20280771a112f2d03b0266abb12e24562456c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string420 = /4876fe3093df0f61892c691ecdf0db052d77c461fac698b50d1fd48e927bd2e9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string421 = /48ca254a725d1c4b6422cde2faa8777559f1513bc9bc032f05ee433be8b5fc55/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string422 = /48f877f4424e0357e506fb65e0b673e495a092c3e1a2b0a010451defbb46c817/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string423 = /494072da9b54381c4b40e55e6131db414797d450b562a67c45168fb3bb46a07c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string424 = /4962402d7407375db7e69c2d731aec97649668214c27c82b46971733a902ac0b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string425 = /4984f4ee968fc246b4df6e9d6552753a98e4762c8cc95cd9693ffa815479d8f7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string426 = /4b1b36706c5306f0084713e926888ffbe0fe9bfbf1b0bdfeef950b6dc531cb18/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string427 = /4b7d328edcfaba732d45ab408f53cf991d87f3e0a2dc2c0adc203885a0361d52/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string428 = /4bb2d035f0972ef95a71600220648cffcc25c8f6baf5c96de7a0eafdf509ae04/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string429 = /4bd5b2fdb9820e93e3b29014d3902ca9f69c0306274c8cc4723ed606116d9a50/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string430 = /4bff519a79e681ee5bb9b4ef66794344224c2084b36cd947ac29646a5687ab64/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string431 = /4c3d4cbeec3d722929d86c0bf19108b3eac090fc5dc8fcde2cf818ff16e6fc5b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string432 = /4c89adb840e2c8c3dfba56ae1eda0447046bcf0796108ffc1c2d446fa3c5a200/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string433 = /4c8e4b74f3326949830cf3974abc31a71852f557ae1bb9d0f4bfc1a92eb95b01/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string434 = /4cd39fb92aaed08de5753a2d62d3ee8c29b9f97ba81b7ba674787a3cbc3bf02e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string435 = /4d24f3932f028ac9d06c80770c3390ec3ce163d6e07344b4e3daa9c93061192d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string436 = /4d4e0c87fefa1a01b8a55af43a2b13c41457e320292d537e4f3f9b160de0e80f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string437 = /4da7304d47772ca23c20710b9b2fa51466080b8f2c6cc3168c908bc25cbecd10/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string438 = /4db3484ba73cd09d06aeee140adcd85fb6c72fb76d05a86ae95fb27e9c795e45/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string439 = /4de29767842d979fd17a50becf0295588a1578b793c5415032847d684f54e445/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string440 = /4e13c7ed59d350b0f0b92062e063afd574452e72a74dd3ee0b5938c514c85749/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string441 = /4e28d3cd00dac5c63ce16fb55efc2024a7d202074013f1264749cf462f6dba03/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string442 = /4f83c68530797e82a76434950e56e3512487a340b5b4e24cd9f81be4eb9e9408/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string443 = /506efcecbd3508595df39add1b44c29682bd595e2b1f6ac11476baa4a5ddabc8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string444 = /507503b18f9fd0a2ad51c175946c3a591f84eade030a59f697c66991771ee8ee/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string445 = /50832dcb77c29cfaadcf530487eb2e4430ae79e702f9866321a484d8d78dc28a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string446 = /5185180b07473697f61c454d099076b300aaa04c418b97775f7bf70aa6289154/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string447 = /51b9750eff6966829371672c64e5bb4f36f336d99a66275c7008ef1edf2be19e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string448 = /52136cb222124a4b78b9cef3b9bd9e1a18a6687043597cb95138aa60bd26c76a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string449 = /529feaedec43ba6c1c4b0c31ab57575e6751fa894c90364ba81732de04bb3b44/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string450 = /52c1a841d7d5551195a1ed8766dd7fcae0e5ad10efe5bd854f541e2879996f1e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string451 = /545769561413f19fbcf5a5593b70deb40d9b56c0acef1adb4854c98572867773/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string452 = /5461cba9d022a943c36a95b7e1017274ae210aeb8b204c9d3a9ab5dcb40c90f8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string453 = /5477fc3d91c7db260acb251e6841c513b42cc0ebc9e0b794e819acbc65fa01b7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string454 = /549f93a48257b5d2003ff8faa655e0f8509f53d052eac0d952b06508caa05ef9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string455 = /55199d5089be9072f5e556c5bb2fc11a3644fec2e652883e2b4da20e851552df/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string456 = /559917334e8dd6e6828011019d20c15f23ab49a9747a08aaca275c6d44a5d811/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string457 = /55e9c45179e5688405513330884f614cc9d97b9bef74ea64c3c6d8dd992a7e9c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string458 = /55f8bbbb112a0bf874c09d9a908fa42773bbc0d9ce3495bb2496b60900e7f09a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string459 = /566e27a6f2a96e268b6f21b88db8f3488739b0d780e82ac516b3ee14c5fc337f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string460 = /56d4452909e80c00ed7a13c08ab27673b286a16d9b083a516edb7f45dbc0c4be/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string461 = /56e11018851e99a4fc3492eed467f1ed59fd663b366b49610f2b5c9b891b167a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string462 = /573ea06d067eeed688c7bc60b367e0b47059a6af03ad5b4d53bb90549894a0bd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string463 = /578bd74856cec7caa02f5f6c53d9412e06bc7eefd6c5213ee8f767a91d88c4c9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string464 = /57bdf28c39480b3e91fd8e433dce4c9f032447f9bf1947a7b8362645ad213732/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string465 = /5822804140e537314665856c9453da3cd786ff9383997e2b9b5d313d32efa0d7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string466 = /582524e066107d16e7e3c95046112a8511167405fdf6e8f92f8352d3653e61c4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string467 = /5863244576fb755560b02f19192a13ce331de82e3fcea5b60509966da90239b5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string468 = /588ab29a14df0313167d12053095f2959f0f7e28206a60f3e5c86cc939c0d89b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string469 = /590e6b85b7ae5a1572103332c6cc9494a13c65d33e839b3316704fe79c998f65/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string470 = /597f9482c4e355cb665fbd02bde2b59133e1a364744cbb41207c68e1bd7fe3c6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string471 = /59ffd99e0fe7d354d185bacf11949be89fa86a88f40ac4773f33e784279b31cd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string472 = /5a56d5caa6847d283e27207b727ce27a852b8a567cacd7b29f6073a1458e494e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string473 = /5a57366f655b5bf5b500769847d1b055d3847065703803d509ff2fa83837ff3a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string474 = /5a9924bf1bd43eaa25685fa21d111909aeab2952b8c7eb67aad1b2ec43b4054c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string475 = /5ae9e28dda38df5a339e0f02d4b318e9e6e48a9abe916bb4161a80c7eac0da1f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string476 = /5b46050219c918b47dc271a458450d384c4691f9ff96d174856946ff3fadffa9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string477 = /5b6250d39e2f2855743616842353bab496aafcb7bc2a45169a54bc94f7939917/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string478 = /5b6868ca1b71f60e801421d7f1629422c0e894bf3c4d0d45778a483ca3d8a41a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string479 = /5c899d6ea0bdfbe381997096421365463461811ac73b1f3d559aceb765a26472/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string480 = /5c9765e765eabf0879fa522b08114cf379a2a8d3a6d92c4f9cfcb1ad49a9cf5d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string481 = /5cfed16ae88f9a36880352f6490b9c417c8d46744a606e453eabf813f26f1239/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string482 = /5da9049dbb09c0f24ee3732e407eb636230a1f8b8dea5f40e74651102229cd92/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string483 = /5ded3e0d1d7d2261be33496b0c7e59c8b6604d6cca0f371caa669d3f47eb10f0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string484 = /5ea7260956640dae112bc2bcc9bd1e0fbf43a6efccd0cc56d95cfecf8af241b1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string485 = /5f27ca4597ebd322f8fca8f3f74a1771d0e5a3f2f9d53779345f73f62c9f5440/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string486 = /5f2c1a61ebef09dd554f3e9db1ae4bd1a516e69b39375948614573aa8e853cac/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string487 = /5f7c2da21629fca7b712829f2d3579ef49af424cc00da2dfc1f4503afebf9eb0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string488 = /602d67f4b63650f0e935953440895184e8edf2b4eab7bfdcf134bc02714156e0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string489 = /605e19b1230344fa63de6979e952594fa3505e47c91b5022ea0334971e6fe812/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string490 = /608dc4ee1e7301aaa26bf7b95aa83ff1b5464f366deb206c4c148434e1970ccb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string491 = /615ef3781d2e2edf36054417bee9292c51737c9782ab174912d18f0b94de2e66/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string492 = /6174e3710ba961a7ac54c781447de43a120224b7def9fb8dd3b15c7e5ccb855d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string493 = /61962c854aa17175796608bf590ae78f3dfcb37a74463a47114b3cdaacc7fc9e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string494 = /61b9260e2f3a75f5ab48bf3fc674810f1afddaa4d79bf670c49771e5ed4c5277/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string495 = /6207b3bdec3775c783313cfe3c278c5d844ed035efdfa02173a23644206d3d97/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string496 = /62d75a789031b5af31711cf4c71df20312613cfbb466ce13f11d8cbd04246872/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string497 = /632b9ef95949f0b11919a46cdb0bf586e8a291ff7c13ce44ba0b0ba83015050d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string498 = /635cde05365898125638645ecab1f6cdb3136c06f0882c2617d2046a2e8f5f27/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string499 = /636b4e445770ac1cf66687e9a1ce57347221eeb539f14fe4b0b60f387cc41009/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string500 = /63794d03a5550be74cf88df14b42968a7e23a58eea0690d23fedf01f57067166/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string501 = /63ef9e8f57db894995c6c89dc58c854d529b8480078b5b608cc6e75722f4c713/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string502 = /641a94207f95ee2eb5cff95317e1aab73db6366fd3c2e5942bae83f0f3cb666f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string503 = /64e4cb3e5effc17d4b5cf14a8c8a095e9edd0b089ecd6106449bd7e95a961310/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string504 = /64f05121f9c950fd6146c9d91aded76884e80fc69825d80b688b113eb8271a24/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string505 = /65774c65f7813f8e95a746597c723006732bf331843e2ebe92c19425b22139a1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string506 = /6584e5af96fd6148ff49ba1c19fd9500024126b231bd78c331ae66c8f45956c9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string507 = /65efc0f2db588996d96021ce4be127ac2b18800d9d35c8a1a5aa7d3140370330/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string508 = /6641564c893c3cb1dff02607a922afdaaa48ba93b0bc35cc90094fb653ee3dba/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string509 = /675936ffca92c0a0cd91495a62d395bb5c2ab3752f3d2451a821af2fd2f63fb6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string510 = /67a5ff45328aa8bc9b0bb4a131dfe70a82bab7ad6c44074c9973421f27ff4fa3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string511 = /67c1cafb276ad174a24340f989c220db9a8997650b2f86cbc95a6979e73b4287/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string512 = /68176e317f4294f7ed8cac8f270a3fcfb1a03000831ea6594c374d2318e976c6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string513 = /685cc5e58579e5f5a176e2be355398579f46cd64dfd0a0e82edf12316fc33b5b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string514 = /68d9f28535974326ecf0a8746d0c6e8c7ccf4ac464f083eb375f998f2eb52ab9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string515 = /68e3ce34f0d904e715ea8471373abc3632bfe4fd945e1a4976baa18d003dff7a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string516 = /69832c96ae4e5d3e7c006a6dd6a86322875f834306c9ef31363f0620a714ac80/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string517 = /69927f9215cf2d0717141e91851febb1c045715a11ebf9f55bc4181114625d41/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string518 = /6a1d90427fe92c1dae2ac16d5b0e7f6b2c823a1447cdad213cdb987390329b26/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string519 = /6b34ffba8e7ce5f0e5e7c157d7e65d320850c98de350d332421e8373aa9fa3a4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string520 = /6b6ae7b2bf3914eead08418884e8ad8121d7f5649424cf57888a884f1461f9a5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string521 = /6c66e4607984458f090c74149dcec7dac9e024d6e3f329cb85ae26e7b8d93d42/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string522 = /6cfa69c4afc8b6bc2e33431b1d61210b51b3b5f204486dffe202d64a4ab73d3b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string523 = /6cfa85f07f3c529fc3ca479c49104de7659010b3ca139ba6c10f7846c0ccf061/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string524 = /6d97644d0cc23ec724b2f6ec91ac273eedefd5d7f2c20b7b913b4e9ff582b183/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string525 = /6dcf39d63a055602fdd1747fe84392641926ec16ed9aae3c136d2915ad83bdcf/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string526 = /6e909861781a8812ee01bc59435fd73fd34da23fa9ad6d699eefbf9f84629876/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string527 = /6f0f34a9afada52530634afb65d734b7121ad6c6d5690f708c7b4ff14572ada5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string528 = /6f1cd2444be1742a43e643df851e0d3dae010c782bd3e05f95b8cadd2c15ec18/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string529 = /6f49763e098fa4e3fd13ba7fef3254f452ac46381f56f4177471932b9f00eb45/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string530 = /6ffd1850657b2dd46a03b1f2988a7c8d153943b6b7dc711c12a3c96fe77288b0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string531 = /704b2be6d3339668a2c4287473fe08261ef23808efcce1a09a0173e514655a18/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string532 = /70cee544c4fdb709afd0e36f93a68f289f844d0373a53ae1e7eb257f7410af36/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string533 = /7103d888907045c6387e39b275db1a7e6fdb22d3d6e15ac6a44ddb1df80c76a4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string534 = /7116769dee3a57fd5aa99823a89114b267b47902f5b71c29e6022926544c36a3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string535 = /7187c30cc73eeed90f61f91911272ae2868636667dfb30862b54aafb4164794a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string536 = /724f896a9176d6559e7ee09e6c2722665beee437b19869e316988a758b735809/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string537 = /72943e841e721066a5db4d3c3c3e03bfcf3cc275802893e1bd678723e7c82ede/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string538 = /7315b2a962905112c0a7172a5efbd5392d27b059a7c4a035eb38e39bcf2e19d1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string539 = /733366cd878504e71534180b9d93fa01139ff82e4cd2f61b15f1de71bd292fa7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string540 = /733fe0591092a284f149d186d66f2435a6196769cd34f65909a23bdf1e907d84/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string541 = /73694f7f3a47359e3135c4da6e4eaab957047d9fc08ee8f0367d2beb5df4ca2f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string542 = /7372d0b75d0e1e78951d47c88fdba0bf2f04eedf7b12dde37afb87d2622b6426/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string543 = /74c46a8cf10e17f507701a84dc429eb7a7a276f0d8e15b4026a3242a1bc0a625/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string544 = /75374c3f9c0ddde44a47e4a780f2ee779e2a1350d8cbea052708b20cdd289599/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string545 = /75852d74cacf2d568b1729555ce3cf8814006764fe4580c6aa51c51427558534/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string546 = /7599c19b85ae59e83faafccf122bef1d93a0642018c4052b09a56dae06272311/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string547 = /7640c7c4319797fd280939186677d05362a592892b6fe65f41dcee7cdb11fe36/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string548 = /764bb35ebb1011e7bfff6991af628ee1ef56119f4e77d5a893439e40101e3ed3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string549 = /76d3b949f37c9e74abb3b4bf91727c4feaf3feba1e32a42706a7843cf83d5c60/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string550 = /7739fe1e685d5ec7296d83851614eb9cedaf7472aece8e1144f2b14fa544db57/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string551 = /7787d9292fae90d6ac9b4b9e691ae56a08e199ea96a974d45c26bc5cb30f3d8e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string552 = /77b587e37104e7a1e8858e76cbfa2580d8633ce37c836e28c3ebbdfcf3db0571/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string553 = /77ec2daecb8490e270bf628cbd585180731178e4a859e75c833dfcfffabcf34f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string554 = /78a8a0392afbefb487d65be78caff5efb2f2f55de2593ea90c0ab23ed727afe2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string555 = /78c15e32aa0d34c32550129f8f40cd76da56bef72a5efd949f92563876a74975/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string556 = /79f4a5f47346781f2b5d7ffbf570db04e0410c435b5bf993ce4e3e3bfbc6e850/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string557 = /7a32219b9b7ba4fca2fd03d0f2387245b9f3049521b9076a5ab4a21f57bb977f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string558 = /7a40166148f77773238e3e5ad7572068d0b935303278f007c6c75dd3e9e302b3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string559 = /7aa90fa85c912e188d6c8d0668574285af14157c5d7b73e48d339d8a3f5dcf67/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string560 = /7b05dd49119858395e365446d7168cc725a999d9d98b7ccabfafc3b5da7a6f74/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string561 = /7ba12c9d99dc22ef178a75886a1c843302e65906d7c15e4aed54066fbae41667/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string562 = /7c0e4bfa155808eba7c7c65fb62dcde013f4061437e1622f3fdbc255d85d38a1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string563 = /7c935380a6f783ea10d0b8358d323f4238398320e1feada66ab08051be6982ed/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string564 = /7d573a4e6b5f9864b7de3e769d2154d8a38119656b0900ab6e93f44f46ad2fbe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string565 = /7e54ae9d348b3235d8582789274b78d92907907478efc94939204fe62921e1c7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string566 = /7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string567 = /7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string568 = /7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string569 = /7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string570 = /7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string571 = /7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string572 = /7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string573 = /7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string574 = /7eb70257593da06f682a3ddda54a9d260d4fc514f645237f5ca74b08f8da61a6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string575 = /7f0b1f1e301cdf0058203bbaee22dae51f023e73409ac60278da05cfa0fa7a23/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string576 = /7f2b0703267297d62119fe11c3f8846f9fafa906b6da577e4480f5fc4914c3e1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string577 = /7f64f0074988005bfda114e773e9cfcd9fe700f37c779105205153430d514ab6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string578 = /7f861f80620136ae0418cecf780c0c4896b4e7b8763cbaa232104ec7b99acdf5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string579 = /7f9d8f3147127bd0bbce2ac04a05747ca2a7ce962c2584b5be197ee75fcad18c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string580 = /80b564a22ac44bb773a8849e33b043617348eaac203be63f87d2bd0ec75f7f30/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string581 = /811d06dc2f9560e4d3697c2a5e2aa39f516a582c70ac88e33468810905ced6fa/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string582 = /81cd3e0dfad46b8baf1d60ca5487c459fd64fdfd31340964ad6b4627605ceb5d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string583 = /826edaeac303c78994a597c1e2ea0ce81c4ab628138b78677517661c32653523/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string584 = /82af85387456fa6a4f598d88cd6f575803e1878d17aacd765c1c6fc19ab9edf3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string585 = /82b695eb37bf703a0c7fb9242f50aff9dfa000d464c5b2c368a8693a5d1adf63/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string586 = /82dcce571a813e9a942b3a6f0c8eb8d557fa29ce50c9ea5516526a62671fc153/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string587 = /83b1ddfa24d6f81fcae9fe687185dab70e97957b471a32e69d88d9b0acfb9d7a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string588 = /84d265868a788a2888bcfa2c6d34021670787c23a4bdd60fca1334248cd1f3c7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string589 = /84e42cfadcc56fd72ad041ad692cc880eede230412bd6cdc3bcf90523b10a98e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string590 = /85fcc2b2c19bc9355cbe509a9ef3ebe10005f1c8a9887df12a6295f25008d260/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string591 = /8704db81460c783dfafccc4414e9346aa6eeadcfd09984c26e5f1e4e895238d3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string592 = /873fdbf2756b2826ee7946770aacd8945e3d3470cb5ced3a23c36b0a988d1b1e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string593 = /8760b515dc5f94eaed37ef0ded50d083cc32e65e5b430089482c00fd40c0c555/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string594 = /876b33b3871778abc2ac0523ef7ef9a23302eebbac92b193ac564946207f9477/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string595 = /87ad24ba9c07337abc8310c7107359fdcf86b9e182b7b93e1f375888fb82dfc1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string596 = /87c96e5d650e67d985bdbb2bf4be55c94f8b967b180d45c1c073cbcd57cf1ddb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string597 = /886de66b761338d87027254c40da3ea0fd9072fc301c1b8fdd2e4d652e231dea/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string598 = /88a56a39fa828dee79620714e53285c2c5bfbec814e64ab150d8795b0d78940c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string599 = /88c940e5e4e3728a9433887cfd7eb308d8d4e5e24f5ab49b3c13dcc595da89d0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string600 = /88e3cee91cfda389858ecd70bf3f9b8e45ce7d41761cb7b13075e8d003724007/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string601 = /89b8e0c1afe4680c8f02e517467a71a4a2559f41792565bd646f0127642782a1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string602 = /8b181b6d9004ec5341ed9adeaaf5f43ece0479da86687e7f3e70788d282df356/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string603 = /8ba79d96e4337be960e4dd1ce94a622c08391da243fee05a44d303de46f9ae93/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string604 = /8bc3958a70372ecaeba0b81e287692297974848cc2ecf053ea7ebb9dfcc933f8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string605 = /8c1007a1d0abce7187cc43079832d6b2b9510aee7c15e1eb2f322d8cc854cf3b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string606 = /8c34fc93d2e71f3faeaa17b1507a70d87e09ec7bafd7922dff22ba887c304db5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string607 = /8c936f3b5bcd9dbb20a4d0602cdf26fbf3efe681134f20e510acda6561526623/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string608 = /8d246f76d57dfa40f287d6d37f3a43c343b67c5db31f728d4568f2d8ed2d2799/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string609 = /8d2b6767f4a99a2bf89c412dd27424aeaf9f79ccd0640ab1257168c895c85f36/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string610 = /8d3129341c603fa22b052f925fdf3bef054327c081299140d3c484f76254ca87/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string611 = /8dacc97038a845b73c4f156f3fb4d00ef5b4cfa7a8e6b10e0bd8e5c918d62fd1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string612 = /8ddfdad7d1865d85b87670ebf29a4fef1f3cc42cef56d1785c8ecc21cef6e55c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string613 = /8e222919847637b1a4c781f780722a7ab32a1e3d310b91496fec82fa38952409/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string614 = /8e348a738400c38f4fe75a08f7b63e290f4b06204552190f910d39e24e61c89a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string615 = /8e7eaf585d3bc9f87159ff49850b074c42a7b192ce6540b06ed04ded87ba0d92/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string616 = /8eb06c672abfaf7de3d0f8b077737415d22b502f08160180771f8b6aa5f65545/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string617 = /8ef891d6334629876c3c94569c9c35acd3b3d2b6930ee1c90086d715e120a40c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string618 = /8efd5b8fbdba3db4ebd783214b56dae23e329eae2c7b1ce36aa59f0726cd35a0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string619 = /8f13ce758ca663d93b81c6db2c658cade683058012e65cbb066a82dac4f58311/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string620 = /8f3fc1278c3632af8725bc717de00833c6710b955372756f30b4ed0a6cccdd0f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string621 = /8f98671d7d96d0e04df6f8510a65f4cdf1fdea2978a0e0a67c998274c40051de/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string622 = /8fa721d35e169cddadb3a6569755c20ce19b9336125a7e5692bd0f76ee276911/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string623 = /8fa721d35e169cddadb3a6569755c20ce19b9336125a7e5692bd0f76ee276911/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string624 = /9036e04e3c1caa4b91d008a010df98e93449cfcd1ace8922d96883bd1587764c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string625 = /90a9080ebaafb4fcf1deb6e6810b4cfc38e0c16b6c9849969aee3a23a730db5b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string626 = /91ec53f564ad02117b9d7e868c449265e99b4b7443d3a83ffe55b3b49d5be279/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string627 = /920c719a1e1d8509b4f2a46062887ad5d09cc53ef907cb3c58140a9eefe6522d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string628 = /922b54e9d685b1bdd4d04f7b34c9f42b5f99745325a65f3147c719108d7e01c5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string629 = /92f28921ca0db8a0c7c1a4e18a9e9dea53fdbd902b3d3ad67444f59a21a96d5c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string630 = /933a32bee8a72a28653b56cb9b013f67da6510d4ad10c21333a6e930d385fb82/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string631 = /93642234b0a16f0af2ebc99eb13287ab9b518bc5784358ee7d8166d3ae254560/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string632 = /9381458c6722bf9307b870bfe07388ed787f229e93d971287883d8d8e490bfff/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string633 = /93d1405dfa8765ab3ec43d1912e65ae89b8b8d06ddbc570f8cae0ca46dbf5007/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string634 = /9421b13f1c89ded77d1964b6e7032e300360063fc9d79b4afd432533038725d4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string635 = /9440cc0475d27f1b73944b69fc843ef2ef2e8fc407d1400502c49ee20291121b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string636 = /948f609d447e622613e2b02500ec333867849aee711dcb146be75ddee92dd02e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string637 = /94a12554419e378df4acc76c0725d141738ecf1f991c74445d1e23c655278747/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string638 = /94beb306747153d234f7da1d2c996cab68e19620e87d9f348979886910eb09cb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string639 = /950fd036a54ec99522231614375eff9aaa6dfff0414090b24b0f394c7810e408/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string640 = /957e5ed833379f0a82f9424055e8b4159bbd205c291b1210bccf689cdfb22d0f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string641 = /961281a6a9502553f68b61f2679a74dfd059fab22328e6f8dcce70c9dbfde0e2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string642 = /96da4a94f18030d87385e954b03d72c51aa2209acc07fd947ef83b89443c905e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string643 = /971193eea29201f09ab21c42b5d03c63a5509d81b42158c2cf2b81bc8851ee8b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string644 = /9839381c8f3e41010d167ca438c054628ea54b7c53231d444281fa217d30fc45/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string645 = /98599d98012adc240e17c6b157e52bdf7b1831e45164d4b27862189c462392d4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string646 = /995c3ae92109046bd3bc58025b09d449a695a82b1bf5102b96091500419aabdb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string647 = /996e6455c47cdc9a046beeea068f06a9fe2c88d45d13fd055145aadecf23657e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string648 = /99852761bd4acc0025c07c147c56caa540b7731be755254e9c85b82f25e08057/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string649 = /99df113d5d44e960f503152ba57985e95e20d3491f291046eb091bb0efbc327a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string650 = /9a9db09b688d52c14792db24734a7aeb90499da5fbd78c9fe43c63d0d3ea3378/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string651 = /9ae751fb94283840a31634a56a3d2a8010949694378a1ae3fea51acd98b52fa5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string652 = /9af2825ac48d01706aa0e6582cc477b4e1a561bf4dbff66608b68031347b8559/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string653 = /9b191adfb91bb2ee0881f26917a18e2079e054d3d69c5bfcb9e3dff55d9c0c16/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string654 = /9b8901200d2f4fc535e25641e40d767a095a597e3d560f3b459d5546d6e3e551/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string655 = /9d21a5677266c6ff348c79d69e7d2908e121bd5c4d841e9cb4eec90d81ceddd3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string656 = /9d251c360046d1bb6a5a0d0e4de7c307b91044aa93a9ce6dc74820a01c5bb745/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string657 = /9d6afdd06228c999288c7eb473b553b8808587182e6dda734f8fef44ebd1066c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string658 = /9e1a4c27fa18f0126da8e2ea83f8c750e83d529c9fd6897327923c96ac6b3b89/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string659 = /9e6d326e015aaf3634835f5f7da3579ff477c5b93ea43d349b819925e83a7537/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string660 = /9eb0701865866d14eb8a85cb2801de1963400fac29467be8e4c253212955d06d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string661 = /9f9039910ee089cd67d3771229526bdab9171ab559d73c2f97bd25da459c6155/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string662 = /9fd5c3497f76b260c02b579d0d5bf95cef10469e08b02d1b1172a046c35ea07d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string663 = /a07f6b1395eed1e18701aa02692a381226f45f9bc51d8fd1ec0b800d7583f196/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string664 = /a0ac483af35fd96f00e099dfea72fcd1a07c0d946e806212c73705a7b82b7b32/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string665 = /a126db530bf2f613db366cf3f51d7a6f1894a2e6ccdd062eb1c454305b4b29eb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string666 = /a1b10058ecfda37d1e138537856103279a326ce5bf8fa3ac1ab8909aed8632f0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string667 = /a1b25d3133a37cefe944c0082272520694f00d4e233e7644d0e2897d433f1bf5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string668 = /a1dd724e09ca85a8265c4486f699ab32882e7204a09f895397ab0fb02e37559e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string669 = /a222df9c30fc7adacb7553a9899a3512e18b9e8d2b735bcd5210c800ba99b243/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string670 = /a239aa784fa1dfdd3bb50c20c21b03dbc3ce364f940bec5d23faca835c2e5417/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string671 = /a243a5df3e04b3a555b3f506b36037d0093a22c0b8e5842a8890bc4610855cdb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string672 = /a2b402f23bed2afebdda5ca21f7bc705a021ad86a35676cd3b55c7aa56406e0f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string673 = /a4635952ba5d7927ceb57a1533c38a7a55a4835de85c4794fa85d863866d5588/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string674 = /a4fee85a73d5192f1daa887e5357eb1304acd73425842f7ed690783c2a27a26f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string675 = /a50cefaf5e3c111224055a9e3e4d289c7c44dc0d8405bf96a52f8c6d254aaeca/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string676 = /a56757ad65727fec369f36a7c892618170bcdf89c22712d1c4010899c6ae9239/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string677 = /a5e673ab3d8d4159b611981668487376eb2c61e3e3715dea1b50ec18d64eef76/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string678 = /a5f10cdd2cd38b2b33a091c60f0e194aafd3a2de3ccbf80333882430a90034b6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string679 = /a60cd6fd8facc92366caa76747ede2aba9c04a166f55d1ae6b84b264d0f2e5b1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string680 = /a644596787f407d005d3de5a3e02316c788b40dec8c5fdd0b4c010edc771677f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string681 = /a74bc97d32a17a7c5a401229100635b8aee9907da5b6e6c6641ae6af9a81b7f2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string682 = /a756ddc08156eddb07bdddea3cc3c75748f854e4c0388e90b17017fc55bc02b6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string683 = /a785efdc2a95072fe9caece4fd872ae1f543777b60cce590a847180c3926a9b2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string684 = /a7b5310c9d38f7242e05c42276f3f8cfd3724ce9ba8fe7ee13bbf22e5b1f9092/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string685 = /a88f29ebf454ddc490c273365b81093089bb4c9f407546371522c2feaeb446db/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string686 = /a8e669125c435f519ccde055c75dd9c44359ab15525846eeab7292262562b80c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string687 = /a99b152752f479050ee12bde36fe6c85d3b07b0ee2b6e974abf287bfa2727916/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string688 = /a9a8593db4e3f0d2b00c3683e029af751e6897bcb525fa0dc38777fe3bfb5c40/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string689 = /a9ada318adc60090587f06cac5d110f274f1fc75e7705c09fc27b8921aa32651/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string690 = /aab70f27573e8f6507ab19843595e8461d5f0e45500bddd6023e5266c123267b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string691 = /ab0198fa0310f86c57835809a96f157d2b4c3acccb3f039dba6cfb1af51f5665/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string692 = /ab0c5d37cd6817bde34337a51531c6db0dec64577b9c325e38627863c2d9bb97/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string693 = /ab495e19cd0752bcd83ae4f1ae0dff5ab09a756d63b22a64c718f87c04909142/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string694 = /ab606d61d0f3791fc8e0c64507a3210299d66e3bbefbe2101c4f7d8ca64aaf8f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string695 = /ac0b5929af1c06ef6d9655a5856c2ac6908c9f4979bd2a7c12f30562fd7f7520/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string696 = /ac32a19580d4f26d045e8555fb3b9f1415a45af8cbc3a67ea8d9c49dba11cdf1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string697 = /acc8e858d44f1310d7c9f6d2544f7a004165279132f6433271b59b73f540dbde/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string698 = /ace5f1151a4f4b7df43bfc7e45aa52d00aa4dc1642bbf1aa6f0872ffed1cd684/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string699 = /ad12dd2d23a3fdaa017293fe0acb1d6b60503d86c05b7b4e94e93df8beb1a347/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string700 = /ADCollector\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string701 = /ADCSPwn\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string702 = /adda6c0cbcc22357d88157922fafad38cc732fd71fa1389181dc1b31c7f6428e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string703 = /adeeb0a359ee487e9a32bed145a31b5f230153bce48040bc00b2478853e0377a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string704 = /ADFSDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string705 = /ADSearch\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string706 = /ae0dcb27348bfae6db1ef03803f267b4c9729d8ff8c9eff70fcff5a3d4b10384/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string707 = /ae2bed75480f578573b7cdb5e7c48cbbaf6012171eb4d9faf9d147aa8ea793e5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string708 = /ae382881d2f7597e84f993113650077b0bda039fbead9b2ef11eeca48ca33699/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string709 = /ae4109ba21693d9f9eb2623be9df5a5c68d3286dff7c8eb27d0e64889ce24c12/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string710 = /ae832b7ffb1e0d22120b433665d797d491e626506fe3b839afe3d5fec8fa6722/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string711 = /aee357b11515032187ff5c1d295b03b955a5198b1828cb7d3fa3f83687b41d64/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string712 = /af125299039eca4bdc0b43b65aec3fb54c62a48b6f8bcf1bb07a0a1e95241c23/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string713 = /afd2db12ce75a9ed350e7c04ab79ae018de33f9b994a7347e2a530755081d2cd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string714 = /b051d7e7069a4ec95d14811b1feb6813bb750fd281080ea0e6941ba1119180fb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string715 = /b0580360a94eff032f2113013124fb7209eb9bfef654841aeac2ebc09cec15c8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string716 = /b0a55532654bbfd0aafa59dfe26b576a095d9ac4a4af2f99bca442a1d87ce29b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string717 = /b0f47f0f3ef0ac238b9c52ca4bfee5f017f0531625f1ad8454bbb3c35e577453/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string718 = /b1c9f86c2715b984749012eb27fc0b1c9e9ae5b92a43991d4ee57bcf54d35daa/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string719 = /b1fd8a78d51a7dfbb73cf0f92912dc4363a2b5bd6746a792b63ac3ae1afb9ccd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string720 = /b25a37095a044369ef13a326fa144ddd84f08a980880dbb5c704b927a7343f4d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string721 = /b3b092ecd0cdb03ec5c038d281b5acc2dec8f01ea55b5742f81410f4f54ff9e2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string722 = /b4278888f8ba29f27b4a289ee4aa382bd7b3e0ea8ffd0c8fd4038ad963d21113/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string723 = /b44f8cfa584427bc18a8712218a1ce31b78b706cbfb02b0248b11f40b097ba9a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string724 = /b4bdf8ba2bfa4fdb140059b502dc0d7a84efe934cf1a251c23d89954aff38896/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string725 = /b61337b16cd16d660ebb308bf91466929d6d85710b595d733c8d11aa7840ec9e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string726 = /b626f6ca0ff3ed66408fdfe3e31466797b020447209cef538ccecd59b068a504/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string727 = /b62a1f3b8e0f601e835993277defc6df4912af3db9cbecd1e6dafa0f458926f4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string728 = /b68c9b6c076e1cdd44efd35fefe2f8da26aa4f271ecefce4e70af68acaf7541c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string729 = /b6c4a39612179674c521ae2c35e3de0b91504adf36928c69e024e0c42e61e74c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string730 = /b6d88a58d1da289997258be70427b46ab2c124179a09bab72d3cf25c44c7ad92/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string731 = /b6ffcd2adfacc8268724e5e8d97904743dcf15152eae87224134df705f916df3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string732 = /b74c431349454dc79731099eebfefca97b6b1d735e6c0269b5a4501e3fee6529/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string733 = /b74d7e3096956fd4bc7c929c2b482969f13a465058276ee97eb76c1d30529aa4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string734 = /b7c4eb1c120f959166ad5477119adb92db8081c61193847287a13fec1e780b24/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string735 = /b83de77d08d842c68a940103588639cef6ab9f9fa12241311d9aed3690502af3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string736 = /b8939f328f43eafc2faa8ba8532a756eb9db47e00e947ad8543484b4b0958bb8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string737 = /b9554f35c8c8dc4a5b428322fea2fa3a00cec87a17c5ed276a6dfe804f3828ed/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string738 = /ba0ec36076382b07332c8d5329ccec4c577ec5d6527c1a6dc56694744763024c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string739 = /baa3a3f7c6a17963ab80baff6de74aca91e4e75fa0a4f80bf18af9a5622edec3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string740 = /bad29346750d2b59ec0fa45fa4eae324aae520436adcc15fffa29edfacc9be60/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string741 = /bb62a3336da75791e241e3e757318dd0af03c1c678a249c3b67f16ef75ce648e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string742 = /bb695f5c847a67e8d0b6918a474b0f93090c8c5d64bf5b160b9f0c0fd4352bf5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string743 = /bb774a70665afeafeda776cc7b37f59f29fc3b16124e94020a91d4fdfa3f260b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string744 = /bd326bcb0c8473cbae427c5e7cdfdb9b9cdab27d0df73f67c704eeb962f8db96/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string745 = /bd43503a9105de8acb54f9dc566d68f3bb7d9b75fdb2ceb5fe939d52791bfdf5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string746 = /bd852d46ed2140ee627ff0798c12d589db9687c7de1b23160fe02a5570163d54/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string747 = /bd99cb3ea030932e00edee60aa4a03d9fdc70d031adaa389d8c6ab12982efcaa/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string748 = /bde38d20d4eb1a86cc38a81cc92861b3d366210af570ecb6fea93ac1060eaa7d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string749 = /be6d43b84e5b69c33f6e155d0e7be48bb3da4a322d19feac4073ef14b845f9fa/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string750 = /beb3dbf652aedb556fee96e7add11e5aa76be4028107fd1cf80066fe3479f43a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string751 = /bee12d2a87cfe2fccb8e9c81b1f3202c4101568d71b5434a04e59f6768730af2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string752 = /BetterSafetyKatz\./ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string753 = /bf46b919a1f3f45d5d31393ca62e1fd8269f49f6b9a6289258867908c5a80b03/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string754 = /bf514687e7c94c53072505b6e7e2e9ce0f318d95d5db4789694ca0851967c1f5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string755 = /bf99eb1afc5b916e63a5b1ff607a8d79012ada12a2bbbb3ca9be3921dc16cfaa/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string756 = /bfc69bfe997864b9ed4fda70da541e4fbed3c9e05206d924d3a511a217dec83f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string757 = /c0439525cf2087fbe8093cd85039fb5efe3557bc47a8a033a7b06657d4119333/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string758 = /c05b0803f8793c6bef98a74b8950be5be30dcb0584e634355896230fb8ee19e1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string759 = /c0800f3267b958f1f1e3796d2462897b698406ffe2c95c09b6249e84ac753bb0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string760 = /c113347933ec19ba179dace4e51ef27c76562a5f57e0321de391ae10c1874712/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string761 = /c1474dc5ff323f1351d89fcc7c922c0a612cf5dc1cd0b7dc719e0688d45aedcf/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string762 = /c1671ad8229c335d3b2edc0c2209db3d09104b85c050971fc8afc7b6f85ce0d0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string763 = /c1b584291f8b0c17013e438cfac02f28ea3088ae3884f3c0e27bf06f988339bf/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string764 = /c1c94cf03ed6fa3b74e3decbe2cedaec81d94a3046f001821111cb3f7687fdb1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string765 = /c2c9d4ca6ba2ca502be8d0a9670f7e8a5f7ab0bf315690b1c9df7b53ccf9c5cd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string766 = /c2fc425c6790459d69b7511d6b7626d4f140442c65a7751d69541ceab1bc47bd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string767 = /c35358989279835340cc632ab21e9e01c0d97415b4c6ac0e7f95fd2e916700c8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string768 = /c35aa7deb47b8e355ef827011cc745183d0099c36345e7f177d024618862873b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string769 = /c3f50756edbddbf72190cbdac5a0084b2c11e6aeab95b63d4da786547a693d73/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string770 = /c45986288840a01919c3b744499554d5a0608a2a109de0952b80303923cd3ce8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string771 = /c47d02f06bc853b2917607af695be6f81013ffa31f4ff13e6bbf8ff835ee40ec/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string772 = /c498592eebde7dec4227e1fe83002fca10beab096138e6d64278ef868a85900f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string773 = /c4c99f7ff1976731ad0a4c3514f291f925f030c3c80d70d93ca98e3bf69a853e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string774 = /c5deda524fb386a888b702d1eef8d55ad8b619affb88b2ed8bd913d24a3cde98/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string775 = /c631eda13fb95658b81e31a06554339857def299970639d8e3ee646df70d9454/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string776 = /c66a79726a52709cb4ceb004f0b2dda9d7159aa04678e002d9be27fb7d887a3c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string777 = /c6962ca89b28d1e9a7aa34b7de5c629e29a8eb732a0b8010406de83d0f2f8c2a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string778 = /c6ec76b8a6041bb25bd2699684ad58f63a6923aa1e4985438345fd99cdf11e20/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string779 = /c6faca2a240b79782651662d2de7511752a97dc187a93955bc83ef3e1b17326f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string780 = /c794d9b0bef6c7d8838f5130e2e0ae4c8bed3ec35cfb9bf502520dcfab38bde2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string781 = /c7bbfa266cc73f87a47186afadea101ceb03f759cf4b927a25dd1004d56ea07e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string782 = /c8273217f19cd8f6f693c350dea5bd6fff1ced10bf83174bbabab4656579c3cb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string783 = /c8458f30f7c976ba1be9cb1c1175b1f0d32aea6fdeb3f62ab911ea77713ede63/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string784 = /c8e190fea8360f02cf9cba596c62d17498e016ec1339b314131a1b828d21b090/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string785 = /c9cd5c71f55be91b6f64f93e17d7dd2a3fa9b66dda9b9c11bf4140c66f18ed39/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string786 = /c9da78ad6095451caaf4dc686005d5145494e9f7be36514423a111242ff523f2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string787 = /c9f355952a93723f4e6b471380f35a1315af1d2de40524ee0bdd252deded71d2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string788 = /ca16e87c3ffc6496a23618ff180b0a57ec07e290207d47e8dc7489a208bf4d85/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string789 = /cacaf377019b13a2e03c1751bf05b0d1513c160ee5325dd54fdf541885846e58/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string790 = /cad75780597ec7bda1505580fb4585123eb9685e0b759082d739c037c11e67be/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string791 = /caeaaee0273746fee0c2f2e790f3215075a28a8ec6ffc22d18f82e68aea555a2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string792 = /caf0940d2bfc54a2efd684ccf47ebddb79da9331584b4781924e260372cca582/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string793 = /cb12cf3f7f44250c5a2142d506921aa3c2ae8a1c6ef2f3781b3bf2ae7eb6cad4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string794 = /cbbb2f474f0ca015a37d57ec856950db3ce62942c8dd737003a9cc8f7cf63c07/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string795 = /cc5855ec2f5ac4e236e8e6cba698d4d307baa15a827c7719f4d6c8a58d28299b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string796 = /cded4541c570c91fd895adeca650b968f20fb68809e59f007a896730d097d8af/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string797 = /ce514ccbb11797a5e0457b8da2cf4914b753928dcc15d59d4db2d2b5ffcd061b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string798 = /ce9ae24722afd760de25a8961c4446b64235936b8ac8d1c2c25625d4feaee6e6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string799 = /cef1fb3c6273b3a908f79a5a5d74dbfe4ceabd2d9f850b2bd3e08e1908c440f1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string800 = /cefcadb734f22d7ddd0ce551628c246f4484400758ccb64afeb37bb93c78b5e0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string801 = /Certify\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string802 = /cf3753524bf8c852c2e81c008688ecfb91e75ba207ade5ef048c33bde631baef/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string803 = /cf9fb0b8e718dfebc8dfb4d5a9be9e57a00994fd060c250187ed92957b69fd15/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string804 = /cfed7067c52715989de828850551ceb0e92a5f1f5389a81a025424a88ab77e50/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string805 = /d029b40b87bd1462c77138f017ab6914a3753c4ec47bcbf192231a6b2585cf36/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string806 = /d0733560ad65a7123d380f6be4007ce0f0e56356f9dc1729e628342bb96892ab/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string807 = /d0844ed23aea55010cdfbca9d818cbf3baaa222ee8b30281b3534e60146583ff/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string808 = /d18b648dfee767e09a9c580a9bd0c60edc5f9aa4718e41c15434c47630023efb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string809 = /d1b7993dc84243e12f8b4650de9b71a85f5a3751c085d96f7211129c5e5f4eb0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string810 = /d1b8e13cf05c57e811ee4c90c985c018a7d1e937eca0f5860fecf36601032630/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string811 = /d1cd42f8663905f5e307c82b421093d7eb93b2d2a8d50f752ff0b8628b2bbc5a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string812 = /d29dcb85619d3c9f31070257e1abf0d1f2f2e23c7c3769a0c7aca9bdc16c2517/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string813 = /d323294bc92b8ab3dc05085a795881b3d75c5b1128911bf7478be1fe39d60482/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string814 = /d39a670a35257b1686b0f6d6b27fab1691839e925ba18c5c30c973ea70a31391/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string815 = /d423b1efdaf4f11171e6daf6e096e3651210cc454ccd6bb65ac07fd0aa0d7806/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string816 = /d43a9a1559ceb6fa1906b0142c375b8d2fa52e3725df36ec795cb0e734e110ce/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string817 = /d4915417cd9c0127ed93470e8d07076540b1c7ac08162831d74ce2114fd7f209/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string818 = /d4d156e6c11c5f257643a6cebfebcbc7c06b93bec236112ecd7df8e82f63846a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string819 = /d4e30598f12b58bb8f2df1b7899cfe35435e183517b941b721b1a70806808638/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string820 = /d4e30d80e0d2e1884270c75a2d13df486b54d0622925daaffa7ec78c942e3d45/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string821 = /d533a9a5a4b19deed391457a2194f896560cd4fc021341750071389b6042bc23/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string822 = /d54be2853d3b9d6245f57221d3abc3d49984322693b450f455570b0e6ae8524a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string823 = /d61c96edd06b7166d5c48c0941f1060c19a0342a6e9b8cb6844fe823fb5d1a58/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string824 = /d65739e2f3ff43ab1fae9e7c88909f9fe40bf275684fedb5d0539e4cdac79fc9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string825 = /d6fb61d7e2e1c8328be688eca56909cd1d4f33e595fd733663630cdd895c32c9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string826 = /d737dd339a9a013f78d089c01da72576a4d89cdb2f002ffdd666d04ae726b142/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string827 = /d75323d0a62e8baea946b82ced3bd78c4e07a6dfa20f07480b7c093c4b977fa4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string828 = /d8891b478ae421a3c0abc85bfa2b4bab4c4d35d46a26ba9f7fc1c6b3d0d30009/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string829 = /d88c69e0ca8a72f71d225ece1756c338ab37ec8af40bd0cdae4d9a73ad20457e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string830 = /d8edc288ad36a1dc853851dfe2255647e17020a528f64ca22b07258f3c918118/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string831 = /d9137008fdb0e917c996162abb1b6d457b20c987958d4a5e496edc9666fa8392/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string832 = /d919b4832a03cd1cc4c40803238e172dc2edd74317967546c4e485de14ddc5ba/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string833 = /d92b4a40c783bf64d9117a9daf35b4f75426f7f1743d9939d756b327f608eda7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string834 = /d941534ce99193cc7771684318af13748af81cf4a9a5b4fb02c791e066b563b2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string835 = /d95bb95780308e82ee8ab7e0a2bb1867a94ab91f96ce11413ba02a15a16750f9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string836 = /d9c8a6fa2ba159dea9e2bbeb86f0d329f996bbf51ff326d194968c2153aabea5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string837 = /d9d30d28c1f342516cf9be162135f570ad63e591ce2a1a6056c96e525b635fbb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string838 = /da6a12b87a18f943d1dd3f50a9f80313302efad3ce750c4073343d55f3b94b72/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string839 = /da9ed4d88d12f0938c05fad2fcfe69ba3fd90b0bda98844cc886e5103ac62c93/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string840 = /dac2f647397f3465db18352b2cc0286948f5d00e4467eac9176c0b4318aa8ff1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string841 = /db0e36392ef1430eae933b1fd0e94c0dd4f7d08ed93cfe369a7d73ed76082c93/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string842 = /db1f07bcc1caabad3c0a5bbeddf48f542193e0576e8c3ee42594c4a3e29d8895/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string843 = /db3bd2d5d62c49cf1b49ff0cd04a11da4e21006acb72bb193b776d1abaddb8a9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string844 = /db40433bbaa08ed43bfaf5d3535372a95c7c10a5803bd9e1ec95157bb65ce6bd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string845 = /db5b21d5a66fadcebe25ed1bcac0cd5590a3afdf1e9d247a3d169ffcd0a78e62/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string846 = /db85afa956f0a0b6ec30c13259782a0759a5adb2f5dc01969068bb4137364d15/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string847 = /db9e318fce9098eb3ae55a782aee7f29667772302296b4e4924e0edb88e69560/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string848 = /dc1bce76ba20f6d3a7020b35f18d47a74597018b0e58a9b1aff6d77be72f4a44/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string849 = /dc8ee760f0a1fb1a2f2a239cae71f44382a9be2b67736d590a471eae8c81d0af/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string850 = /dd14d6cd273d756c527fc0fa4b55e5bc33518d51d713325846458df7894b0d24/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string851 = /dd307d39038a79e45a140d13c406c084fceb840317a7c53a5d929012fa409cf3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string852 = /dd5cbddadb4446fe8e9558788ea449ac7f497973cf83ef9d8acc3803cfae956b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string853 = /dd6c8226641df9aa2a08e5e11949430e94773d763734ec3516a7976ad8d10f1a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string854 = /de81859bc3a1de8e35c2fa363f2405d7aff32f674cc3757caa1cc89235ec818e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string855 = /DeployPrinterNightmare\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string856 = /df4c83b6cc9b95717ed255abc28211a8f50db90f6b963c19c12e02bfce81c5ef/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string857 = /df73e65ae951cedb5ed162e7a32b7e361820b61c051bfe852017e5acc66e79f0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string858 = /dfb800d654e50937f2b2816724a0add4b35960bbc231f2a340a2fcebc53e9b46/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string859 = /e066fd26097862651947220c02240ca24faceb5f4ca0d1279881d97f7cff2c17/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string860 = /e0745223bdd96223cc512234545e517028d410e462bfa265f4c09b8e3740a44a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string861 = /e075c5a3c998e450c06b2e27ac2904ac2377b6d724577c5071437b68d6b3238b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string862 = /e0b25ed05fbe4558e26b270038d41c1de91ecde35d03520a2f20aaab7eee37e3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string863 = /e0bca03ae086a2ada8a29930036efe3ba12961a2ee71f2ec72cf9bd57096f604/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string864 = /e0c20aa0ef6e4fd5cd5cabde2f89d64d4fe1c73d13cc1ed58e401bf5e0667754/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string865 = /e114380d61281bb9bffe5246d366342cecc6dfa22814b308fa08b075e0b0f35f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string866 = /e1aa34410dd260529c0e32bb0fbc5263f3042bf47d01dc5ad424bb8cecc2b887/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string867 = /e1b23e90752a40a4a54afc406b874655f6d279a26e140402ad3f69509e9da496/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string868 = /e21abc2c59ac704df355a42b7275021e48670c876d019f05f56bf5a9c4cff78c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string869 = /e230c0ac37691456fdf0363b1f81215c15a7a235ddc96f072c74c5ac40866c9e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string870 = /e2c4f99f6a5d7bd663caba698a5867963fa2917201dcad6e94de8ff4a3f6a256/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string871 = /e370fb7d05e5b2ede88b633c05b9b21aa073678c392dda6407c112afe3430a61/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string872 = /e3731ce37c3e570254e35ac1201483592e708b43c898b3b21cca71a9f401d214/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string873 = /e376d23f48816e9d9a8d74cc9f8891b6fed2cff46d2b0efe989d8272b05931f2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string874 = /e4501ae5fc883efc3f0491b2d277e76fbb6d5b4d6618a2221d9fe08e8af41d00/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string875 = /e475c6f8ad8471fe068b1cbce42300ecffb7e6825ba88bf7dff8c2969562f595/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string876 = /e4ae0aec069aa237c5408c25c838464a65f7ca4e87453e6191f0629909fb2dfa/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string877 = /e56cc23ffa05a02bdb22fd0db6b82e1b91d64ce467bf9be73236edab7cf11af2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string878 = /e58bed7731a0a2a03e7c402d88a76a7d08c932494d6f5f78c0bc5f35b16ba9f6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string879 = /e62f551dcaca8e16effff14816c75f5838640a23112052b50d99999bb4db7f1d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string880 = /e634b7711fbe4e8f83481dbb2191faba51915d5533ec94db6fb2f1029161d0d8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string881 = /e6351ad6e15aa6faa8d9ff9b476e66c6b6970c2f7ad7a04b08e0c7ee1af043bd/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string882 = /e6428916f71a100481e78f6dac951b5c9e885b53dc8f1ab4e9e8a719528f70b8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string883 = /e6c2db94a0b0f667ef69e2e28e507a5e7fa629636b93506c119ccac224d74e62/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string884 = /e704bd6ebe126565b2334547aac8ef9bfcd9e3ec5ccf59b6e86d5b857610aa70/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string885 = /e75171190134063cc579d897bd1bd45370e3616b134398d239491c6382d3775f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string886 = /e754181c7e46930dab3fab1056569be0f6fa13cbdc77a87e91ee5c4bc83f658d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string887 = /e7a9855e85e1d0040e342e54182576f7f12e7f7fbe0debe50cc434f8215f0172/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string888 = /e7fe93ae48f18878e1476a2aaaf46af6da778d2f3a33dfe27c8d18cc890e1e7c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string889 = /e8336778c23574464fae2551b27074d52a949d7c97fe3fd0d8351f3f340e811b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string890 = /e848c25347ea3027e46eb9825cc47f3e8eaf44c5aead6691d6ea61c27cd4b136/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string891 = /e88262454c26daae342bea04507e03b8b49599d5fd2d5ec81027e685333a4104/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string892 = /e888bdb98dec5ad0f33feec1ce1563987ae364a7d27da8a1676d763d1d04fbef/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string893 = /e8c419d7176ad443676893924e1a1c0871bda59e512297b9b5846bebe9568b56/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string894 = /e8de489a84256609ac4e2b5236737d953af63fed9601d3f69253a5f199d901fc/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string895 = /e99a3bec641c578ceaa05b63b6544daf5b437361c1a5f8742808d8a09df5bca6/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string896 = /e9fff62c4585ae6de84da278a20e754ff3ff9ccdd0f11041a43eae84a54a622d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string897 = /ea707d12f05cf7fe93ca743158ae20c91ee663c50bd738b776d1183d1c8c7db2/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string898 = /eb6536b06148bb2c1a9c4103b98778d51f1204bd0aaf1b01dfb4a2c103ee000a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string899 = /ebf9bf76500715fe20c475140d200e76b51c400406683827eabb2ab70f9f986f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string900 = /ec3fea4e00eb0a4712a869b52eacce7efbcdcc9b958b8f46066e6f8969c4f79c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string901 = /ecf32e9cc006fb558375569ad4021fe588206e04722fe0474a34d05d9cc358f5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string902 = /ed0e2694b307d3510c102a4a5687523d0c72b8efba9dc256f493555639a3d470/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string903 = /ed0ee202bacea249b3d4563c0262501587434b25fc8b754c17829c8f4a64ad84/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string904 = /ed3e2cf7fe3797b0ec87b74568628f8a4d7ac1c4c5a29c6e169599ded4d1d947/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string905 = /ed565cd47f1e75dc1c53043d03631809f64c091293d10fb26f272ff74d419a6d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string906 = /ed72a475f9c8bb454e36a97155172424cd9892cbeba30bb6fc53cad973767fd1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string907 = /edcf68c388027b82dc8db46324c2cc67105a90f3689a200972331deb5dcdb887/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string908 = /eddd8cf62034d52903edacb5d07fc26220597cc98395d200fe859bd88936fc70/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string909 = /ee0ef3b713324cc7b0d6406c194c4e563fdcbcdea330300844e30603969cbde3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string910 = /ee9f3bc75013e6741dde950888676f9c20134ed7a7607bd069da81727be1fa01/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string911 = /eeb9847bbb8fdb98a1454e6dcde4e4e685bf549e0ab42fab823ed5abf83de427/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string912 = /ef5bf46dc35dcb1881a81107214ba85cafd4b3eb76e8a68b32005e9dd44d1371/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string913 = /ef9bce2a5c2f623419be05c9090187cba082a208f7685bd93c349fe71cbad896/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string914 = /effc137c4e7594fc3b3b5240c786ba3351e521bb7f9d14883dca6ff9db5f5f28/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string915 = /f140d5c67e7a151d9bba6d8c456dd44004f14056acd3257aa2203b30e959ef39/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string916 = /f187ab7396fc3a96e9549316af3e8eaf9ecdca41adec82d98ca52e67974811a8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string917 = /f2179c77b91b691efbf523410bdd70aa97c9a6866d5d13004a8ff559243f18e0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string918 = /f2754719c9b797be118057367989dc2da30a55d3f17260b55d252efdf7967579/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string919 = /f2e4dc0f2862a37449a85eaa39fe3a7840822e7ae24e8999fb6401b084c9505a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string920 = /f2ea2ded9b06880391d161ba3763f120209c6e2831e2c0092733df29e96a59a5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string921 = /f2f1df5e2cb5f824bea4b8e5b936187293b9717268aec16ab4eaa8c3f35e16cb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string922 = /f336ca7eed8b8f05f14090f23c4cc1a67f9b7e58b61586adf5c72542b05b94be/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string923 = /f3a97e2966c9b63bf0ce88346b568687f4253557841fd9c8acdee8ad25b27a97/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string924 = /f401f7bdae8094f273ab86529a90d93a192fed69897b908d1f5cc94f625b6b88/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string925 = /f44103b0e97b84c0381f234744a0a2aa2bf79cc884ee9526dbab8f9d674bc17b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string926 = /f4b50c86fa7368506ce70412d54b64ec45d4d93b6f0740b607c23a1a149eea46/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string927 = /f4fc8dabe2ba48d9d204dd0f74cae65a1eb27951664911aa116ab08446c1fb1d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string928 = /f504340404e40fea29f2beb71c114ce3d310ca80631aff7c0f0c19198da897d4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string929 = /f56888799e7efbcf2196e8f9dfa0d1adc97772ad6fee946cc59307d758a99e21/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string930 = /f579af445d7bae578d9848251bcfeb75f0947df511f68a595c902468fad39086/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string931 = /f5da690a8c9d7656d49401f2b54b3582197b81f6554eda0dc0bd511995db095c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string932 = /f5ef714731d36549ad900a94888613cdcfdddaa07dfb4a56990b2326bfc4cac7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string933 = /f5efe627e03bc8128bc4a3a600774648f2bd9384fb8f146262ae6727133e8414/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string934 = /f6955930082d6cb41401cd02d95e0f79bf44f92918adc18bdbd5aef7207625d1/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string935 = /f6f65c22bb7a4f263d745b83a959cc8b295eadbc9f458afb437b716ad3fac833/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string936 = /f6f865390750822cea504855053b4fe017001235f63f628f8433dab6f3b15582/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string937 = /f724f2ad9e30f001e16034efa68757a3baf31fe918a71722b529a53f71c3bac0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string938 = /f745fdbab44bfd54a5997a5d8746a602eb3af30c10d3fd264edbc705a8bb6e2a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string939 = /f7685768c93c8405a525090484261be417913ca2bcfdcce9596856dc3b5c64e0/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string940 = /f7851e5b0bca91e7ae15d879a7c5be4f63014c2c4b85bc756f6eddcf8c1eaa39/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string941 = /f80dcd0195952b3bed5899824560e51e26cde9ec9974acbf1751d3ba845e5232/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string942 = /f88a7b4bbe98f4e4d0f9e4c2f4de2a448f13ed7783772e6f5d6881c18b324bb4/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string943 = /f891fa68159f087901b55f0109bdf40a39e312fc31fb9caafca22726798e7aeb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string944 = /f9b96ad88884c71b8a0d911ebdcb01fe871d795354c4fbd66b705ee7120d83a3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string945 = /f9e0e800766e3a28d93ec6f55de8d2c64204d87162898d977eb3156c9cebb24b/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string946 = /f9ecfddee46fd760c809c843dc86c2bf7b9dfe1ac9ad932f782fb0ed6e34a23e/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string947 = /f9fdfa324c6c8d1e73da339f92f03a275e3f847082350a2881cca8c14e401d23/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string948 = /fa3ff4c4ead31c5754d9cd83bbee29512cfa4929722594998199e8fd51ae3bfb/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string949 = /fad52d687cfe0824b40ba5fd96a6a3034537fc33c59d628049de8b93c4364ce9/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string950 = /fb6a2914759e6644c5067b1b7308bc295d4b6b357b1ad9f904b430ba588654f8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string951 = /fb8c1454ea22ccc9d97cbd90692d38c3c63d551680f6632fe658598a9bb23c03/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string952 = /fbcbcfae5662f9f0dfbf7f5cb31c052399382232a51554197f4554d1bb06332f/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string953 = /fbd415807cca02732e2b7b7ad2d8fd09db1ab75953fe24fe7b6238f691c6e5a8/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string954 = /fc04cd7b616aa8a43a35a5318a9454f4228c74b056bfa07ec14105d249593e35/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string955 = /fc52dac4f484c090d99d8b142ed41ed3368938955dfc25d76cd4f290bb6c59d5/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string956 = /fc8516a68f470a92e9e4dd80b5928ddd732d2de4b43b483d23d068bb92509f0c/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string957 = /fc959cac98096ae179061a564cdce68687a17768f90ec9af568a5b58c0adfb5a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string958 = /fc9b91ba161b6dcf81cee6713bbf224e82c49e3166178c0d9ceb54f963250ce7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string959 = /fe22bb52058886459e0ff6f9c1c70b4604b15c30b5f1e3ebfc58305d4e94a7e3/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string960 = /fe2cc64a77ca3a7620a9ddec10f9f6e80769132f5587cece5dd03d419782481d/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string961 = /fed573df80a1aeb08f129824ce29906dd614fea7b3af704fa0e9324c26e5084a/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string962 = /fee8aa6d643d13d224330adb9389f37ec58c487cf91769158f5a650fa5522bde/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string963 = /ffb3ecd39698fe5e2fc33483b159f10d1ba16801682aab754f61ccb814eff5d7/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string964 = /ffebf73d11403dc0bb57ab23a775a568ff5c67c1bb5f8fac7a1f2fbd3960b619/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string965 = /fff54c4b8a879869c50760512e87a39578fea5e07ecead1086af4b50561b5453/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string966 = /Flangvik\/SharpCollection/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string967 = /ForgeCert\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string968 = /Inveigh\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string969 = /KrbRelay\.Clients\.Attacks/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string970 = /KrbRelay\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string971 = /KrbRelayUp\.DSInternals\.Common\.Properties/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string972 = /KrbRelayUp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string973 = /KrbRelayUp\.lib/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string974 = /LockLess\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string975 = /PassTheCert\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string976 = /PurpleSharp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string977 = /Rubeus\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string978 = /SafetyKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string979 = /SauronEye\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string980 = /SearchOutlook\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string981 = /Seatbelt\.Commands\.Windows/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string982 = /Seatbelt\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string983 = /ShadowSpray\.DSInternals/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string984 = /ShadowSpray\.Kerb\.lib/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string985 = /SharpAllowedToAct\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string986 = /SharpAppLocker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string987 = /SharpBypassUAC\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string988 = /SharpChisel\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string989 = /SharpChrome\sbackupkey/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string990 = /SharpChrome\.cs/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string991 = /SharpChrome\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string992 = /SharpChromium\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string993 = /SharpCloud\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string994 = /SharpCOM\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string995 = /SharpCookieMonster\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string996 = /SharpCrashEventLog\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string997 = /SharpDir\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string998 = /SharpDPAPI\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string999 = /SharpDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1000 = /SharpEDRChecker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1001 = /SharPersist\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1002 = /SharpExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1003 = /SharpGPOAbuse\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1004 = /SharpHandler\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1005 = /SharpHose\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1006 = /SharpHound\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1007 = /SharpKatz\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1008 = /SharpLAPS\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1009 = /SharpMapExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1010 = /SharpMiniDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1011 = /SharpMove\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1012 = /SharpNamedPipePTH\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1013 = /SharpNoPSExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1014 = /SharpPrinter\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1015 = /SharpRDP\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1016 = /SharpReg\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1017 = /SharpSCCM\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1018 = /SharpSearch\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1019 = /SharpSecDump\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1020 = /SharpShares\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1021 = /Sharp\-SMBExec\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1022 = /SharpSniper\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1023 = /SharpSphere\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1024 = /SharpSpray\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1025 = /SharpSQLPwn\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1026 = /SharpStay\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1027 = /SharpSvc\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1028 = /SharpTask\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1029 = /SharpUp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1030 = /SharpView\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1031 = /SharpWebServer\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1032 = /SharpWifiGrabber\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1033 = /SharpWMI\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1034 = /SharpZeroLogon\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1035 = /Shhmon\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1036 = /Snaffler\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1037 = /Snaffler\.Properties/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1038 = /Snaffler\.SnaffRules/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1039 = /StickyNotesExtract\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1040 = /SweetPotato\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1041 = /ThunderFox\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1042 = /TokenStomp\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1043 = /TruffleSnout\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1044 = /Whisker\.DSInternals/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1045 = /Whisker\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1046 = /winPEAS\.exe/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1047 = /winPEAS\.Info\.FilesInfo\.Office\.Office/ nocase ascii wide
        // Description: Nightly builds of common C# offensive tools. fresh from their respective master branches built and released in a CDI fashion using Azure DevOps release pipelines.
        // Reference: https://github.com/Flangvik/SharpCollection
        $string1048 = /WMIReg\.exe/ nocase ascii wide

    condition:
        any of them
}
