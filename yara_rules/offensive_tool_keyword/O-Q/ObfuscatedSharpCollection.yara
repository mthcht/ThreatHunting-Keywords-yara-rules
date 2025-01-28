rule ObfuscatedSharpCollection
{
    meta:
        description = "Detection patterns for the tool 'ObfuscatedSharpCollection' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ObfuscatedSharpCollection"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string1 = /\.exe\._obf\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string2 = /\/ADCollector\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string3 = /\/ADCSPwn\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string4 = /\/ADFSDump\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string5 = /\/ADSearch\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string6 = /\/BetterSafetyKatz\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string7 = /\/DeployPrinterNightmare\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string8 = /\/ForgeCert\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string9 = /\/Group3r\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string10 = /\/KrbRelay\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string11 = /\/KrbRelayUp\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string12 = /\/LockLess\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string13 = /\/ObfuscatedSharpCollection\.git/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string14 = /\/PassTheCert\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string15 = /\/PurpleSharp\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string16 = /\/Rubeus\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string17 = /\/SafetyKatz\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string18 = /\/SauronEye\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string19 = /\/Seatbelt\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string20 = /\/SharpAllowedToAct\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string21 = /\/SharpApplocker\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string22 = /\/SharpBypassUAC\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string23 = /\/SharpChisel\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string24 = /\/SharpChrome\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string25 = /\/SharpChromium\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string26 = /\/SharpCloud\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string27 = /\/SharpCOM\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string28 = /\/SharpCookieMonster\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string29 = /\/SharpCrashEventLog\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string30 = /\/SharpDir\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string31 = /\/SharpDPAPI\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string32 = /\/SharpDump\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string33 = /\/SharpEDRChecker\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string34 = /\/SharPersist\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string35 = /\/SharpExec\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string36 = /\/SharpGPOAbuse\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string37 = /\/SharpHandler\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string38 = /\/SharpHose\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string39 = /\/SharpHound\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string40 = /\/SharpKatz\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string41 = /\/SharpLAPS\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string42 = /\/SharpMapExec\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string43 = /\/SharpMove\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string44 = /\/SharpNamedPipePTH\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string45 = /\/SharpNoPSExec\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string46 = /\/SharpPrinter\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string47 = /\/SharpRDP\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string48 = /\/SharpReg\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string49 = /\/SharpSCCM\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string50 = /\/SharpSearch\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string51 = /\/SharpSecDump\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string52 = /\/SharpShares\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string53 = /\/Sharp\-SMBExec\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string54 = /\/SharpSniper\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string55 = /\/SharpSphere\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string56 = /\/SharpSpray\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string57 = /\/SharpSQLPwn\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string58 = /\/SharpStay\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string59 = /\/SharpSvc\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string60 = /\/SharpTask\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string61 = /\/SharpUp\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string62 = /\/SharpView\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string63 = /\/SharpWebServer\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string64 = /\/SharpWifiGrabber\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string65 = /\/SharpWMI\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string66 = /\/SharpZeroLogon\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string67 = /\/Shhmon\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string68 = /\/Snaffler\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string69 = /\/StickyNotesExtract\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string70 = /\/ThunderFox\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string71 = /\/TokenStomp\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string72 = /\/TruffleSnout\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string73 = /\/Watson\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string74 = /\/Whisker\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string75 = /\/winPEAS\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string76 = /\/WMIReg\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string77 = /\\ADCollector\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string78 = /\\ADCSPwn\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string79 = /\\ADFSDump\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string80 = /\\ADSearch\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string81 = /\\BetterSafetyKatz\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string82 = /\\Certify\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string83 = /\\DeployPrinterNightmare\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string84 = /\\ForgeCert\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string85 = /\\Group3r\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string86 = /\\KrbRelay\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string87 = /\\KrbRelayUp\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string88 = /\\LockLess\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string89 = /\\ObfuscatedSharpCollection/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string90 = /\\PassTheCert\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string91 = /\\PurpleSharp\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string92 = /\\Rubeus\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string93 = /\\SafetyKatz\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string94 = /\\SauronEye\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string95 = /\\Seatbelt\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string96 = /\\SharpAllowedToAct\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string97 = /\\SharpApplocker\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string98 = /\\SharpBypassUAC\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string99 = /\\SharpChisel\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string100 = /\\SharpChrome\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string101 = /\\SharpChromium\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string102 = /\\SharpCloud\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string103 = /\\SharpCOM\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string104 = /\\SharpCookieMonster\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string105 = /\\SharpCrashEventLog\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string106 = /\\SharpDir\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string107 = /\\SharpDPAPI\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string108 = /\\SharpDump\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string109 = /\\SharpEDRChecker\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string110 = /\\SharPersist\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string111 = /\\SharpExec\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string112 = /\\SharpGPOAbuse\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string113 = /\\SharpHandler\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string114 = /\\SharpHose\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string115 = /\\SharpHound\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string116 = /\\SharpKatz\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string117 = /\\SharpLAPS\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string118 = /\\SharpMapExec\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string119 = /\\SharpMove\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string120 = /\\SharpNamedPipePTH\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string121 = /\\SharpNoPSExec\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string122 = /\\SharpPrinter\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string123 = /\\SharpRDP\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string124 = /\\SharpReg\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string125 = /\\SharpSCCM\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string126 = /\\SharpSearch\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string127 = /\\SharpSecDump\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string128 = /\\SharpShares\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string129 = /\\Sharp\-SMBExec\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string130 = /\\SharpSniper\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string131 = /\\SharpSphere\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string132 = /\\SharpSpray\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string133 = /\\SharpSQLPwn\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string134 = /\\SharpStay\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string135 = /\\SharpSvc\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string136 = /\\SharpTask\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string137 = /\\SharpUp\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string138 = /\\SharpView\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string139 = /\\SharpWebServer\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string140 = /\\SharpWifiGrabber\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string141 = /\\SharpWMI\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string142 = /\\SharpZeroLogon\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string143 = /\\Shhmon\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string144 = /\\Snaffler\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string145 = /\\StickyNotesExtract\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string146 = /\\ThunderFox\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string147 = /\\TokenStomp\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string148 = /\\TruffleSnout\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string149 = /\\Watson\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string150 = /\\Whisker\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string151 = /\\winPEAS\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string152 = /\\WMIReg\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string153 = ">ADCSPwn<" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string154 = ">ADFSDump<" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string155 = ">BetterSafetyKatz<" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string156 = "010eb2bab7b24ddaec85ddd15383b64286cf8791ba4556c465e806d7235eab1c" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string157 = "01ba4719c80b6fe911b091a7c05124b64eeece964e09c058ef8f9805daca546b" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string158 = "01e17d1133dbcf9e6acd463f20f6a5b8a499f5ec8d728cdfea8c58df1085d1cc" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string159 = "0bcc96d2405f07c6ad41b4904c79008707584c523b20df5e2689d8fc25412029" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string160 = "0d45502cdd00e1f2a8864ef450dc532497f817f7596c105933e1eb9054186bf3" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string161 = "11c1761a8b341699d52bc16698a43ea3193518818323307d82c41763893fbdd2" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string162 = "12de29e0372dc7deeb72828e2d98d1f918a9b1093ca55a579cbec210a31fb325" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string163 = "137b032bd7485d528ecbd52168dcbab45d13c3902fda391c46a0665d72938dbb" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string164 = "13ce1d09e6b47a8c35d56416c864710146fccb4a93d6ef11aa4e550bdb1aef31" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string165 = "1676f2761aadc0b59145f87fce45d8f27339d8978d015245cbc1c5cfa8c38eda" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string166 = "16c7ff461f2dbc21d705c9a458901ad48a5c830eb7e4e472b0df65634f850434" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string167 = "17808f0e8af07a26a574ab7e9e91ceac220d82f44dbc6c06e20a2afefccec418" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string168 = "1a500fbb73dca02d86318499781d5932bf8e66471e98a9d543904e661fa87c19" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string169 = "1b91671f55675c1262fa008c5a6f24f7842cb7f14bcf30aed99444d8ea5fed5f" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string170 = "1bf703bef8ee1927c28ba6691843bf7576dc9f7e3af6c2efdb653695e7163daf" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string171 = "22986734a47c09453ffda17227be0a2bc1ab4875aca8ad84444a603577afb646" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string172 = "29130af313a863e17612085d8ffefd98e2002d989757283656d870202cd18847" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string173 = "2cea373bf30e78ea980ffcece278ef5a41df27484103e6e57cb0084e34a65a5f" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string174 = "35849ba82ab0c1fb2c295f53326954434d2612aa31dab3c1ea7703690477ab0d" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string175 = "370058f9f12c7cc257de6508328287c7f6aa566003cecdaf843bdbbc4c0d177d" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string176 = "38a0bf28c523180015d3c969129a72e94bbbcdb4dc30f9a630b32f6c97c41e0d" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string177 = "3d072fb48ae49e6cf6e94af84c2e6ba2c278a1189ac12b0e51b232462f3865d1" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string178 = "443b045acebb863062cf5b292afd9d831700510daec69f1961aa7236d1d595aa" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string179 = "4465f8d00184474f6f609f3e2f9ad68b70bfcddbc2e8f370f8d4fa6e47a9e0ee" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string180 = "44f6d55e84972a295d82d3e670bd8356fe8fee457e19e9115f26005ffb24f68d" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string181 = "45a8664a10f0b5f30e458aed00e46378dae5e8b3e6e208394a83e1d080b8a978" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string182 = "494dd15c32c3fe9a43edefb8ae35752f2e596d609a358e4ea1e7b9b4eba8e542" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string183 = "4ae656fa671d794cdf9780b1dbf9c2a097f81f7c349f2e18fbb2535d495feefd" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string184 = "4b56fdc12b0f2b0c1e1b5f2e4e5fceb6794d4446587fbee895847d2eae8de930" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string185 = "4dd26db699ec39da43ed638597d277ccfe5e27d15dedfb037476d0f4a5b8cb87" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string186 = "51ef910e61dfc492f4e1e1ad115b1c600175cffa379ae8a7035e6ba016ec7af5" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string187 = "5b989ce585f0c93fd67cc305fcf195755c498f19f5437151b9ce371460f6ab56" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string188 = "623eff8ac5efc0fd81c37ff8262eba95b7ea2bb941366b7edde5dcf5524292fd" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string189 = "6e97ff7ed0f51797300080bd5b39662c9b78693b54f7b3bb3da80b3be20cf076" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string190 = "6ef83e490ccff661262cb10a37850b957ceb1da55a680321e1d354bf7a036c10" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string191 = "7067f8017505177909b1e7100dfe85349cef8c01858be393fa2c5cc8c718c0af" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string192 = "7bcabfc6777e1141b116e4595e113148fca5c89fb5f8eb8c4fec519f91e483b8" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string193 = "82cff3a5c17a0c205a4b60bbcaa8f10494ba5bd0d38445e1227d65f944acd922" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string194 = "84d3264c0daaaed493505f366bac7e8504137bdfa73dc0618588081d544997bb" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string195 = "8769a14055d8c1d1f2dce1642ba7fdf3f8d4c24cafee7348857403905c50f4d6" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string196 = "8c6fb15cbc44a898922c14019dd37452cabbebaffd16823646aff4d886d5a75e" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string197 = "8c763214b528d61ef64a39db9b01deb16f2a550e3f2e8fbc530fb982860f682f" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string198 = "8d944f890478ade2c832a84892373f85b54a3903bce4d0fc34f07a396736b4a5" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string199 = "98063f3e117a093aee435c3b1130f770b9a98022165356ff1679a6f33a61e1e5" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string200 = "9a13e576203799161d672251815bf9f34a428af3a58787c01eb73c99c1436eac" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string201 = "9b58d53cfea14b281ec196a1989aedb62550857ad91273708da6cce760f51306" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string202 = "a3758ea5e899a151d3f5055938dcd9db6aa28c163c2022975f85db8700d48d60" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string203 = "a53818852885cf956baa7b75e10a818ecef060c2c3ab1026d6f0cbbf2f47810e" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string204 = "a60723c287985d0ff660c28a9558dc511a5be3cd2171778e2068f2950934e0c6" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string205 = "a65acb163d08410f58a84447f9a615c45219343e637a1853dc29a2e79ff2f112" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string206 = "a771136ec4681f7b160ec60642134a43b79c4da8e04e787371978b1bcb3e02cb" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string207 = "a79765b3ea99f275733ff0d9860658a403469ff3e7cb25e52a58f9d2c79e89f4" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string208 = "a7c1eba0aa510794924988b65a5965df2452a5960721bcdaf464d07bd693cbfb" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string209 = "a7f243d5fa0843494e5d83810d2a4be9469fe02b2d8ced52e61a9355d9e6d697" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string210 = /ADCollector\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string211 = /ADCSPwn\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string212 = /ADFSDump\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string213 = "b0e1039ae0d67bf914c268cfb9ca01b11aaa76a7af1560cf16ca5b52ecff0f96" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string214 = "b220de41dd61f8477fff83c8930a8a1759c3c1cb3da593698136b79f37ba01b9" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string215 = "b297813bf0834ce143142bd53ca142e54844abd57c60ee01279a2171f32fdb77" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string216 = "bcb2e399281a97256985eae807d94d8656c0b76ab2aed4ca200e57acb3b07eea" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string217 = /BetterSafetyKatz\.exe/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string218 = "c4baa8972cd078acdbbddc5db31b73bdabb84b88cf06e133e7cb34fbc316761e" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string219 = "c50948b611e3e9902eab10fff0c03918d3420fb4126a9ca8a8882f03613775e5" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string220 = "c562f6223396e63dae95ab394c4b7a4ff3836d246a97266d5bb601f47bfdd2a1" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string221 = "c787d2dcdb5ea2184d90206ffd7da618a71d51383888b3d8564a9c71e7f100c4" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string222 = "c9436dd6ae789bd83bada6aa823ea7f3d1a36455e818d78f64ab296222dd3362" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string223 = "cca940a0ba81f0ab849d294e3399485f6bf82961997b66c2e093062e72a4d31e" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string224 = "d1efc8919bbb55ea144e8b91203a43cec5ceda5ae68f1077836e1da06340f557" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string225 = "d31689572f9c5c80ca601075267a0db0e32b89665f039e721b27f6b9536c3be2" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string226 = "d81858b01de71a850d5c4f69578441c6d91f06dbd96b96c3d78cb6539681816b" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string227 = "d99a506000fb5bb53cc19e3b33f742db07b36b8e6f71375584faf9308474a9e4" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string228 = "dabaad1501e39a462ca3ec0e31f7dd0e70e335db0274b8fd03a03a2419037129" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string229 = "dcbb2973c0775f8c81ec4f4d421de38d62196d169cfcad09ecd41c1ffb74bada" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string230 = "DeployPrinterNightmare" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string231 = "df13fa4302b5994f61271abcf3bfbb9c7c4cf881dbc6631735916fe3ca891043" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string232 = "e084636dbb198247674ec5cf50646a01ff95b16ed6cf81c5a841062d14657a7e" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string233 = "e22a97f69dbd69e72d2bd9b542a44c33a2139963ca121976085de6bc23858ce9" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string234 = "e8d08184a9c9b9f5b4263107fa19cfad2735f161dd2b16670ee8f68943fda2cf" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string235 = "e9986bdf879ff9f5e6dfd0fc90531bdc88e854e81a4354b7bf3cc0fd2aedae65" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string236 = "ea1e3b04e30cb4192671bf6a15f42bbb9aab140b59ab0d4097bb36459def54eb" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string237 = "ed2e54a7a57637f150701a4764bbece4af4bcbc563b9a0e61c017146b3bed284" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string238 = "f333b88f6b0f3260dd3f291b932816e055ee81fc1c94d1e5712f0848523dd706" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string239 = "f43d2a38f8e8ec7033006cc51efd0e596801579838059178042db1bcb295d131" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string240 = "f45e8e11a4c9817e0742a79e7753377b944ef887824f94dab1cc2fa7e4771795" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string241 = "fcd4c0133b296c3590588114f203cd6506d60462590d115f942a3e123f472808" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string242 = "fec9a5ebd0b87374a1f94cf6760a4d1e83ce4333b68c224bc8fb6a464df67850" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string243 = "Flangvik/ObfuscatedSharpCollection" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string244 = /Group3r\.View\.NiceGpoPrinter/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string245 = /LibSnaffle\.Logging/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string246 = /PurpleSharp\.Lib\.IPAddressRange/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string247 = /Rubeus\.Ndr\.RPC_/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string248 = /Seatbelt\.Commands\.Windows\./ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string249 = "SharpBypassUAC" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string250 = "SharpChisel" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string251 = "SharpCookieMonster" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string252 = "SharpCrashEventLog" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string253 = /SharpDPAPI\.Commands\./ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string254 = /Sharphound\.Runtime/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string255 = "SharpInvoke-SMBExec" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string256 = "SharpNamedPipePTH" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string257 = "SharpNoPSExec" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string258 = /SharpSCCM\.Program/ nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string259 = "SharpSQLPwn" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string260 = "SharpWifiGrabber" nocase ascii wide
        // Description: obfuscated Sharp Offensive tools
        // Reference: https://github.com/Flangvik/ObfuscatedSharpCollection
        $string261 = /SharpWMI\.Program/ nocase ascii wide

    condition:
        any of them
}
