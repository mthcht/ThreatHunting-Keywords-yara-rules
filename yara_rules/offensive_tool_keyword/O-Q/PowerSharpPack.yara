rule PowerSharpPack
{
    meta:
        description = "Detection patterns for the tool 'PowerSharpPack' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "PowerSharpPack"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string1 = /\s\-grouper2\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string2 = /\s\-Internalmonologue\s\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string3 = /\s\-lockless\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string4 = /\s\-Rubeus\s\-Command\s.{0,1000}kerberoast/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string5 = /\s\-SauronEye\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string6 = /\s\-seatbelt\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string7 = /\s\-SharpChromium\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string8 = /\s\-SharpDPAPI\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string9 = /\s\-SharPersist\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string10 = /\s\-SharpShares\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string11 = /\s\-SharpSniper\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string12 = /\s\-SharpSpray\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string13 = /\s\-SharpUp\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string14 = /\s\-Sharpview\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string15 = /\s\-sharpweb\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string16 = /\s\-Tokenvator\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string17 = /\s\-UrbanBishop\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string18 = /\s\-watson\s\-Command\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string19 = /\s\-winPEAS\s/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string20 = /\/GzipB64\.exe/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string21 = /\/PowerSharpPack\.git/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string22 = /\\GzipB64\.exe/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string23 = /\\windows\\temp\\pwned\.trx/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string24 = /\-Command\s\"\-\-signature\s\-\-driver\"/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string25 = /Invoke\-BadPotato/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string26 = /Invoke\-BetterSafetyKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string27 = /Invoke\-BlockETW/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string28 = /Invoke\-Carbuncle/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string29 = /Invoke\-Certify/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string30 = /Invoke\-DAFT\./ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string31 = /Invoke\-DinvokeKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string32 = /Invoke\-Eyewitness/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string33 = /Invoke\-FakeLogonScreen/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string34 = /Invoke\-Farmer/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string35 = /Invoke\-Get\-RBCD\-Threaded/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string36 = /Invoke\-Gopher/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string37 = /Invoke\-Grouper2/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string38 = /Invoke\-Grouper3/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string39 = /Invoke\-HandleKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string40 = /Invoke\-Internalmonologue/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string41 = /Invoke\-KrbRelay/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string42 = /Invoke\-LdapSignCheck/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string43 = /Invoke\-Lockless/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string44 = /Invoke\-MalSCCM/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string45 = /Invoke\-MITM6/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string46 = /Invoke\-NanoDump/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string47 = /Invoke\-OxidResolver/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string48 = /Invoke\-P0wnedshell/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string49 = /Invoke\-P0wnedshellx86/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string50 = /Invoke\-PPLDump/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string51 = /Invoke\-Rubeus/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string52 = /Invoke\-SafetyKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string53 = /Invoke\-SauronEye/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string54 = /Invoke\-SCShell/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string55 = /Invoke\-Seatbelt/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string56 = /Invoke\-ShadowSpray/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string57 = /Invoke\-SharpAllowedToAct/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string58 = /Invoke\-SharpBlock/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string59 = /Invoke\-SharpBypassUAC/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string60 = /Invoke\-SharpChromium/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string61 = /Invoke\-SharpClipboard/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string62 = /Invoke\-SharpCloud/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string63 = /Invoke\-SharpDPAPI/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string64 = /Invoke\-SharpDump/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string65 = /Invoke\-SharPersist/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string66 = /Invoke\-SharpGPOAbuse/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string67 = /Invoke\-SharpGPO\-RemoteAccessPolicies/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string68 = /Invoke\-SharpHandler/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string69 = /Invoke\-SharpHide/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string70 = /Invoke\-Sharphound2/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string71 = /Invoke\-Sharphound3/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string72 = /Invoke\-SharpHound4/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string73 = /Invoke\-SharpImpersonation/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string74 = /Invoke\-SharpImpersonationNoSpace/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string75 = /Invoke\-SharpKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string76 = /Invoke\-SharpLdapRelayScan/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string77 = /Invoke\-Sharplocker/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string78 = /Invoke\-SharpLoginPrompt/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string79 = /Invoke\-SharpMove/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string80 = /Invoke\-SharpPrinter/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string81 = /Invoke\-SharpPrintNightmare/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string82 = /Invoke\-SharpRDP/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string83 = /Invoke\-SharpSCCM/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string84 = /Invoke\-SharpSecDump/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string85 = /Invoke\-Sharpshares/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string86 = /Invoke\-SharpSniper/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string87 = /Invoke\-SharpSploit/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string88 = /Invoke\-Sharpsploit_nomimi/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string89 = /Invoke\-SharpSSDP/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string90 = /Invoke\-SharpStay/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string91 = /Invoke\-SharpUp/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string92 = /Invoke\-Sharpview/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string93 = /Invoke\-SharpWatson/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string94 = /Invoke\-Sharpweb/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string95 = /Invoke\-SharpWSUS/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string96 = /Invoke\-Snaffler/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string97 = /Invoke\-Spoolsample/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string98 = /Invoke\-StandIn\./ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string99 = /Invoke\-StickyNotesExtract/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string100 = /Invoke\-Thunderfox/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string101 = /Invoke\-Tokenvator/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string102 = /Invoke\-UrbanBishop/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string103 = /Invoke\-Whisker/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string104 = /Invoke\-winPEAS/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string105 = /Invoke\-WireTap/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string106 = /no\sMimik\@tz\s\-\sloaded\ssuccessfully/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string107 = /PowerSharpBinaries/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string108 = /PowerSharpPack\.ps1/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string109 = /PowerSharpPack\-master/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string110 = /S3cur3Th1sSh1t\/PowerSharpPack/ nocase ascii wide

    condition:
        any of them
}
