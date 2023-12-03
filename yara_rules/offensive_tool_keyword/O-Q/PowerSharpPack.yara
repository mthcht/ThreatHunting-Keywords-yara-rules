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
        $string1 = /.{0,1000}\s\-grouper2\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string2 = /.{0,1000}\s\-Internalmonologue\s\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string3 = /.{0,1000}\s\-lockless\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string4 = /.{0,1000}\s\-Rubeus\s\-Command\s.{0,1000}kerberoast.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string5 = /.{0,1000}\s\-SauronEye\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string6 = /.{0,1000}\s\-seatbelt\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string7 = /.{0,1000}\s\-SharpChromium\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string8 = /.{0,1000}\s\-SharpDPAPI\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string9 = /.{0,1000}\s\-SharPersist\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string10 = /.{0,1000}\s\-SharpShares\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string11 = /.{0,1000}\s\-SharpSniper\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string12 = /.{0,1000}\s\-SharpSpray\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string13 = /.{0,1000}\s\-SharpUp\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string14 = /.{0,1000}\s\-Sharpview\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string15 = /.{0,1000}\s\-sharpweb\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string16 = /.{0,1000}\s\-Tokenvator\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string17 = /.{0,1000}\s\-UrbanBishop\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string18 = /.{0,1000}\s\-watson\s\-Command\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string19 = /.{0,1000}\s\-winPEAS\s.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string20 = /.{0,1000}\/GzipB64\.exe.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string21 = /.{0,1000}\/PowerSharpPack\.git.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string22 = /.{0,1000}\\GzipB64\.exe.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string23 = /.{0,1000}\\windows\\temp\\pwned\.trx.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string24 = /.{0,1000}Invoke\-BadPotato.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string25 = /.{0,1000}Invoke\-BetterSafetyKatz.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string26 = /.{0,1000}Invoke\-BlockETW.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string27 = /.{0,1000}Invoke\-Carbuncle.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string28 = /.{0,1000}Invoke\-Certify.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string29 = /.{0,1000}Invoke\-DAFT\..{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string30 = /.{0,1000}Invoke\-DinvokeKatz.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string31 = /.{0,1000}Invoke\-Eyewitness.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string32 = /.{0,1000}Invoke\-FakeLogonScreen.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string33 = /.{0,1000}Invoke\-Farmer.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string34 = /.{0,1000}Invoke\-Get\-RBCD\-Threaded.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string35 = /.{0,1000}Invoke\-Gopher.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string36 = /.{0,1000}Invoke\-Grouper2.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string37 = /.{0,1000}Invoke\-Grouper3.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string38 = /.{0,1000}Invoke\-HandleKatz.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string39 = /.{0,1000}Invoke\-Internalmonologue.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string40 = /.{0,1000}Invoke\-KrbRelay.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string41 = /.{0,1000}Invoke\-LdapSignCheck.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string42 = /.{0,1000}Invoke\-Lockless.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string43 = /.{0,1000}Invoke\-MalSCCM.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string44 = /.{0,1000}Invoke\-MITM6.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string45 = /.{0,1000}Invoke\-NanoDump.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string46 = /.{0,1000}Invoke\-OxidResolver.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string47 = /.{0,1000}Invoke\-P0wnedshell.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string48 = /.{0,1000}Invoke\-P0wnedshellx86.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string49 = /.{0,1000}Invoke\-PPLDump.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string50 = /.{0,1000}Invoke\-Rubeus.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string51 = /.{0,1000}Invoke\-SafetyKatz.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string52 = /.{0,1000}Invoke\-SauronEye.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string53 = /.{0,1000}Invoke\-SCShell.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string54 = /.{0,1000}Invoke\-Seatbelt.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string55 = /.{0,1000}Invoke\-ShadowSpray.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string56 = /.{0,1000}Invoke\-SharpAllowedToAct.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string57 = /.{0,1000}Invoke\-SharpBlock.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string58 = /.{0,1000}Invoke\-SharpBypassUAC.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string59 = /.{0,1000}Invoke\-SharpChromium.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string60 = /.{0,1000}Invoke\-SharpClipboard.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string61 = /.{0,1000}Invoke\-SharpCloud.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string62 = /.{0,1000}Invoke\-SharpDPAPI.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string63 = /.{0,1000}Invoke\-SharpDump.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string64 = /.{0,1000}Invoke\-SharPersist.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string65 = /.{0,1000}Invoke\-SharpGPOAbuse.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string66 = /.{0,1000}Invoke\-SharpGPO\-RemoteAccessPolicies.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string67 = /.{0,1000}Invoke\-SharpHandler.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string68 = /.{0,1000}Invoke\-SharpHide.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string69 = /.{0,1000}Invoke\-Sharphound2.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string70 = /.{0,1000}Invoke\-Sharphound3.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string71 = /.{0,1000}Invoke\-SharpHound4.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string72 = /.{0,1000}Invoke\-SharpImpersonation.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string73 = /.{0,1000}Invoke\-SharpImpersonationNoSpace.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string74 = /.{0,1000}Invoke\-SharpKatz.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string75 = /.{0,1000}Invoke\-SharpLdapRelayScan.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string76 = /.{0,1000}Invoke\-Sharplocker.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string77 = /.{0,1000}Invoke\-SharpLoginPrompt.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string78 = /.{0,1000}Invoke\-SharpMove.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string79 = /.{0,1000}Invoke\-SharpPrinter.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string80 = /.{0,1000}Invoke\-SharpPrintNightmare.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string81 = /.{0,1000}Invoke\-SharpRDP.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string82 = /.{0,1000}Invoke\-SharpSCCM.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string83 = /.{0,1000}Invoke\-SharpSecDump.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string84 = /.{0,1000}Invoke\-Sharpshares.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string85 = /.{0,1000}Invoke\-SharpSniper.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string86 = /.{0,1000}Invoke\-SharpSploit.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string87 = /.{0,1000}Invoke\-Sharpsploit_nomimi.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string88 = /.{0,1000}Invoke\-SharpSpray.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string89 = /.{0,1000}Invoke\-SharpSSDP.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string90 = /.{0,1000}Invoke\-SharpStay.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string91 = /.{0,1000}Invoke\-SharpUp.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string92 = /.{0,1000}Invoke\-Sharpview.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string93 = /.{0,1000}Invoke\-SharpWatson.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string94 = /.{0,1000}Invoke\-Sharpweb.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string95 = /.{0,1000}Invoke\-SharpWSUS.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string96 = /.{0,1000}Invoke\-Snaffler.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string97 = /.{0,1000}Invoke\-Spoolsample.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string98 = /.{0,1000}Invoke\-StandIn\..{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string99 = /.{0,1000}Invoke\-StickyNotesExtract.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string100 = /.{0,1000}Invoke\-Thunderfox.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string101 = /.{0,1000}Invoke\-Tokenvator.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string102 = /.{0,1000}Invoke\-UrbanBishop.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string103 = /.{0,1000}Invoke\-Whisker.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string104 = /.{0,1000}Invoke\-winPEAS.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string105 = /.{0,1000}Invoke\-WireTap.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string106 = /.{0,1000}no\sMimik\@tz\s\-\sloaded\ssuccessfully.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string107 = /.{0,1000}PowerSharpBinaries.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string108 = /.{0,1000}PowerSharpPack\.ps1.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string109 = /.{0,1000}PowerSharpPack\-master.{0,1000}/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string110 = /.{0,1000}S3cur3Th1sSh1t\/PowerSharpPack.{0,1000}/ nocase ascii wide

    condition:
        any of them
}
