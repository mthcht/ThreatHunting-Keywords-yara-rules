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
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string22 = /\/PowerSharpPack\// nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string23 = /\\GzipB64\.exe/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string24 = /\\PowerSharpPack\\/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string25 = /\\windows\\temp\\pwned\.trx/ nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string26 = /\-Command\s\"\-\-signature\s\-\-driver\"/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string27 = /GzipB64\.exe/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string28 = /GzipB64\.pdb/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string29 = /Invoke\-BadPotato/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string30 = /Invoke\-BadPotato/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string31 = /Invoke\-BetterSafetyKatz/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string32 = /Invoke\-BetterSafetyKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string33 = /Invoke\-BlockETW/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string34 = /Invoke\-Carbuncle/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string35 = /Invoke\-Carbuncle/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string36 = /Invoke\-Certify/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string37 = /Invoke\-Certify/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string38 = /Invoke\-DAFT/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string39 = /Invoke\-DAFT\./ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string40 = /Invoke\-DinvokeKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string41 = /Invoke\-Eyewitness/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string42 = /Invoke\-Eyewitness/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string43 = /Invoke\-FakeLogonScreen/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string44 = /Invoke\-FakeLogonScreen/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string45 = /Invoke\-Farmer/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string46 = /Invoke\-Farmer/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string47 = /Invoke\-Get\-RBCD\-Threaded/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string48 = /Invoke\-Get\-RBCD\-Threaded/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string49 = /Invoke\-Gopher/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string50 = /Invoke\-Gopher/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string51 = /Invoke\-Grouper2/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string52 = /Invoke\-Grouper2/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string53 = /Invoke\-Grouper3/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string54 = /Invoke\-Grouper3/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string55 = /Invoke\-HandleKatz/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string56 = /Invoke\-HandleKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string57 = /Invoke\-Internalmonologue/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string58 = /Invoke\-Internalmonologue/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string59 = /Invoke\-Inveigh/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string60 = /invokeKatz\.ps1/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string61 = /Invoke\-KrbRelay/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string62 = /Invoke\-KrbRelay/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string63 = /Invoke\-LdapSignCheck/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string64 = /Invoke\-LdapSignCheck/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string65 = /Invoke\-Lockless/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string66 = /Invoke\-Lockless/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string67 = /Invoke\-MalSCCM/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string68 = /Invoke\-MalSCCM/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string69 = /Invoke\-MITM6/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string70 = /Invoke\-MITM6/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string71 = /Invoke\-NanoDump/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string72 = /Invoke\-NanoDump/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string73 = /Invoke\-OxidResolver/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string74 = /Invoke\-OxidResolver/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string75 = /Invoke\-P0wnedshell/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string76 = /Invoke\-P0wnedshell/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string77 = /Invoke\-P0wnedshellx86/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string78 = /Invoke\-P0wnedshellx86/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string79 = /Invoke\-Postdump/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string80 = /Invoke\-PPLDump/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string81 = /Invoke\-PPLDump/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string82 = /Invoke\-Rubeus/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string83 = /Invoke\-Rubeus/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string84 = /Invoke\-SafetyKatz/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string85 = /Invoke\-SafetyKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string86 = /Invoke\-SauronEye/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string87 = /Invoke\-SauronEye/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string88 = /Invoke\-SCShell/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string89 = /Invoke\-SCShell/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string90 = /Invoke\-Seatbelt/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string91 = /Invoke\-Seatbelt/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string92 = /Invoke\-ShadowSpray/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string93 = /Invoke\-ShadowSpray/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string94 = /Invoke\-SharpAllowedToAct/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string95 = /Invoke\-SharpAllowedToAct/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string96 = /Invoke\-SharpBlock/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string97 = /Invoke\-SharpBlock/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string98 = /Invoke\-SharpBypassUAC/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string99 = /Invoke\-SharpBypassUAC/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string100 = /Invoke\-SharpChromium/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string101 = /Invoke\-SharpChromium/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string102 = /Invoke\-SharpClipboard/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string103 = /Invoke\-SharpClipboard/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string104 = /Invoke\-SharpCloud/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string105 = /Invoke\-SharpCloud/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string106 = /Invoke\-SharpDPAPI/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string107 = /Invoke\-SharpDPAPI/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string108 = /Invoke\-SharpDump/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string109 = /Invoke\-SharpDump/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string110 = /Invoke\-SharPersist/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string111 = /Invoke\-SharPersist/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string112 = /Invoke\-SharpGPOAbuse/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string113 = /Invoke\-SharpGPOAbuse/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string114 = /Invoke\-SharpGPO\-RemoteAccessPolicies/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string115 = /Invoke\-SharpGPO\-RemoteAccessPolicies/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string116 = /Invoke\-SharpHandler/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string117 = /Invoke\-SharpHandler/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string118 = /Invoke\-SharpHide/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string119 = /Invoke\-SharpHide/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string120 = /Invoke\-Sharphound2/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string121 = /Invoke\-Sharphound2/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string122 = /Invoke\-Sharphound3/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string123 = /Invoke\-Sharphound3/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string124 = /Invoke\-SharpHound4/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string125 = /Invoke\-SharpHound4/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string126 = /Invoke\-SharpImpersonation/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string127 = /Invoke\-SharpImpersonation/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string128 = /Invoke\-SharpImpersonationNoSpace/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string129 = /Invoke\-SharpImpersonationNoSpace/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string130 = /Invoke\-SharpKatz/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string131 = /Invoke\-SharpKatz/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string132 = /Invoke\-SharpLdapRelayScan/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string133 = /Invoke\-SharpLdapRelayScan/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string134 = /Invoke\-Sharplocker/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string135 = /Invoke\-Sharplocker/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string136 = /Invoke\-SharpLoginPrompt/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string137 = /Invoke\-SharpLoginPrompt/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string138 = /Invoke\-SharpMove/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string139 = /Invoke\-SharpMove/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string140 = /Invoke\-SharpPrinter/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string141 = /Invoke\-SharpPrinter/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string142 = /Invoke\-SharpPrintNightmare/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string143 = /Invoke\-SharpPrintNightmare/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string144 = /Invoke\-SharpRDP/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string145 = /Invoke\-SharpRDP/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string146 = /Invoke\-SharpSCCM/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string147 = /Invoke\-SharpSCCM/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string148 = /Invoke\-SharpSecDump/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string149 = /Invoke\-SharpSecDump/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string150 = /Invoke\-Sharpshares/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string151 = /Invoke\-Sharpshares/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string152 = /Invoke\-SharpSniper/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string153 = /Invoke\-SharpSniper/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string154 = /Invoke\-SharpSploit/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string155 = /Invoke\-SharpSploit/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string156 = /Invoke\-Sharpsploit_nomimi/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string157 = /Invoke\-Sharpsploit_nomimi/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string158 = /Invoke\-SharpSpray/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string159 = /Invoke\-SharpSpray/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string160 = /Invoke\-SharpSSDP/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string161 = /Invoke\-SharpSSDP/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string162 = /Invoke\-SharpStay/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string163 = /Invoke\-SharpStay/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string164 = /Invoke\-SharpUp/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string165 = /Invoke\-SharpUp/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string166 = /Invoke\-Sharpview/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string167 = /Invoke\-Sharpview/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string168 = /Invoke\-SharpWatson/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string169 = /Invoke\-SharpWatson/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string170 = /Invoke\-Sharpweb/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string171 = /Invoke\-Sharpweb/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string172 = /Invoke\-SharpWSUS/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string173 = /Invoke\-SharpWSUS/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string174 = /Invoke\-Snaffler/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string175 = /Invoke\-Snaffler/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string176 = /Invoke\-Spoolsample/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string177 = /Invoke\-Spoolsample/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string178 = /Invoke\-StandIn/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string179 = /Invoke\-StandIn\./ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string180 = /Invoke\-StickyNotesExtract/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string181 = /Invoke\-StickyNotesExtract/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string182 = /Invoke\-Thunderfox/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string183 = /Invoke\-Thunderfox/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string184 = /Invoke\-Tokenvator/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string185 = /Invoke\-Tokenvator/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string186 = /Invoke\-UrbanBishop/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string187 = /Invoke\-UrbanBishop/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string188 = /Invoke\-Whisker/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string189 = /Invoke\-Whisker/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string190 = /Invoke\-winPEAS/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string191 = /Invoke\-winPEAS/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string192 = /Invoke\-WireTap/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string193 = /Invoke\-WireTap/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string194 = /no\sMimik\@tz\s\-\sloaded\ssuccessfully/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string195 = /PowerSharpBinaries/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string196 = /PowerSharpPack\.ps1/ nocase ascii wide
        // Description: offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string197 = /PowerSharpPack\.ps1/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string198 = /PowerSharpPack\-master/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string199 = /S3cur3Th1sSh1t\/PowerSharpPack/ nocase ascii wide

    condition:
        any of them
}
