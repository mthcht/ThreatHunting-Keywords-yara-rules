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
        $string1 = " -grouper2 -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string2 = " -Internalmonologue  -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string3 = " -lockless -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string4 = /\s\-Rubeus\s\-Command\s.{0,1000}kerberoast/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string5 = " -SauronEye -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string6 = " -seatbelt -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string7 = " -SharpChromium " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string8 = " -SharpDPAPI -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string9 = " -SharPersist " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string10 = " -SharpShares " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string11 = " -SharpSniper " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string12 = " -SharpSpray " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string13 = " -SharpUp -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string14 = " -Sharpview " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string15 = " -sharpweb -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string16 = " -Tokenvator -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string17 = " -UrbanBishop -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string18 = " -watson -Command " nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string19 = " -winPEAS " nocase ascii wide
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
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string24 = "03C4F510E0DA9684181E07BD9F4FB1329BFC9F815856BCDA224D37666704EEAF" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string25 = "04DD48A0AFD6D6EA2969225DE9DDEF69EDB3DBC1D8C1AED2C4F12E9621C948F1" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string26 = "04E8D9E98A7BAF3AFBA44E9FCFF34659979ED27AC3AE92EE2184F5963F339E32" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string27 = "0800C357553BD74B42A5DD8A7C80C59422BFBC23F3E3F81CF0B16DEF66D4A70F" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string28 = "0E7A579798A6A57A88C6CBD5C67313E43B8F7D84DF4798C88142B134D48C263B" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string29 = "15835E15B02D775A71F29ECEF61FC3E5ADB50C13F8987072A945AF99A17C0F6E" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string30 = "1877E0EC0E657212BF5C9C9170427F7B4D8FDCBED8CFE8FAC388827CE33FDADD" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string31 = "1B3D331BD6ABC44B54119E00509215AE3EA4B482DDB0C9F0D21D71C24EC3B5B6" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string32 = "2566C66F43F181F2B8AEFE41D902F02B54AE284B516062270E83F301A32A5F35" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string33 = "4351D871B1B4CB1BA8F54C52A6786C809707A05353B46EA1AF9A4950D88C4E61" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string34 = "648BA42AFD2FEC89A055E69B21A04CB11B74F13916249F4BC3512C3145FDC249" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string35 = "6C3D086F568E4DCF1379D750C48464FC1F737326E2547DEE1EAFFD00F19FF16C" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string36 = "6F3899086ACCAB2E2686ADB078E049066754D0EE7798666042416CEF566F65E0" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string37 = "7D430DB8006F611817143F28D8141BBDB3291348455FB0C53E9EEBE59E890695" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string38 = "9D08025F46B50B02A2B45CC2E6E83F85BC80C4AEEDEB8651E36B38DA29856542" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string39 = "9E6E4B36B39C50C733FE8EB2DD43AB1A6B397066866A1D16987D87275B0359D3" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string40 = "A5FDFE2A253B751DA1A84A41A2B501648735D027E03882CF363ACE84FE235034" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string41 = "B1952AB299560820661C7D76EF8BCF224EBA551C2F5111525428E7F2CEA0AF9A" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string42 = "BAE62044075CF4F76F0BAAD0FA33F6322541CC46F80C81170E97A181CAA43104" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string43 = "C6678CDE09F4A18DD9C295262837C94E8D069295D26CE187C94C8AEDDE996CB3" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string44 = "C7A5E6480C6CEC01E3627AE0A8EAC1FFE13226C560D4E4C05FCE1CAB1168CC8D" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string45 = "C82E994585B5C08F7259B00BD5F91AD45FCC8E42B4BF6A3CA989278D0A63BACF" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string46 = "CA9F2786DFE0A75DAF0A5C711B355D6EE0B2605D7F344E85DA9F4D40127EBC69" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string47 = "CDC35DDA09316ABD091D51CF9EE78DECE9216ABB9F09FC2CDF4EB36E4971AB3C" nocase ascii wide
        // Description: perform minidump of LSASS process using few technics to avoid detection
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string48 = "-Command \"--signature --driver\"" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string49 = "D24C50F9C1F0E6AC82157B0319127ECF72E454FE5A9E86C25891B3101F957769" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string50 = "D60C351E1207F7C344C467BB09EC1EEA33D283C34FA56A531222871BB2542CE4" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string51 = "DA0A017BDD91FE21E8580F8AC005B497743635E73649764D132726E341171D50" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string52 = "E5AF133E4976EE14EA6EDB8652F354A18483289E2E1B6043D905B821FA84C53C" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string53 = "EDE1D800842E11B147A6E039507EA5DCD7F825BF9AF3195F8B1FAF10080CDE77" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string54 = "F5F605F596F85A1344F46774D782F4109EA83DD851139338CB07DF90FD1D0D5A" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string55 = "F74BACC239A453DA97AACA6C0E9E70D2282CE801EC9A1262A8F3237CCFC27E9A" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string56 = "F8D2B9771E5AB15013A38543F05ECD747A23A6A33463D9A53106FDD15DADF002" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string57 = "FC7A5B008FCF3AD0C3535D4463C094D6833F11AB21DD39616B93A5518FB1C316" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string58 = "FFC64B8DA962F05C780B803F11727D9960C31E133523FE9DADA309F8836DD098" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string59 = "Invoke-BadPotato" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string60 = "Invoke-BetterSafetyKatz" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string61 = "Invoke-BlockETW" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string62 = "Invoke-Carbuncle" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string63 = "Invoke-Certify" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string64 = /Invoke\-DAFT\./ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string65 = "Invoke-DinvokeKatz" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string66 = "Invoke-Eyewitness" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string67 = "Invoke-FakeLogonScreen" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string68 = "Invoke-Farmer" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string69 = "Invoke-Get-RBCD-Threaded" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string70 = "Invoke-Gopher" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string71 = "Invoke-Grouper2" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string72 = "Invoke-Grouper3" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string73 = "Invoke-HandleKatz" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string74 = "Invoke-Internalmonologue" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string75 = "Invoke-KrbRelay" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string76 = "Invoke-LdapSignCheck" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string77 = "Invoke-Lockless" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string78 = "Invoke-MalSCCM" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string79 = "Invoke-MITM6" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string80 = "Invoke-NanoDump" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string81 = "Invoke-OxidResolver" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string82 = "Invoke-P0wnedshell" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string83 = "Invoke-P0wnedshellx86" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string84 = "Invoke-PPLDump" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string85 = "Invoke-Rubeus" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string86 = "Invoke-SafetyKatz" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string87 = "Invoke-SauronEye" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string88 = "Invoke-SCShell" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string89 = "Invoke-Seatbelt" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string90 = "Invoke-ShadowSpray" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string91 = "Invoke-SharpAllowedToAct" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string92 = "Invoke-SharpBlock" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string93 = "Invoke-SharpBypassUAC" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string94 = "Invoke-SharpChromium" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string95 = "Invoke-SharpClipboard" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string96 = "Invoke-SharpCloud" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string97 = "Invoke-SharpDPAPI" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string98 = "Invoke-SharpDump" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string99 = "Invoke-SharPersist" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string100 = "Invoke-SharpGPOAbuse" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string101 = "Invoke-SharpGPO-RemoteAccessPolicies" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string102 = "Invoke-SharpHandler" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string103 = "Invoke-SharpHide" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string104 = "Invoke-Sharphound2" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string105 = "Invoke-Sharphound3" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string106 = "Invoke-SharpHound4" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string107 = "Invoke-SharpImpersonation" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string108 = "Invoke-SharpImpersonationNoSpace" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string109 = "Invoke-SharpKatz" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string110 = "Invoke-SharpLdapRelayScan" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string111 = "Invoke-Sharplocker" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string112 = "Invoke-SharpLoginPrompt" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string113 = "Invoke-SharpMove" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string114 = "Invoke-SharpPrinter" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string115 = "Invoke-SharpPrintNightmare" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string116 = "Invoke-SharpRDP" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string117 = "Invoke-SharpSCCM" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string118 = "Invoke-SharpSecDump" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string119 = "Invoke-Sharpshares" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string120 = "Invoke-SharpSniper" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string121 = "Invoke-SharpSploit" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string122 = "Invoke-Sharpsploit_nomimi" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string123 = "Invoke-SharpSSDP" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string124 = "Invoke-SharpStay" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string125 = "Invoke-SharpUp" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string126 = "Invoke-Sharpview" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string127 = "Invoke-SharpWatson" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string128 = "Invoke-Sharpweb" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string129 = "Invoke-SharpWSUS" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string130 = "Invoke-Snaffler" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string131 = "Invoke-Spoolsample" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string132 = /Invoke\-StandIn\./ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string133 = "Invoke-StickyNotesExtract" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string134 = "Invoke-Thunderfox" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string135 = "Invoke-Tokenvator" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string136 = "Invoke-UrbanBishop" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string137 = "Invoke-Whisker" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string138 = "Invoke-winPEAS" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string139 = "Invoke-WireTap" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string140 = "no Mimik@tz - loaded successfully" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string141 = "PowerSharpBinaries" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string142 = /PowerSharpPack\.ps1/ nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string143 = "PowerSharpPack-master" nocase ascii wide
        // Description: Many useful offensive CSharp Projects wraped into Powershell for easy usage
        // Reference: https://github.com/S3cur3Th1sSh1t/PowerSharpPack
        $string144 = "S3cur3Th1sSh1t/PowerSharpPack" nocase ascii wide

    condition:
        any of them
}
