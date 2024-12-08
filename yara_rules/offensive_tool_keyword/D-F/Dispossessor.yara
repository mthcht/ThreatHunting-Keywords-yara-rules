rule Dispossessor
{
    meta:
        description = "Detection patterns for the tool 'Dispossessor' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Dispossessor"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: scheduled task used by Dispossessor ransomware group to disabled AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string1 = " /Create /SC ONCE /TN 'DisableBitdefender-" nocase ascii wide
        // Description: user name used in Dispossessor ransomware group notes - adding to admin group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string2 = " localgroup administrators BitdefenderBounty " nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string3 = /\/cleanRDP\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove Sophos
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string4 = /\/Sophos\sRemoval\sTool\.ps1/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove Sophos
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string5 = /\/Sophos\%20Removal\%20Tool\.ps1/ nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string6 = /\\cleanRDP\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string7 = /\\disable\-defender\.rar/ nocase ascii wide
        // Description: script used to install anydesk by the Dispossessor group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string8 = /\\hidden\-cmd\.bat/ nocase ascii wide
        // Description: credential scripts used by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string9 = /\\ProgramData\\found_shares\.txt/ nocase ascii wide
        // Description: notes used to install anydesk by the Dispossessor group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string10 = /\\Safe_mode_AnyDesk\.txt/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string11 = /\\Sophos\sRemoval\sTool\.ps1/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string12 = /\\windows\\temp\\CreateService\.ps1/ nocase ascii wide
        // Description: script used to install anydesk by the Dispossessor group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string13 = "032bf57408a5cc20cb45e19dc494fa0ee9dcd3b70b0c606698dd9af4e689268b" nocase ascii wide
        // Description: Bruteforce tools used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string14 = "07d8d02d79b1653fdb0f1c91a56d62f7f1a418564874605e07755a1f9f010b61" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string15 = "1a26c5a16b9601d79e53c830cfb5e339b6629d3e1d1d4ceb2993c7ff48734c60" nocase ascii wide
        // Description: Bruteforce tools used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string16 = "1cdbbd933f2f3b766efcabbe97d13cd5275165a3d67b9dfb0aa6d34fd7a89bfd" nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string17 = "20cd0aabd640797f04eaa5c121a282002871288efc8f4915dffd46f75bc21d71" nocase ascii wide
        // Description: ngrok authent token used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string18 = "27f1C8X9cfrYlKDqSViVB3O98xj_56MqzcTRpNGioTnpwbJVj" nocase ascii wide
        // Description: CleanRDP.bat script erasing RDP traces used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string19 = "2bb07676482a8d332efd72aeb151af750b90d5e5e67fe75752dba92f3bc74786" nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string20 = "2d970264f004706b30aba04627024af60227bd9da276cf924912d6a18bce8567" nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string21 = "2e75b82c2b0c1f1c1d449fb6077cad9bb5311ed933f990214efdb6556b27017e" nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string22 = "2e75b82c2b0c1f1c1d449fb6077cad9bb5311ed933f990214efdb6556b27017e" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string23 = "30ae46c2d4af520064374b822bdbc1bbce8dfb67a1280dc6b4461c67aa3289f0" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string24 = "30D66EE9B5168E6E03F7E57F4A0CEA711CCC8BB69F911E143626F50DAA67D660" nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string25 = "38d05edbbe5d0667278b55dbf9c53493153e8416e4694c97d92f06f429690dc0" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string26 = "3972dc9744f6499f0f9b2dbf76696f2ae7ad8af9b23dde66d6af86c9dfb36986" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string27 = "4435f3c1a52fe762834684da28c45e9b5217b9c0cb65882f95cc45516c8afd9b" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string28 = "45ac6b7f8086f9f50624985e018dc4869cf5a4bb9c831d76cc0d1eeb1baf2105" nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string29 = "4a8cf21bf284a3a1b2e17abf51ac94f47ba5595676a56d4fe9b276054528e4e8" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string30 = "4E3374D3AC2BA877D985A8D3FCEB7A9D5E518C16029A2DC5CE8DBA4306384A8D" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string31 = "55bd5fa243002914817f32fb28c16579d57cf21b12406d350b226de472b66856" nocase ascii wide
        // Description: Bruteforce tools used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string32 = "56860821457ebef4e71091ee01f6abe3703bc83cc56ae6db40ed140ab1c48043" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string33 = "5D48347779833123E9FCCBCDC58ECE0FC301F05BCA0EDAFD34DE4F2693DC5E59" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string34 = "63184d644922cc6b2c7cf8c1059485d5de726bd2d5e6538bfcdbec841818ca87" nocase ascii wide
        // Description: Bruteforce tools used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string35 = "6881a17bb0b124e295cfbf2fae1165babe35a3dda065dd246dad52b107ef3252" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string36 = "79d864217d3db0f218b2a638648d1a86b5b6ef2d4fab9d09cd50460685f1a2a7" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string37 = "80736669542D3727C77CCDA1589F9D7C17568A1D97D98FFAE84AFBBBF081BE67" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string38 = "872ee783ea0fc1ed1d646611c77a424568a0a90f0d7b5a0dc430f248a0b824ee" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string39 = "8bcd2cc3874df031fb416bb9f451e2b13f146a71b0e02a7edca42c21b1d248b0" nocase ascii wide
        // Description: Bruteforce tools used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string40 = "8f0c9eaabea10640a0e534b55d46c1d61aa92bb370d4696fb9e7b3c8bb965d8d" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string41 = "971EA5AE1205C3DC4693EED2C730D21E00022E9EA17D5928C2695749D68BB7A7" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string42 = "A2791A8889432638BC1ADB213A1CF50E9B07439442D77D6057C635778789CC82" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string43 = "a4a32b65f7452ee26bb5be301620461938d46f44455a5be4e872a6dda8c6150e" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string44 = "A4D129236E794B44A883AA46B8722E7190DBAC0F0AED2FEBB087C93C81CA6383" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string45 = "A6FF9B59C25CE7EED2D73C5310BCE5E57071601D3F61E0F9C03715FEE99A1085" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string46 = "a7accf6149a294089b3a2220d4ba48e567a31f4af6d8b4b8654ba90bae93895a" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string47 = "AA5751006B1D1F18E8BD39F254DD31F26E1EC45FE6FC910B4BFCD0528A5ACBFD" nocase ascii wide
        // Description: email account used by the ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string48 = /appadmin9090\@proton\.me/ nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string49 = "bac0dc3ff787d4aa2989b0d899510c98a0a7ef5923c55860c70b27c96a1a3d19" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string50 = "BDC1465EDF60B9B627B24051396694AAE3048DC5D5F7C79813C1AFA0741BBD7D" nocase ascii wide
        // Description: Bruteforce tools used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string51 = "bfe768938d3186ff5a221c06902e18c4e67aa4d7c11b07aa54aeeb3746e31efe" nocase ascii wide
        // Description: tool used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string52 = /Bitdefender\-DisableAV\-Remote\.bat/ nocase ascii wide
        // Description: script names used by Dispossessor ransomware group executed by dir_start.bat
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string53 = /C\:\\dir2\.bat/ nocase ascii wide
        // Description: script names used by Dispossessor ransomware group executed by dir_start.bat
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string54 = /C\:\\dir4\.bat/ nocase ascii wide
        // Description: script names used by Dispossessor ransomware group executed by dir_start.bat
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string55 = /C\:\\dir5\.bat/ nocase ascii wide
        // Description: script names used by Dispossessor ransomware group executed by dir_start.bat
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string56 = /C\:\\dir6\.bat/ nocase ascii wide
        // Description: script names used by Dispossessor ransomware group executed by dir_start.bat
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string57 = /C\:\\dir7\.bat/ nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string58 = "c639d871357cbbf7fffcb59745989ae74ec836e149695568480a9a7fba1fc591" nocase ascii wide
        // Description: script used to install anydesk by the Dispossessor group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string59 = "c7fa65795c3627674274f83ccab5776c80922708787a2121ac4d5cfd02551fc4" nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string60 = "cbaea921d56ea8c24330964c8b73ba77ceccd1691b80213399c18eb82c54b11a" nocase ascii wide
        // Description: script used to install anydesk by the Dispossessor group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string61 = "d18c5c837e4bdfb76b6c4e6fa7ad0d6e583eec0cadf8184cd9297c77813337c2" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string62 = "D1C2F2133FF88AEE3A302ABB828198F12C075847297604D3A1AF8CD5E91645B5" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string63 = "d1d808c69e803b797745a4bd963e44aa1f0ec16edbc721114867d9ef02f0a94d" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string64 = "d2fe624c63b655021b81ba91f90618cb9fc9ea56535117e945f41912cd9f2cd5" nocase ascii wide
        // Description: Bruteforce tools used by Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string65 = "d3468041efe888dda240f4aafc6182365b39dfe0ca7ae9c5c5acc0802a34bc5d" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string66 = "D4C4772E4D0E458214204795B306E71E67AB3554547CE06DDDC180219E5F4C3D" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string67 = "DFFE7691BAC94B487B52667CEA436719BCCE3E84D0B47BF8191B52C4FC50063E" nocase ascii wide
        // Description: tool used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string68 = /DisableBitdefenderAV\.exe/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string69 = /DisableBitdefenderAV\-1\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string70 = /DisableBitdefenderAV\-2\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string71 = /DisableBitdefenderAV\-3\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string72 = /DisableBitdefenderAV\-4\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string73 = /DisableBitdefenderAV\-5\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string74 = /DisableBitdefenderAV\-6\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string75 = /DisableBitdefenderAV\-7\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string76 = /DisableBitdefenderAV\-8\.bat/ nocase ascii wide
        // Description: script used by Dispossessor ransomware group to remove AV
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string77 = /DisableBitdefenderAV\-9\.bat/ nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string78 = "E1AC3CD517F50462DD5B022F4D0016F3B9E8BCD8FC72B86FBB94C36BBA6EE543" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string79 = "e1d459e568068bae8db668a9478e7d373afda5a174f2ea54a329056f5d6b681b" nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string80 = "ed87362886559097875401d60cbcb440d8cf6da80ad5a6cc36aa0e679ce7c0a6" nocase ascii wide
        // Description: Dispossessor ransomware scripts and binaries
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string81 = "EFE50F0BE7CE12CB062816896427A3E1CD8B025CA218805C321882AB33520E4D" nocase ascii wide
        // Description: hashes of AV removing scripts tools and notes from the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string82 = "f51cdf6aff5e752276cf11830733e4ac4b69526d4031ecaee4884f2c36576c4c" nocase ascii wide
        // Description: socks tools used by the ransomware group Dispossessor
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string83 = "f88dbf4830bbe1e1c4df5d928626e757180857b56bfdc3e01ff6883662c2cc0e" nocase ascii wide
        // Description: credential scripts used by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string84 = /Find\-KeePassconfig\sC\:\\/ nocase ascii wide
        // Description: credential scripts used by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string85 = "function Find-KeePassconfig" nocase ascii wide
        // Description: credential scripts used by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string86 = "Get-ChromeDump " nocase ascii wide
        // Description: credential scripts used by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string87 = /Get\-ChromePasswords\.ps1/ nocase ascii wide
        // Description: credential scripts used by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string88 = "Get-FirefoxPasswords " nocase ascii wide
        // Description: credential scripts used by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string89 = /Get\-FirefoxPasswords\.ps1/ nocase ascii wide
        // Description: email used by the Dispossessor ransomware group notes for data exfiltration
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string90 = /guerillamailaccount\@sharklasers\.com/ nocase ascii wide
        // Description: credential scripts used by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string91 = "Invoke-Get-FirefoxPasswords" nocase ascii wide
        // Description: credential scripts used by the Dispossessor ransomware group
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string92 = "Invoke-mimikittenz" nocase ascii wide
        // Description: email used by the Dispossessor ransomware group notes for data exfiltration
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string93 = /nevah\.juan\@allfreemail\.net/ nocase ascii wide
        // Description: email used by the Dispossessor ransomware group notes for data exfiltration
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string94 = /rakeem\.osias\@foreastate\.com/ nocase ascii wide
        // Description: script used in the Dispossessor ransomware group notes
        // Reference: https://vx-underground.org/Archive/Dispossessor%20Leaks
        $string95 = /trendmicro\spass\sAV\sremove\.bat/ nocase ascii wide

    condition:
        any of them
}
