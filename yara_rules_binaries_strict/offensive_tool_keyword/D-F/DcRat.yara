rule DcRat
{
    meta:
        description = "Detection patterns for the tool 'DcRat' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DcRat"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string1 = " DisableAntiSpyware 1 -Type Dword -Force -ea 0" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string2 = "%qwqdanchun%" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string3 = /\/DcRat\.git/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string4 = /\/DcRat\.sln/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string5 = "/DcRat/releases/download/" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string6 = /\/Ransomware\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string7 = /\\DcRat\.sln/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string8 = /\\Ransomware\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string9 = /\\RemoteCamera\.dll/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string10 = ">Keylogger<" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string11 = "001f68ac4e3ffa91b0e787586bb8382aeeb8300da5548a8802417ee6a38ff880" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string12 = "024d01776b9b5d42efb6115f59ec51addab5e64db969f3ec9a564f242bf702f2" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string13 = "0c2ddbc7ae28df7912929d7523e0116c5ba39a00c842ce23876c3c1ad5490c43" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string14 = "0E423DD6-FAAF-4A66-8828-6A5A5F22269B" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string15 = /119\.45\.104\.153\:8848/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string16 = /127\.0\.0\.1\:8848/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string17 = "16fef3f7f220a758a571905bad6800a58c249af4d9a0ca47eb097c07e774250f" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string18 = "191726b972ff700b962e92c032e0f155ab314c2edec1517e18f69c63073eb859" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string19 = "1b8ca67716c0928b6e8f6325dc89affc9c312353dfcaea788618c8b50337c857" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string20 = "21a7803ec85cae6362c0ad25529e21ca76783570b93bacbe64d0502aef852b2f" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string21 = "312a47c833f5ea3eb3e1f8f3a26c9bbc811a1a4b389c432715ea8f040826f65f" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string22 = "3379f86e6b7a13491a8aa668e567b7dfc532d79da5216fd50e3659f7ea9df372" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string23 = "378FC1AA-37BD-4C61-B5DE-4E45C2CDB8C9" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string24 = "37E20BAF-3577-4CD9-BB39-18675854E255" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string25 = "40C64006-EE9C-4EC8-A378-B8499142C071" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string26 = "419a61a91a4de08b2644a68725a73c750535ea50e525ec1aea3dacf47f2ea1ea" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string27 = "424B81BE-2FAC-419F-B4BC-00CCBE38491F" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string28 = "520411a91c6021dba0746e4520bb495db8d7c71c7b1813a95b9aae26531d493a" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string29 = "5D01A326-0357-4C3F-A196-3B8B866C9613" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string30 = "605fba81b3a049064b1bff90a6ffba00cbde7e68cdb5c22cbaa197251fc0b081" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string31 = "616f3a9958a29d934fd3b1362d7f10d14d1c36b1d5c144c625fc4ab525110133" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string32 = "619B7612-DFEA-442A-A927-D997F99C497B" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string33 = "66cc6913830c3720ead982e9cd43574bb3340d112521e86b4cf3c9edf627f88b" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string34 = "66d21568244cc3fda07d6d6c28b0bc683f18f12d4508bbe7be070b9e98989395" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string35 = "68115c6e039363be3b80e416ed462d97f8c763af800237b1fa183cca1180bac5" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string36 = "6AA4E392-AAAF-4408-B550-85863DD4BAAF" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string37 = "6AA4E392-AAAF-4408-B550-85863DF3BAAF" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string38 = "6d755e74fb426af04016752db3be2c0c17aad722173e96f5797648c1ceda2cf3" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string39 = "7767C300-5FD5-4A5D-9D4C-59559CCE48A3" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string40 = "79D3788D-683D-4799-94B7-00360F08145B" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string41 = "8B73C3EC-D0C4-4E0D-843A-67C81283EC5F" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string42 = "8BF244EB-0CA3-403E-A076-F1D77731A728" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string43 = "8BFC8ED2-71CC-49DC-9020-2C8199BC27B6" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string44 = "8DE42DA3-BE99-4E7E-A3D2-3F65E7C1ABCE" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string45 = "9042B543-13D1-42B3-A5B6-5CC9AD55E150" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string46 = "94bdfe850be6641545e52c3b0a3cbe2cb753145d02004ce8211b8468902d88ba" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string47 = "96dbae48dbdc89b918377d94b26393e214655b42b56044402e15046d9ecccf97" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string48 = "9ae914a31cb9728ac8bb4519698f992af1da69233f48eaf690e9e87cfc4445be" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string49 = "9D1D39D8-2387-46ED-A4A8-59D250C97F35" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string50 = "a18a2e9a870deb66397ea527ca071bcc74ebb7789b7aeec4a179ab13a1674a00" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string51 = "a2358b98f2f8c2d58f2314043c9207dae176eea11260788d7a2d67cb82f39cc9" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string52 = "AB6CDF36-F336-4F14-8D69-3C190B7DEC65" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string53 = "abb92eca9ff99f47ecad47b9ca079ba9578b5cfdd1156a3e3b09ff43a76309ed" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string54 = "AsyncRAT/DCRat" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string55 = "b2a992052d32a5b9d3702350b133289b45a8d209acd0161d9c3b0bc6fd702b3c" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string56 = "B5C5BDD1-568E-44F6-91FF-B26962AF9A6C" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string57 = "BEE88186-769A-452C-9DD9-D0E0815D92BF" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string58 = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string59 = "C3C49F45-2589-4E04-9C50-71B6035C14AE" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string60 = /CN\=DcRat\sServer.{0,100}OU\=qwqdanchun.{0,100}O\=DcRat\sBy\sqwqdanchun/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string61 = "D640C36B-2C66-449B-A145-EB98322A67C8" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string62 = "DAFE686A-461B-402B-BBD7-2A2F4C87C773" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string63 = "DC199D9E-CF10-41DD-BBCD-98E71BA8679D" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string64 = "DC199D9E-CF10-41DD-BBCD-98E71BA8679D" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string65 = /DcRat\s\s1\.0\.7/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string66 = "DcRat By qwqdanchun" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string67 = "DCRat Keylogger" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string68 = /DcRat\.7z/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string69 = /DcRat\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string70 = /DcRat\.zip/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string71 = /DcRat_png\.png/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string72 = "DCRatBuild" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string73 = "DCRat-Log#" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string74 = /DcRat\-main\.zip/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string75 = "DcRatMutex_qwqdanchun" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string76 = "DCRatPlugin" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string77 = "e42d27145528616d6fe1951421989dbdaf174abe860b90bdc9321f1093593a71" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string78 = "EE03FAA9-C9E8-4766-BD4E-5CD54C7F13D3" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string79 = "EFFE3048-E904-48FD-B8C0-290E8E9290FB" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string80 = "f05ff84ba4bb193182883786c635cac0643b51d7046cedfc48c352ca415d348a" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string81 = "f15b1b50831974a8a4ac09cce5b7b9f5cc71404ee4cabe67ee2f95e890419d3c" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string82 = "f5986b6b5b1365e170643d4aa47939b15ea02a9d647e75a2a76bc7c0eb2de702" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string83 = "f67dd8a803b6a71f7e13d8d0c8d6bb07de34a401f5fc966c157fc46e1c2a557c" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string84 = "ffa560f9e335f64e3e5716bcf9566e2b80a9071e92f7c2da81a191026d2c3794" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string85 = /https\:\/\/pastebin\.com\/raw\/fevFJe98/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string86 = /Keylogger\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string87 = /Keylogger\.pdb/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string88 = "localhost:8848" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string89 = "OU=qwqdanchun" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string90 = /Plugins\\SendFile\.dll/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string91 = /Plugins\\SendMemory\.dll/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string92 = "qwqdanchun" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string93 = "qwqdanchun/DcRat" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string94 = /Ransomware\.dll/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string95 = /Ransomware\.pdb/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string96 = /Resources\\donut\.exe/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string97 = /ReverseProxy\.dll/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string98 = "System' EnableSmartScreen 0 -Type Dword -Force -ea 0" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string99 = "Windows Defender' DisableAntiSpyware 1 -Type Dword -Force -ea 0" nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string100 = /Windows\sDefender\sSecurity\sCenter\\\\Notifications\'\sDisableNotifications\s1\s\-Type\sDword\s\-ea\s0/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string101 = /Windows\sDefender\sSecurity\sCenter\\Notifications\'\sDisableNotifications\s1\s\-Type\sDword\s\-ea\s0/ nocase ascii wide
        // Description: DcRat C2 A simple remote tool in C#
        // Reference: https://github.com/qwqdanchun/DcRat
        $string102 = "Windows Defender\" DisableAntiSpyware 1 -Type Dword -Force -ea 0" nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or // Windows binary
            uint16(0) == 0x457f or // Linux ELF
            uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or // macOS binary
            uint32(0) == 0x504B0304 or // Android APK, JAR
            uint32(0) == 0xCAFEBABE or // Java Class, Mach-O Universal Binary
            uint32(0) == 0x4D534346 or // Windows Cabinet File
            uint32(0) == 0xD0CF11E0 or // MSI Installer Package
            uint16(0) == 0x2321 or // Shebang (#!)
            uint16(0) == 0x3c3f // PHP and other script
        )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}
