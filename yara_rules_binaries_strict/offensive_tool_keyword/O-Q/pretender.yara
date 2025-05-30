rule pretender
{
    meta:
        description = "Detection patterns for the tool 'pretender' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pretender"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string1 = " --dont-spoof " nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string2 = " --dont-spoof-for " nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string3 = /\/pretender\.exe/ nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string4 = /\/pretender\.git/ nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string5 = /\/pretender_Linux_arm\.tar\.gz/
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string6 = /\/pretender_Windows_x86_64\.zip/ nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string7 = /\/releases\/download\/v.{0,100}\/pretender_/ nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string8 = /\\pretender\.exe/ nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string9 = /\\pretender_Windows_x86_64\.zip/ nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string10 = "037be685f55c58fdbb54ccbff3829e4de62d73174cc2a25339b047515877f1b9" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string11 = "1852b51d64caeda03dba3856a6f691fb80f5a240946fd968d1978f41e7f56fc1" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string12 = "1aade6ab28b468f362122c2b96f45f572a66142e09214b30467bc3d97a345d0b" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string13 = "1e06baefc53c4bd963aca273bc8a05d683664c755a20baf2a04c95c5e3888ca0" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string14 = "23d95cfa93563a5a187125ae4caac02f2cad2132b382b2bdb9b36a28b23194af" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string15 = "31bd80a4afc0f06bce365a02b6035e55d7a13d2e9c949b4d401133a4deef5c40" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string16 = "3a71764fed9b90c2b7a05ca5cac028dc9980d5d4da2b53570f490b43c829f0c0" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string17 = "484e5f88fb6e76e88b542f032e1ff0b693e16f67ca9810cbc4de4d1314f4420d" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string18 = "48f5813a8aedad134e9d5d3ee4be23f50f2cdc98b43d46f86913e2d1d34bd276" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string19 = "4a2cb5591a0c84383b2a476d27de2647ae1a88c1e60ba409a90049a132bebb73" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string20 = "52ee64e32e40b7fb75d57b97f66359cad87fe7a6bace5cdd3a17bd48be13e878" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string21 = "544207337c0553feb47498ed24a367c427dcb5feb49f0e3eee4913d235610262" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string22 = "558919265d6ae62662b5326b9dfa3a03b7a07bb9b657bc13130adc12124d06d0" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string23 = "5791ebb3782d4210dcd5e16ca5f8e16d30582b73f87fc848735a09374190d010" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string24 = "5b14b133f4421557781cf8765d8a16bb5a6ca90ef5606dee10af7eee3107a18f" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string25 = "5e16331a5e5b6bf1c82658272e49d8f28bcac62bd222e08f530ee9062ca16b23" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string26 = "5eb106f4e859025654fcab29697c9b4599545b89da2ddd9c5db318c0b53cd66d" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string27 = "60faba8d3526efd03354e82efb9d9d272bbf39e7b3b5c785b35675d0791b377e" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string28 = "61241af5ce576034133175ae34bbf8107c57d0b7546b964ba6a436c9f5202638" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string29 = "62e4454e30b5238083722ab887d43c7e522a9ace13f1e62bf1618b717b80938c" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string30 = "649be8fb570c82231730dbdba7934429187a5d8deaf0a17150aa304786378434" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string31 = "65d2c2559bab3590761c7d856d14bcccf2bcc3f2f25ac6ff0d3e1a62de49540b" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string32 = "68f88c6f39dea0b385af37b957b9a55ad766a079d53a03deaee5a44790ce62cf" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string33 = "6c43f8eb224f04c2d5c0dc415e16db9151ab0739c7dc12530be41ff61682ffbe" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string34 = "81f9ec1160d8019b6279927295f308a0697e132b3f09876e9d1e4b2e2192be55" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string35 = "8659af289bd4328901e5ba6e08a8ecead915c02a1d402a154ee3cddd16b65999" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string36 = "86dfbd71a69913b1a1a5303da9a7cbe612bdcf798717ab9db54cf876b589a03f" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string37 = "8a496c84ce56714227135340a42fb720d04f4f9038e46b1e525e6fbdc87434e8" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string38 = "92957b4a275c9aeb0579dbd5ce0fa2997de8cf1a3952b540089ef3b1c0729aaf" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string39 = "987d9b6f804800af119f8f286976ae67a3ce09e2b54170511afa8307fe40f70c" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string40 = "a2d9e1816e8f4f6a4bbb1a0b19c0805b1a2b221615d5038740a5903be8ed7cc3" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string41 = "aa8cfc4df8dea4d1fe806aef767c9c0f522ab3f49cc471c19bb0851dda5448fc" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string42 = "ad9d0bd619aae9231977ed9b002981bf272afb9a93d198406296a7b4f7d28542" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string43 = "c5a8b48bbe0bf68409a54d401ebac706e3f3880822310717d2d8e7db5cec436b" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string44 = "c7f3f560c94164a7ed168b1ea7c5edf9e0cda3a9fe1a7e3918c1de6378444869" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string45 = "ca6e34d55019477a50ab0f91cdef48d755a7d8e10bfc65851a6bf67bc50f7963" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string46 = "cfcaca43f0d9b496ee8d45d9382492994b9c120a5d1cb0e51c23528a8ca4c171" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string47 = "d38d1bd6117fce3916ca8b1c8c2c0bf62f8cb9753bdc3ac6e18071cd85631a3e" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string48 = "d7257981496461fd58ba1e00931ad71ff49a9e41f7e81d5ce04de265674b14f7" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string49 = "dde0f307acb5f8701be9bd6ecefa316952a96f3629e04fa8f519865752d78691" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string50 = "e258ac6068d1de41188caf6269d662aadf7b6e0489aa7b18b32a57f4691559e3" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string51 = "e273cf78ec19c5e3051a98721131c2b94d7a3bdadc5e3269ccb7b72e230ee643" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string52 = "ea4f2fa909653aa2c186bd78bca337abdd3aa7dc7277a510c4d6ffc692284ee8" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string53 = "ed8aaac54cc040340e0bdb1fd8396c72399c26e8385c9778558378bdf3bd8ac4" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string54 = "fb834d272d81fcdad1dbceeaf118960fce2e0398a4ab47640fdbd139db9b947a" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string55 = "fc9b3605369431a13dff28fc6bd80351199281ac59b536902db537132cb69ab5" nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string56 = /kontakt\@redteam\-pentesting\.de/ nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string57 = /ntlmrelayx\.py/ nocase ascii wide
        // Description: MitM sidekick for relaying attacks featuring DHCPv6 DNS takeover as well as mDNS - LLMNR and NetBIOS-NS spoofing
        // Reference: https://github.com/RedTeamPentesting/pretender
        $string58 = "RedTeamPentesting/pretender" nocase ascii wide
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
