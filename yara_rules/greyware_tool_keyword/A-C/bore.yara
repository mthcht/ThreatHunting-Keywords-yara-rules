rule bore
{
    meta:
        description = "Detection patterns for the tool 'bore' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "bore"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string1 = /\sinstall\sbore\-cli/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string2 = /\s\-\-to\sbore\.pub/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string3 = /02006756198c02904d534aa215a4382f39b9f182e6fed9d7c2bbb36f3e2c06f6/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string4 = /079ba7d752899ae9635cc444d27479b0cd314a39a282d114e9940a26fb9f55e7/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string5 = /0c2294231827539891a70bd5b7657c7d1d87f53d13f2c609a32f49ca54440797/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string6 = /24328a6907e7d2783be6817bdd1c2ca6c14aa1cb556caff0e193af56e799ff1a/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string7 = /2b5d0530f54a5cb1aa7e037ab075ba27991bafa83a42555d50fde9245a3eb435/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string8 = /32dc4748174790882d0d962dd7b5a6bf332cb8cd6c8ccf8d75d9ec5cd703274a/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string9 = /33de7cf074cc9aa8850b99ef61fb64e490cdf04f0231d76988b207b3d09cbdae/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string10 = /37206e26ef07932cdc1c9f37bb28242b85c7c895bfcfa0b58c48875e0979daf3/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string11 = /418ad6ef7472d4a0d275bb3912b5c1498e26efd801344f581f6eb63e1076e2c4/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string12 = /466de31afaad2ff25fb1e080ec326c31d4d08bc8639b2c957f3f02f2e5900139/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string13 = /4bc74cda62178ccf38917109af3b74d7612ac1fbc234d9c69f0be49e5b7425ce/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string14 = /568ec361aa33903f8cf1678a5b35592887ea6e3de3fae6a1f752730ca2e8e82c/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string15 = /66ae97d291d0e2d0dae8a8642fb8d2872a6dd0183aff325b7eaedcc911284741/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string16 = /703e2d2c0fa3fb1e6b7f1a5249533072d9d9caeaf7811dbe1750ee43c1ef0501/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string17 = /7f36205ce8bfa40c35723afeee04f94c3a3c978b6076c321b6d108d4c7f04963/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string18 = /a583e31f6c18a593b681896402295f35a903df7bc34faae45914679b3e9751b9/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string19 = /ad5c1453508585d413c083df1571738ae1158b7a83aeab24c456548fb0e4cdbd/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string20 = /ae37bedf1ad63fabd9843da4dc3598e80bc135b820555842cc20cad4f95164ff/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string21 = /ba68f7b9e8eb49325a28ed27d1ff542919952145af371b144cc7effdd0d561d9/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string22 = /bb25b3f72e24573d9695f7bb677500a695ad46ce61b61dae5d13fb035ce071c2/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string23 = /bea23804b59ef8bc8cbd4e03054e2b89baccf01b2640013e3b1b7db85c5f6b2e/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string24 = /bore\slocal\s.{0,1000}\s\-\-to\s/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string25 = /bore\sserver\s\-\-secret\s/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string26 = /c9bdea295fc4e88e634edc48697912379334da2c771e6130dc1702e32e70672c/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string27 = /c9e87a3b55c42f86a7fbbb0bd11063d7d601988d8a31db7cf1b7c827654b0dc6/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string28 = /ekzhang\/bore/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string29 = /f606f2a59706479d9cab36d16b9c241e204edb46540c92333521872dfcda025f/ nocase ascii wide
        // Description: bore is a simple CLI tool for making tunnels to localhost
        // Reference: https://github.com/ekzhang/bore
        $string30 = /http\:\/\/bore\.pub\// nocase ascii wide

    condition:
        any of them
}
