rule SharpRODC
{
    meta:
        description = "Detection patterns for the tool 'SharpRODC' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SharpRODC"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string1 = /\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\sRODC\s\{count\}\s\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\-\s/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string2 = /\/SharpRODC\.git/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string3 = /\\SharpRODC\./ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string4 = /\\SharpRODC\\/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string5 = /62e779d3d44b32644b427335bb091880b637ed5dd3c01ec2ecd9c732a5d17539/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string6 = /69e92737993cca7f4757a5a3dc027b1f85ee6d836f18f6433332d9d269b9262f/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string7 = /987ebc109f9bb594b780a59dbe5f5b5c3694f5ac21bb0bd044b4e06ccb64bdab/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string8 = /9ca9d965d2d159763c2ca4431a1fa6597ca6633f443732139340341c77f6a39f/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string9 = /D305F8A3\-019A\-4CDF\-909C\-069D5B483613/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string10 = /Get\-ADComputer\sRODC\s\-Properties\smsDS\-RevealedList/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string11 = /https\:\/\/whoamianony\.top\/posts\// nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string12 = /Set\-DomainObject\s\-Identity\s\'CN\=Allowed\sRODC\sPassword\sReplication\sGroup.{0,1000}\s\-Set\s\@\{\'member\'\=\@\(/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string13 = /Set\-DomainObject\s\-Identity\s\'CN\=Denied\sRODC\sPassword\sReplication\sGroup.{0,1000}\s\-Clear\s\'member\'/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string14 = /Set\-DomainObject\s\-Identity\s\'CN\=RODC.{0,1000}\s\-Set\s\@\{\'msDS\-NeverRevealGroup\'\=\@\(/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string15 = /SharpRODC\.exe/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string16 = /SharpRODC\.pdb/ nocase ascii wide
        // Description: audit the security of read-only domain controllers
        // Reference: https://github.com/wh0amitz/SharpRODC
        $string17 = /wh0amitz\/SharpRODC/ nocase ascii wide

    condition:
        any of them
}
