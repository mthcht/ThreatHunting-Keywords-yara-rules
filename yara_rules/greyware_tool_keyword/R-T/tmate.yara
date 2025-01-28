rule tmate
{
    meta:
        description = "Detection patterns for the tool 'tmate' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "tmate"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string1 = " install tmate"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string2 = /\/\.tmate\.conf/
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string3 = "/tmate -k "
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string4 = /\/tmate\-ssh\-server\./
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string5 = /\/tmate\-ssh\-server\.git/
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string6 = "/tmate-ssh-server/releases/"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string7 = "/tmp/tmate"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string8 = "0965055fd620c556b5e515b292178d9fc77d04b5739c593be7c08e8b32ea93ec"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string9 = "16eb3559cff7a2c2f02aef28b81c8677dc1d2c87dbbf81d5dadbec5c84eb3f3c"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string10 = "1a092bc669e1aa4ffc86ef47e50b48aaa7fb330d39169225dc22e1ac98af691a"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string11 = "39598a1e7623f06f98429b4d31706dd12e7cb8f2b62ef82a89796f529317a956"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string12 = "43999af8d360359e36555f3a7843d4e987df5fc727e4fbd67e9bb1c4eff08150"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string13 = "4ff03132d760141bc5f6e4ad0469be9081f179cf65e8f632c5c2c1eea1ed57ce"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string14 = "52f5d95236e0d5eb73651af96e99d1da201164bfb63cea329aa25e01e2609463"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string15 = "56c158d1060d6306a404027a06868c0c9475fec5d218d3e3746b1bddfe76c115"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string16 = "632e9fb9eca80662e59afecf7eac6fb83026efdfe3f6e7d8ffbb06ca49dce4a7"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string17 = "640ab98dba4d07fc0cfd6ecbab07244bbefb0d69575ce43a14ebb4f589de016b"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string18 = "6e503a1a3b0f9117bce6ff7cc30cf61bdc79e9b32d074cf96deb0264e067a60d"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string19 = "887db63eb3481f3a32aa449b84cbc44b4059ba2eacb869a87e965c10b4ce0173"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string20 = "9bb687cca974dcb711e07739d9eaa8ed124519c2531a4442a0c0d320a75d8584"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string21 = "9cfa910939a8af2fbf84786f386cb38d801981d9eb85337ac9694411e8133114"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string22 = "bd6c9258ee73cd63d1b1a2aa02fda7cbefd1cee3ff17a590fc74613723625043"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string23 = "c0339ea0fe2da7faf3e26186c09b27ba7697728311a98d5890ad504804395b8b"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string24 = "cab846a2c20b581cb99f032f0e06c48baea38186f328c07d0f730e64b40f63b1"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string25 = "d6777b4c6f1d93d8b23df1499c0ca56a9531ff823b07b923e094c9e9dba0d304"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string26 = "dea4f15255d1b7f31845c80e1a49ace858044561465d60e5d8bbc029a404b150"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string27 = "dfb7cd69256fb8b7d188f6819643ec10475b489c7d82c1950480e7b96f20116a"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string28 = "ec7ce933860267a9fd6fb69a88ca01a8e5ec911910745fe8c2b6220cc0ab682f"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string29 = "emerge -a app-misc/tmate"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string30 = "f42dc28b48ba4a85f8127ccf118136aae48407eeee8c22a640d2d3ae755184d9"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string31 = "fee0ecda586f1dfec39d0de21239642953ce228082a118e030fd76b4f827ae7c"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string32 = "ffb2e75e9f58cb082f6cabb6e0a4794b0e22b037dc82abc3bc7ee8f376f44e23"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string33 = /https\:\/\/tmate\.io\/t\//
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string34 = "pacman -S tmate"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string35 = "pkg_add tmate"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string36 = "set -g tmate-server-"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string37 = "set tmate-api-key "
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string38 = "set tmate-authorized-keys"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string39 = "set tmate-session-name "
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string40 = "set-option -g tmate-webhook-"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string41 = /ssh\s.{0,1000}\.tmate\.io/
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string42 = /sudo\s\.\/tmate\-ssh\-server/
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string43 = /tmate\s\-a\s\~\/\.ssh\/authorized_keys/
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string44 = "tmate -F -n "
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate
        $string45 = "tmate -S /tmp"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string46 = "tmate/tmate-ssh-server"
        // Description: Instant terminal sharing
        // Reference: https://github.com/tmate-io/tmate-ssh-server
        $string47 = "tmate-io/tmate"

    condition:
        any of them
}
