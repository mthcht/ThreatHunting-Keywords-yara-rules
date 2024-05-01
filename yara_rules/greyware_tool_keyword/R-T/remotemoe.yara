rule remotemoe
{
    meta:
        description = "Detection patterns for the tool 'remotemoe' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "remotemoe"
        rule_category = "greyware_tool_keyword"

    strings:
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string1 = /\sssh\s\-R.{0,1000}\sremote\.moe/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string2 = /\.config\/systemd\/user\/remotemoe\.service/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string3 = /\/remotemoe\.git/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string4 = /159\.69\.126\.209/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string5 = /69bc5a68959f7b47ac43810dbe782723eca56101d4bb60533a78530ac1ba23b1/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string6 = /7k3j6g3h67l23j345wennkoc4a2223rhjkba22o77ihzdj3achwa\.remote\.moe/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string7 = /92c70b09d49bef20ae730c579e125f4f7c66d85ef2249c77694f0066a3156b26/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string8 = /df1b9ddfb57a7fa9b93b250a689e392171764364ff929a701e7a2df763904b78/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string9 = /dummy\.remote\.moe/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string10 = /fasmide\/remotemoe/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string11 = /http\:\/\/.{0,1000}\.remote\.moe\// nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string12 = /https\:\/\/.{0,1000}\.remote\.moe\// nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string13 = /infrastructure\/remotemoe\.service/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string14 = /systemctl\srestart\sremotemoe/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string15 = /systemctl\sstart\sremotemoe/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string16 = /systemctl\sstatus\sremotemoe/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string17 = /systemctl\sstop\sremotemoe/ nocase ascii wide
        // Description: remotemoe is a software daemon for exposing ad-hoc services to the internet without having to deal with the regular network stuff such as configuring VPNs - changing firewalls - or adding port forwards
        // Reference: https://github.com/fasmide/remotemoe
        $string18 = /systemctl\s\-\-user\sstart\sremotemoe\.service/ nocase ascii wide

    condition:
        any of them
}
