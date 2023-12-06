rule IMDSpoof
{
    meta:
        description = "Detection patterns for the tool 'IMDSpoof' taken from the ThreatHunting-Keywords github project" 
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "IMDSpoof"
        rule_category = "offensive_tool_keyword"

    strings:
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string1 = /\/etc\/systemd\/system\/IMDS\.service/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string2 = /\/IMDSpoof\.git/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string3 = /grahamhelton\/IMDSpoof/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string4 = /IMDS\sService\sSpoofing\sEnabled/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string5 = /IMDSPoof\sHoney\sToken/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string6 = /IMDSpoof.{0,1000}IMDS\.go/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string7 = /IMDSpoof\-main/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string8 = /IQoJb3Jpz2cXpQRkpVX3Uf/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string9 = /systemctl\sdisable\sIMDS/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string10 = /systemctl\senable\sIMDS/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string11 = /systemctl\sstart\sIMDS/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string12 = /systemctl\sstatus\sIMDS/ nocase ascii wide
        // Description: IMDSPOOF is a cyber deception tool that spoofs the AWS IMDS service to return HoneyTokens that can be alerted on.
        // Reference: https://github.com/grahamhelton/IMDSpoof
        $string13 = /systemctl\sstop\sIMDS/ nocase ascii wide

    condition:
        any of them
}
