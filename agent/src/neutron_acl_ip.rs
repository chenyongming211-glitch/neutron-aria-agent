use aria_api::proto_from_string;
use std::net::{Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum IpFamily {
    Ipv4,
    Ipv6,
}

impl IpFamily {
    pub(crate) fn as_u8(self) -> u8 {
        match self {
            Self::Ipv4 => 4,
            Self::Ipv6 => 6,
        }
    }

    pub(crate) fn label(self) -> &'static str {
        match self {
            Self::Ipv4 => "ipv4",
            Self::Ipv6 => "ipv6",
        }
    }

    pub(crate) fn parse_ethertype(value: Option<&str>) -> Result<Self, String> {
        match value
            .unwrap_or("IPv4")
            .trim()
            .to_ascii_lowercase()
            .as_str()
        {
            "ipv4" => Ok(Self::Ipv4),
            "ipv6" => Ok(Self::Ipv6),
            other => Err(format!("unsupported ACL ethertype {}", other)),
        }
    }
}

#[derive(Clone, Copy, Debug, Eq, Ord, PartialEq, PartialOrd)]
pub(crate) enum AclCidr {
    V4 { network: u32, prefix: u8 },
    V6 { network: u128, prefix: u8 },
}

impl AclCidr {
    pub(crate) fn parse(value: &str, family: IpFamily) -> Result<Self, String> {
        let text = value.trim();
        if text.contains('%') {
            return Err(format!("invalid {} CIDR {}", family.label(), value));
        }
        let (address, prefix) = text
            .split_once('/')
            .ok_or_else(|| format!("invalid {} CIDR {}", family.label(), value))?;
        if prefix.contains('/')
            || prefix.is_empty()
            || !prefix.bytes().all(|byte| byte.is_ascii_digit())
        {
            return Err(format!("invalid {} CIDR {}", family.label(), value));
        }
        let prefix = prefix
            .parse::<u8>()
            .map_err(|_| format!("invalid {} CIDR {}", family.label(), value))?;

        match family {
            IpFamily::Ipv4 => {
                if prefix > 32 {
                    return Err(format!("invalid IPv4 CIDR {}", value));
                }
                let address = address
                    .parse::<Ipv4Addr>()
                    .map_err(|_| format!("invalid IPv4 CIDR {}", value))?;
                let address = u32::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u32::MAX << (32 - prefix)
                };
                Ok(Self::V4 {
                    network: address & mask,
                    prefix,
                })
            }
            IpFamily::Ipv6 => {
                if prefix > 128 {
                    return Err(format!("invalid IPv6 CIDR {}", value));
                }
                let address = address
                    .parse::<Ipv6Addr>()
                    .map_err(|_| format!("invalid IPv6 CIDR {}", value))?;
                if address.to_ipv4_mapped().is_some() {
                    return Err(format!("IPv4-mapped IPv6 CIDR {} is unsupported", value));
                }
                let address = u128::from(address);
                let mask = if prefix == 0 {
                    0
                } else {
                    u128::MAX << (128 - prefix)
                };
                Ok(Self::V6 {
                    network: address & mask,
                    prefix,
                })
            }
        }
    }

    pub(crate) fn family(self) -> IpFamily {
        match self {
            Self::V4 { .. } => IpFamily::Ipv4,
            Self::V6 { .. } => IpFamily::Ipv6,
        }
    }

    pub(crate) fn canonical(self) -> String {
        match self {
            Self::V4 { network, prefix } => {
                format!("{}/{}", Ipv4Addr::from(network), prefix)
            }
            Self::V6 { network, prefix } => {
                format!("{}/{}", Ipv6Addr::from(network), prefix)
            }
        }
    }

    pub(crate) fn interval(self) -> (u128, u128) {
        match self {
            Self::V4 { network, prefix } => {
                let host_mask = if prefix == 32 {
                    0
                } else {
                    u32::MAX >> prefix
                };
                (u128::from(network), u128::from(network | host_mask))
            }
            Self::V6 { network, prefix } => {
                let host_mask = if prefix == 128 {
                    0
                } else {
                    u128::MAX >> prefix
                };
                (network, network | host_mask)
            }
        }
    }
}

pub(crate) fn acl_protocol(value: Option<&str>, family: IpFamily) -> Result<u8, String> {
    let token = value.unwrap_or("any").trim().to_ascii_lowercase();
    match (family, token.as_str()) {
        (IpFamily::Ipv4, "icmp") => Ok(1),
        (IpFamily::Ipv6, "icmp" | "icmpv6" | "ipv6-icmp") => Ok(58),
        (IpFamily::Ipv4, "icmpv6" | "ipv6-icmp" | "58") => {
            Err("ICMPv6 protocol is invalid for IPv4 ACL rules".to_string())
        }
        (IpFamily::Ipv6, "1") => {
            Err("ICMPv4 protocol is invalid for IPv6 ACL rules".to_string())
        }
        _ => {
            let protocol = proto_from_string(&token)?;
            if family == IpFamily::Ipv4 && protocol == 58 {
                return Err("ICMPv6 protocol is invalid for IPv4 ACL rules".to_string());
            }
            if family == IpFamily::Ipv6 && protocol == 1 {
                return Err("ICMPv4 protocol is invalid for IPv6 ACL rules".to_string());
            }
            Ok(protocol)
        }
    }
}
