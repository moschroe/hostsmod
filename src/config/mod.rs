use serde::{Deserialize, Serialize};
use std::borrow::Cow;
use std::collections::BTreeSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

pub const RESERVED_HOSTNAME: &str = "%HOSTNAME%";
pub const RESERVED_LOCALHOST: &str = "localhost";
pub const RESERVED_IP6_LOCALHOST: &str = "ip6-localhost";
pub const RESERVED_IP6_LOOPBACK: &str = "ip6-loopback";
pub const RESERVED_IP6_ALLNODES: &str = "ip6-allnodes";
pub const RESERVED_IP6_ALLROUTERS: &str = "ip6-allrouters";

const IP4_LOCAL: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const IP4_LOCAL_ALT: Ipv4Addr = Ipv4Addr::new(127, 0, 1, 1);
const IP6_LOCAL: Ipv6Addr = Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1);
const IP6_ALL_NODES: Ipv6Addr = Ipv6Addr::new(65282, 0, 0, 0, 0, 0, 0, 1);
const IP6_ALL_ROUTERS: Ipv6Addr = Ipv6Addr::new(65282, 0, 0, 0, 0, 0, 0, 2);

#[allow(dead_code)]
pub const DONT_TOUCH: &[HostsEntry] = &[
    HostsEntry {
        ip: IpAddr::V4(IP4_LOCAL),
        hostname: Cow::Borrowed(RESERVED_LOCALHOST),
    },
    HostsEntry {
        ip: IpAddr::V4(IP4_LOCAL_ALT),
        hostname: Cow::Borrowed(RESERVED_HOSTNAME),
    },
    HostsEntry {
        ip: IpAddr::V6(IP6_LOCAL),
        hostname: Cow::Borrowed(RESERVED_LOCALHOST),
    },
    HostsEntry {
        ip: IpAddr::V6(IP6_LOCAL),
        hostname: Cow::Borrowed(RESERVED_IP6_LOCALHOST),
    },
    HostsEntry {
        ip: IpAddr::V6(IP6_LOCAL),
        hostname: Cow::Borrowed(RESERVED_IP6_LOOPBACK),
    },
    HostsEntry {
        ip: IpAddr::V6(IP6_ALL_NODES),
        hostname: Cow::Borrowed(RESERVED_IP6_ALLNODES),
    },
    HostsEntry {
        ip: IpAddr::V6(IP6_ALL_ROUTERS),
        hostname: Cow::Borrowed(RESERVED_IP6_ALLROUTERS),
    },
];

#[derive(Debug, Serialize, Deserialize)]
pub struct HostsEntry<'a> {
    pub ip: IpAddr,
    pub hostname: Cow<'a, str>,
}

#[derive(Default, Serialize, Deserialize)]
pub struct HostsmodConfig {
    pub whitelist: BTreeSet<String>,
    #[serde(skip_serializing)]
    #[serde(default = "safely_false")]
    pub enable_dangerous_operations: bool,
}

impl std::fmt::Debug for HostsmodConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        f.debug_struct("HostsmodConfig")
            .field("whitelist", &self.whitelist)
            .finish()
    }
}

fn safely_false() -> bool {
    false
}
