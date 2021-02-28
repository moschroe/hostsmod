use crate::parse::{comb_ipaddr, maybe_hostname_alias};
use nom::branch::alt;
use nom::bytes::complete::{tag, take_while1};
use nom::combinator::{eof, map};
use nom::sequence::{preceded, separated_pair, terminated};
use nom::IResult;
use std::net::IpAddr;

#[derive(Debug, Eq, PartialEq)]
pub enum Action {
    Remove(String),
    Define(IpAddr, String),
    DefineExclusive(IpAddr, String),
}

#[derive(Debug, StructOpt)]
#[structopt(settings = & [structopt::clap::AppSettings::ColoredHelp])]
pub struct HostsArgs {
    /// Will make no change and simply output what would have changed.
    #[structopt(short = "n", long = "dry-run")]
    pub dry_run: bool,
    /// Will output generated hosts file to stdout
    #[structopt(short = "v", long = "verbose")]
    pub verbose: bool,
    /// Will generate a sample configuration on stdout
    #[structopt(long = "sample-config")]
    pub generate_sample_config: bool,
    /// Actions are the modifications to hosts that should be made. Prefix with `--` to stop other
    /// argument parsing! There are three cases:
    ///
    /// -host    -> Remove hostname from file. If no IP mapping remains, entry will be removed.
    /// IP=host  -> Define an entry exclusively, IP mapping gets added or changed. Will remove
    ///             any other mapping with the same hostname!
    /// IP+=host -> Define an entry, IP mapping gets added. Will not change existing mapping
    ///             with same hostname.
    ///
    /// IP can be any IPv4 or IPv6 IP. It is only checked for valid format!
    ///
    /// Actions will be processed in the order provided. So to clear all other assignments for a
    /// hostname, define an entry exclusively with `=` and then add for example an IPv6 entry with
    /// `+=`.
    #[structopt(parse(try_from_str = try_parse_action),
    verbatim_doc_comment,
    help = "Defines intended modifications to hosts file. use `--help` for full description.",
    name="ACTIONS")]
    pub actions: Vec<Action>,
}

fn try_parse_action(str_action: &str) -> Result<Action, String> {
    comb_action(str_action)
        .map_err(|err| format!("unable to parse action {:?}: {}", str_action, err))
        .map(|(_, action)| action)
}

fn comb_action(input: &str) -> IResult<&str, Action> {
    alt((
        map(
            terminated(preceded(tag("-"), take_while1(maybe_hostname_alias)), eof),
            |host: &str| Action::Remove(host.to_string()),
        ),
        map(
            terminated(
                separated_pair(comb_ipaddr, tag("+="), take_while1(maybe_hostname_alias)),
                eof,
            ),
            |(ip, host)| Action::Define(ip, host.to_string()),
        ),
        map(
            terminated(
                separated_pair(comb_ipaddr, tag("="), take_while1(maybe_hostname_alias)),
                eof,
            ),
            |(ip, host)| Action::DefineExclusive(ip, host.to_string()),
        ),
    ))(input)
}

#[cfg(test)]
mod tests {
    use crate::opts::{comb_action, Action};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_parse_actions() {
        {
            let (remainder, parsed) = comb_action("-somehost").unwrap();
            assert_eq!("", remainder);
            assert_eq!(Action::Remove("somehost".into()), parsed);
        }
        {
            let (remainder, parsed) = comb_action("127.1.65.77+=somehost").unwrap();
            assert_eq!("", remainder);
            assert_eq!(
                Action::Define(IpAddr::V4(Ipv4Addr::new(127, 1, 65, 77)), "somehost".into()),
                parsed
            );
        }
        {
            let (remainder, parsed) = comb_action("2003::f+=somehost").unwrap();
            assert_eq!("", remainder);
            assert_eq!(
                Action::Define(
                    IpAddr::V6(Ipv6Addr::from_str("2003::f").unwrap()),
                    "somehost".into()
                ),
                parsed
            );
        }
        {
            let (remainder, parsed) = comb_action("::1=somehost").unwrap();
            assert_eq!("", remainder);
            assert_eq!(
                Action::DefineExclusive(
                    IpAddr::V6(Ipv6Addr::from_str("::1").unwrap()),
                    "somehost".into()
                ),
                parsed
            );
        }
    }
}
