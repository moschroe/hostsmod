use nom::branch::alt;
use nom::bytes::complete::{is_not, tag, take_while, take_while1};
use nom::combinator::{complete, eof, map, map_res, opt, peek};
use nom::multi::{separated_list0, separated_list1};
use nom::sequence::{preceded, terminated, tuple};
use nom::{AsChar, IResult};
use std::borrow::Cow;
use std::net::IpAddr;
use std::str::FromStr;

/// Part of a hosts file, representing all of the possible values.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum HostsPart<'a> {
    /// An entry as outlined in `man 5 hosts`. Starting with an IP address (v4 or v6), followed by
    /// at least one space or tab, then a hostname, alphanumeric+`.`+`-`. Optional host aliases may
    /// be present, set apart by at least one more space or tab each.
    ///
    /// A `#` character at any point will start a comment until the next line break.
    Entry(IpAddr, Vec<Cow<'a, str>>, Option<Cow<'a, str>>),
    /// An entry matching the `Entry` pattern, only commented out by a `#` character at the
    /// beginning of the line. This differentiation might be used to only disable entries while
    /// leaving the information still present in the file (eg. for human consumption).
    CommentedEntry(IpAddr, Vec<Cow<'a, str>>, Option<Cow<'a, str>>),
    /// A comment, consisting of a `#` character followed by arbitrary text until the next line
    /// break..
    Comment(Cow<'a, str>),
    /// An empty part of a hosts file will contain only whitespace (or an empty string for a single
    /// line break).
    Empty(Cow<'a, str>),
}

/// Small enum representing the address family of an IP address.
#[derive(Debug, Eq, PartialEq)]
pub enum HostsPartFamily {
    #[allow(missing_docs)]
    IPv4,
    #[allow(missing_docs)]
    IPv6,
}

impl<'a> HostsPart<'a> {
    /// Checks whether a hosts file part matches the provided IP address. Considers commented-out
    /// entries.
    pub fn matches_ip(&self, ip_needle: &IpAddr) -> bool {
        match self {
            HostsPart::Entry(ip, ..) | HostsPart::CommentedEntry(ip, ..) => ip == ip_needle,
            _ => false,
        }
    }

    /// Checks whether a hosts file part contains the provided hostname. Aliases are considered, as
    /// are commented-out entries.
    pub fn matches_hostname(&self, host_needle: &str) -> bool {
        match self {
            HostsPart::Entry(_, hosts, ..) | HostsPart::CommentedEntry(_, hosts, ..) => {
                hosts.iter().any(|host| host == host_needle)
            }
            _ => false,
        }
    }

    /// Checks whether a hosts file part is empty.
    pub fn is_empty(&self) -> bool {
        match self {
            HostsPart::Empty(..) => true,
            _ => false,
        }
    }

    /// Checks whether a hosts file part is a commented-out entry.
    #[allow(dead_code)]
    pub fn is_commented(&self) -> bool {
        match self {
            HostsPart::CommentedEntry(..) => true,
            _ => false,
        }
    }

    /// If a hosts file part contains an IP address, returns that addresses family (v4 or v6).
    /// Considers commented-out entries.
    pub fn get_family(&self) -> Option<HostsPartFamily> {
        match self {
            HostsPart::Entry(ip, ..) | HostsPart::CommentedEntry(ip, ..) => {
                if ip.is_ipv4() {
                    Some(HostsPartFamily::IPv4)
                } else if ip.is_ipv6() {
                    Some(HostsPartFamily::IPv6)
                } else {
                    unimplemented!("IpAddr is neither V4 nor V6, no idea what to do");
                }
            }
            _ => None,
        }
    }

    // pub fn add_hostname<'b: 'a>(&mut self, host_new: Cow<'b, str>) {
    //     match self {
    //         HostsPart::Entry(_, hosts, ..) | HostsPart::CommentedEntry(_, hosts, ..) => {
    //             if !hosts.contains(&host_new) {
    //                 hosts.push(host_new);
    //             }
    //         }
    //         _ => {}
    //     }
    // }
    //
    // pub fn remove_hostname<'b: 'a>(&mut self, host_new: Cow<'b, str>) {
    //     match self {
    //         HostsPart::Entry(_, hosts, ..) | HostsPart::CommentedEntry(_, hosts, ..) => {
    //             if !hosts.contains(&host_new) {
    //                 hosts.push(host_new);
    //             }
    //         }
    //         _ => {}
    //     }
    // }
}

fn maybe_ip_addr(byt: char) -> bool {
    // is_hex_digit(byt) || byt == b':' || byt == b'.'
    let res = byt.is_hex_digit() || byt == ':' || byt == '.';
    // eprintln!("maybe_ip_addr: {:?}= {:?}", byt, res);
    res
}

pub(crate) fn maybe_hostname_alias(byt: char) -> bool {
    // eprintln!("maybe_hostname_alias: {:?}", byt);
    // if byt == 't' {
    //     return false;
    // }
    byt.is_alphanumeric() || byt == '-' || byt == '_' || byt == '.'
}

fn is_space(byt: char) -> bool {
    // eprintln!("is_space: {:?}", byt);
    byt == ' ' || byt == '\t'
}

pub fn parse_hosts_file(input: &str) -> IResult<&str, Vec<HostsPart>> {
    // dbg!(input);
    complete(separated_list0(
        comb_linebreak,
        alt((
            map(
                comb_commented_entry,
                |(ip, hosts, opt_comment): (IpAddr, Vec<Cow<str>>, Option<&str>)| {
                    HostsPart::CommentedEntry(ip, hosts, opt_comment.map(Cow::Borrowed))
                },
            ),
            map(comb_comment, |comment| {
                HostsPart::Comment(Cow::Borrowed(comment))
            }),
            map(
                comb_entry,
                |(ip, hosts, opt_comment): (IpAddr, Vec<Cow<str>>, Option<&str>)| {
                    HostsPart::Entry(ip, hosts, opt_comment.map(Cow::Borrowed))
                },
            ),
            // map(is_not("\r\n"), |ws: &str| {
            //     HostsPart::Empty(Cow::Borrowed(ws))
            // }),
            map(
                terminated(take_while(is_space), peek(alt((comb_linebreak, eof)))),
                |anything| HostsPart::Empty(Cow::Borrowed(anything)),
            ),
        )),
    ))(input)
}

fn comb_entry<'a>(input: &'a str) -> IResult<&str, (IpAddr, Vec<Cow<'a, str>>, Option<&str>)> {
    tuple((
        terminated(comb_ipaddr, take_while1(is_space)),
        terminated(
            separated_list1(
                take_while1(is_space),
                map(take_while1(maybe_hostname_alias), |host| {
                    Cow::Borrowed(host)
                }),
            ),
            take_while(is_space),
        ),
        opt(comb_comment),
    ))(input)
}

fn comb_comment(input: &str) -> IResult<&str, &str> {
    preceded(preceded(take_while(is_space), tag("#")), is_not("\r\n"))(input)
}

fn comb_commented_entry<'a>(
    input: &'a str,
) -> IResult<&str, (IpAddr, Vec<Cow<'a, str>>, Option<&str>)> {
    preceded(
        preceded(
            take_while(is_space),
            terminated(tag("#"), take_while(is_space)),
        ),
        comb_entry,
    )(input)
}

fn comb_linebreak(input: &str) -> IResult<&str, &str> {
    alt((tag("\r\n"), tag("\n\r"), tag("\n")))(input)
}

/*
map_res(take_while1(maybe_ip_addr), |str_ip| {
                        IpAddr::from_str(str_ip)
                    })
*/
pub(crate) fn comb_ipaddr(input: &str) -> IResult<&str, IpAddr> {
    map_res(take_while1(maybe_ip_addr), |str_ip| {
        IpAddr::from_str(str_ip)
    })(input)
}

/// Parses hosts file and returns `Vec` of resulting parts.
#[allow(clippy::needless_lifetimes)]
pub fn try_parse_hosts<'a>(read: &'a str) -> Result<Vec<HostsPart<'a>>, String> {
    let (remainder, parsed) =
        parse_hosts_file(read).map_err(|err| format!("Error parsing hosts: {:?}", err))?;
    if remainder.len() > 0 {
        return Err(format!(
            "unable to parse hosts file, remainder: {:?}",
            remainder
        ));
    }
    Ok(parsed)
}

#[cfg(test)]
mod tests {
    use crate::parse::{parse_hosts_file, HostsPart};
    use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
    use std::str::FromStr;

    #[test]
    fn test_parse_hosts_realistic() {
        let data = r##"127.0.0.1	localhost
127.0.1.1	thismachine
::1	localhost ip6-localhost ip6-loopback
ff02::1 ip6-allnodes
ff02::2 ip6-allrouters
# comment

198.51.100.11	www.employer.example
10.0.20.4	intranet.someclub.example #  with trailing comment!
# 10.4.79.99	deactivated.host deactivated.host.1
    
"##;

        let parsed_canon = vec![
            HostsPart::Entry(
                IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
                vec!["localhost".into()],
                None,
            ),
            HostsPart::Entry(
                IpAddr::V4(Ipv4Addr::new(127, 0, 1, 1)),
                vec!["thismachine".into()],
                None,
            ),
            HostsPart::Entry(
                IpAddr::V6(Ipv6Addr::from(1)),
                vec![
                    "localhost".into(),
                    "ip6-localhost".into(),
                    "ip6-loopback".into(),
                ],
                None,
            ),
            HostsPart::Entry(
                IpAddr::V6(Ipv6Addr::from_str("ff02::1").unwrap()),
                vec!["ip6-allnodes".into()],
                None,
            ),
            HostsPart::Entry(
                IpAddr::V6(Ipv6Addr::from_str("ff02::2").unwrap()),
                vec!["ip6-allrouters".into()],
                None,
            ),
            HostsPart::Comment(" comment".into()),
            HostsPart::Empty("".into()),
            HostsPart::Entry(
                IpAddr::V4(Ipv4Addr::new(198, 51, 100, 11)),
                vec!["www.employer.example".into()],
                None,
            ),
            HostsPart::Entry(
                IpAddr::V4(Ipv4Addr::new(10, 0, 20, 4)),
                vec!["intranet.someclub.example".into()],
                Some("  with trailing comment!".into()),
            ),
            HostsPart::CommentedEntry(
                IpAddr::V4(Ipv4Addr::new(10, 4, 79, 99)),
                vec!["deactivated.host".into(), "deactivated.host.1".into()],
                None,
            ),
            HostsPart::Empty("    ".into()),
            HostsPart::Empty("".into()),
        ];

        let parsed = parse_hosts_file(data).expect("unable to parse sample hosts file");
        assert!(parsed.0.is_empty(), "unparsed input!: {:#?}", parsed);
        assert_eq!(
            parsed_canon.len(),
            parsed.1.len(),
            "length of canonical test data differs from parsed result: expected: {}, found: {}",
            parsed_canon.len(),
            parsed.1.len()
        );
        for (idx, (canon, parsed)) in parsed_canon.iter().zip(parsed.1.iter()).enumerate() {
            if canon != parsed {
                panic!(
                    "comparison failed at index {}, expected: {:?}, found: {:?}",
                    idx, canon, parsed
                );
            }
        }
    }
}
