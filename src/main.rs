#![deny(warnings)]
#![deny(missing_docs)]
//! Command line tool for modifying hosts file on Linux/UNIX to change static hostname-IP mappings.
//!
//! Intended to be run with the suid bit set, so unprivileged users may update the hosts file. This
//! allow easy integration for jobs like updating entries after launching a docker container or
//! locally testing virtual hosts vor web projects without any requirement for privilege escalation.
//!
//! ## Engineered for Safety
//!
//! The tool has been engineered for safety and features a configurable list of hostnames for which
//! entries may be modified. If this configuration is not editable without privileges, no other
//! modifications are possible.
//!
//! Also, some key entries that might affect correct function of software like `localhost` are
//! checked before writing the new configuration.
//!
//! The new configuration is written to the file system under a different name next to the original
//! file and only moved into place as the last step. This makes the change atomic (according to
//! POSIX semantics) and any error occurring earlier leaves the existing configuration intact. After
//! an unsuccessful run, if the new placeholder file is already present, manual intervention will
//! be necessary.

#[macro_use]
extern crate structopt;
// #[macro_use]
extern crate nom;

mod config;
mod opts;
mod parse;

use crate::config::RESERVED_HOSTNAME;
use crate::config::{HostsmodConfig, DONT_TOUCH};
use crate::opts::Action;
use crate::parse::{try_parse_hosts, HostsPart, HostsPartFamily};
use std::borrow::Cow;
use std::cmp::min;
use std::fs::{rename, File, OpenOptions};
use std::io::{stdout, BufReader, Read, Write};
use std::net::IpAddr;
use structopt::StructOpt;

const PATH_HOSTSFILE: &str = "/etc/hosts";
const PATH_HOSTSFILE_NEW: &str = "/etc/hosts.new";

const PATH_CONFIG: &str = "/etc/hostsmod.yaml";

fn main() {
    let hostname_os_string = hostname::get().expect("unable to determine system hostname");
    let hostname = hostname_os_string
        .to_str()
        .expect("system hostname is not a valid UTF-8 string");
    let mut opts: opts::HostsArgs = {
        let app: structopt::clap::App = opts::HostsArgs::clap();
        let str_about = format!(
            r##"Tool for mopdifying system wide hosts file to simulate arbitrary DNS A and AAAA records.
            
Expects a hosts file at {:?} and a configuration in YAML format at {:?}. This
program is intended to be run by non-priviledged users with the help of setuid. It therefore has
some safety features.

Any modifications will not be persisted until the end of program execution. In the event of any
error, the original hosts file will not be modified. 
            
The configuration defines a whitelist of hostnames that can be modified. This program will refuse
to modify any hostname not present in that list. It will also ensure that certain hostnames are
never modified:
- {:?}
- {:?}
- {:?}
- {:?}
- {:?}
- {:?} <- current hostname

The only exception is if the config variable `enable_dangerous_operations` is set to true. Then even
these reserved hostnames can be modified."##,
            PATH_HOSTSFILE,
            PATH_CONFIG,
            config::RESERVED_LOCALHOST,
            config::RESERVED_IP6_LOCALHOST,
            config::RESERVED_IP6_LOOPBACK,
            config::RESERVED_IP6_ALLNODES,
            config::RESERVED_IP6_ALLROUTERS,
            hostname
        );
        let app = app
            // .before_help("PRE!!!")
            // .after_help("POST!!!")
            .about(str_about.as_ref());
        opts::HostsArgs::from_clap(&app.get_matches())
    };

    if opts.generate_sample_config {
        let mut out = stdout();
        let mut sample = HostsmodConfig::default();
        sample.whitelist.insert("somerandomhost.with.tld".into());
        serde_yaml::to_writer(&mut out, &sample).expect("unable to write default config to stdout");
        return;
    }

    let euid = users::get_effective_uid();
    // dbg!(uid);
    if euid != 0 {
        eprintln!("not effectively root, forced dry-run mode");
        opts.dry_run = true;
    }
    // dbg!(opts);

    // open file
    let mut file_hosts_orig = OpenOptions::new()
        .read(true)
        // .write(!opts.dry_run)
        .write(false)
        .truncate(false)
        .create(false)
        .open(PATH_HOSTSFILE)
        .expect("unable to open hosts");

    // let opt_file_hosts_new = if opts.dry_run {
    //     None
    // } else {
    //     Some(
    //         OpenOptions::new()
    //             .write(true)
    //             .create_new(true)
    //             .open(PATH_HOSTSFILE_NEW)
    //             .expect("unable to open new hosts file for writing! Stale file from previous run?"),
    //     )
    // };

    let mut str_content = String::with_capacity(1024 * 8);

    let len_content = file_hosts_orig
        .read_to_string(&mut str_content)
        .expect("unable to read hosts file as UTF-8 string");

    let mut hosts_parts =
        try_parse_hosts(&str_content).expect("unable to parse contents of hosts file");
    trim_hosts_parts(&mut hosts_parts);

    let hosts_parts_orig = hosts_parts.clone();

    // eprintln!("PRE-actions: {:#?}", &hosts_parts);

    let cfg: HostsmodConfig = {
        // TODO: check config file ownership & access rights
        let file_cfg = BufReader::new(File::open(PATH_CONFIG).expect("unable to open config file"));
        serde_yaml::from_reader(file_cfg).expect("unable to parse configuration")
    };

    if opts.dry_run || opts.verbose {
        if opts.verbose {
            eprintln!("config: {:#?}", cfg);
        }
        println!("original contents:\n>>>\n{}<<<", str_content);
    }

    let mut found_pre = vec![false; DONT_TOUCH.len()];

    if !cfg.enable_dangerous_operations {
        for (dt, found) in DONT_TOUCH.iter().zip(found_pre.iter_mut()) {
            let dt_host = if dt.hostname == RESERVED_HOSTNAME {
                Cow::Borrowed(hostname)
            } else {
                Cow::Borrowed(dt.hostname.as_ref())
            };
            for part in &hosts_parts {
                if part.matches_hostname(&dt_host) && part.matches_ip(&dt.ip) {
                    *found = true;
                }
            }
        }
    }
    let found_pre = found_pre;

    // execute actions
    perform_actions(&mut opts, &mut hosts_parts, &cfg).expect("unable to modify hosts file");

    if !opts.dry_run && hosts_parts == hosts_parts_orig {
        if opts.verbose {
            println!("no changes, not modifying hosts file");
        }
        return;
    }

    // remove redundant Empty elements
    trim_hosts_parts(&mut hosts_parts);
    {
        let mut remove = false;
        hosts_parts.retain(|item| match (item.is_empty(), remove) {
            (true, true) => false,
            (true, false) => {
                remove = true;
                true
            }
            (false, _) => {
                remove = false;
                true
            }
        });
    }

    // eprintln!("POST-actions: {:#?}", &hosts_parts);

    // compare against DONT_TOUCH
    let buf_generate = generate_hosts_file(len_content, &hosts_parts);
    // eprintln!(">\n{}<", &buf_generate);

    // safety checks
    if !cfg.enable_dangerous_operations {
        let mut found_post = vec![false; DONT_TOUCH.len()];
        for (dt, found) in DONT_TOUCH.iter().zip(found_post.iter_mut()) {
            let dt_host = if dt.hostname == RESERVED_HOSTNAME {
                Cow::Borrowed(hostname)
            } else {
                Cow::Borrowed(dt.hostname.as_ref())
            };
            for part in &hosts_parts {
                match (part.matches_hostname(&dt_host), part.matches_ip(&dt.ip)) {
                    (true, true) => {
                        *found = true;
                    }
                    (true, false) => {
                        if DONT_TOUCH
                            .iter()
                            .find(|dt_lookup| {
                                // eprint!("conflict: {:?} == {:?} ", part, dt_lookup);
                                let res = part.matches_hostname(&dt_lookup.hostname)
                                    && part.matches_ip(&dt_lookup.ip);
                                // eprintln!("{}", res);
                                res
                            })
                            .is_none()
                        {
                            panic!(
                                "untouchable entry {:?} {:?} was changed! {:?}",
                                dt.ip, dt_host, part
                            );
                        }
                        // *found = true;
                    }
                    (false, _) => {}
                }
            }
        }
        if found_post != found_pre {
            dbg!(&found_pre);
            dbg!(&found_post);
            for (i, (pre, post)) in found_pre.iter().zip(found_post.iter()).enumerate() {
                if pre != post {
                    eprintln!("Difference: {:?}", DONT_TOUCH[i])
                }
            }
            panic!("found_post != found_pre");
        }
    }

    if opts.dry_run || opts.verbose {
        println!("generated:\n>>>\n{}<<<", &buf_generate);
    }
    if opts.dry_run {
        println!("DRY-RUN DRY-RUN DRY-RUN DRY-RUN DRY-RUN DRY-RUN DRY-RUN DRY-RUN DRY-RUN DRY-RUN DRY-RUN DRY-RUN");
        println!("hosts file not modified");
        return;
    }

    let mut file_hosts_new = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(PATH_HOSTSFILE_NEW)
        .expect("unable to open new hosts file for writing! Stale file from previous run?");

    file_hosts_new
        .write_all(buf_generate.as_bytes())
        .expect("unable to write generated hosts file");
    file_hosts_new
        .set_len(buf_generate.as_bytes().len() as u64)
        .expect("unable to truncate hosts file to right len");
    file_hosts_new.flush().expect("unable to flush hosts file");
    // close file handles
    drop(file_hosts_new);
    drop(file_hosts_orig);
    rename(PATH_HOSTSFILE_NEW, PATH_HOSTSFILE).expect("unable to move new hosts file into place!");
}

fn trim_hosts_parts(hosts_parts: &mut Vec<HostsPart>) {
    let trim = hosts_parts
        .iter()
        .rev()
        .take_while(|part| part.is_empty())
        .count();
    hosts_parts.truncate(hosts_parts.len() - trim);
}

fn perform_actions(
    opts: &mut opts::HostsArgs,
    hosts: &mut Vec<HostsPart>,
    config: &HostsmodConfig,
) -> Result<(), String> {
    'loop_actions: for action in &opts.actions {
        match action {
            Action::Define(ip, host) => {
                if !config.whitelist.contains(host) {
                    return Err(format!("HOST {:?} not whitelisted!", host));
                }
                // eprintln!("defining additionally...: {:?} += {:?}", ip, host);
                let mut opt_insert = Some(hosts.len());
                let mut host_found_v4 = false;
                let mut host_found_v6 = false;
                for (i, part) in hosts
                    .iter_mut()
                    .enumerate()
                    .filter(|(_i, p)| p.matches_ip(ip) || p.matches_hostname(host))
                {
                    // eprintln!("matching entry: {:?}", part);
                    let matches_hostname = part.matches_hostname(host);
                    if part.matches_ip(ip) && matches_hostname {
                        // eprintln!("already defined, NOP");
                        //opt_insert = None;
                        continue 'loop_actions;
                    }
                    if matches_hostname {
                        match part.get_family() {
                            Some(HostsPartFamily::IPv4) => {
                                if host_found_v4 || ip.is_ipv4() {
                                    return Err(format!(
                                        "duplicate entry for host {:?} {:?}",
                                        host,
                                        HostsPartFamily::IPv4
                                    ));
                                }
                                host_found_v4 = true;
                            }
                            Some(HostsPartFamily::IPv6) => {
                                if host_found_v6 || ip.is_ipv6() {
                                    return Err(format!(
                                        "duplicate entry for host {:?} {:?}",
                                        host,
                                        HostsPartFamily::IPv6
                                    ));
                                }
                                host_found_v6 = true;
                            }
                            None => {}
                        };
                    }
                    if opt_insert.is_some() {
                        opt_insert = Some(i + 1);
                    }
                }

                if let Some(insert) = opt_insert {
                    let insert = min(insert, hosts.len());
                    hosts.insert(
                        insert,
                        HostsPart::Entry(ip.clone(), vec![Cow::Owned(host.clone())], None),
                    );
                }
            }
            Action::DefineExclusive(ip, host) => {
                if !config.whitelist.contains(host) {
                    return Err(format!("HOST {:?} not whitelisted!", host));
                }
                // eprintln!("defining exclusively...: {:?} += {:?}", ip, host);
                let mut vec_remove = vec![];
                for (i, _part) in hosts
                    .iter()
                    .enumerate()
                    .filter(|(_i, p)| p.matches_hostname(host))
                {
                    // eprintln!("matching entry: {:?}", part);
                    // if part.matches_ip(ip) && part.matches_hostname(host) {
                    //     eprintln!("already defined, NOP");
                    //     return;
                    // }
                    // insert = i + 1;
                    vec_remove.push(i);
                }
                for remove in vec_remove.iter().rev() {
                    hosts.remove(*remove);
                }
                let insert = vec_remove.into_iter().min().unwrap_or(hosts.len());
                hosts.insert(
                    insert,
                    HostsPart::Entry(ip.clone(), vec![Cow::Owned(host.clone())], None),
                );
            }
            Action::Remove(host) => {
                if !config.whitelist.contains(host) {
                    return Err(format!("HOST {:?} not whitelisted!", host));
                }
                let mut vec_remove = vec![];
                let mut vec_insert = vec![];
                let mut offset_remove = 0;
                for (i, part) in hosts
                    .iter()
                    .enumerate()
                    .filter(|(_i, p)| p.matches_hostname(host))
                {
                    match part {
                        HostsPart::Entry(ip, hosts, opt_comment) => {
                            // eprintln!("matching entry: {:?}", (&ip, &hosts, &opt_comment));
                            if hosts.len() > 1 {
                                let mut hosts_filtered = hosts.clone();
                                hosts_filtered.retain(|ent| ent != host);
                                vec_insert.push((
                                    i,
                                    HostsPart::Entry(
                                        ip.clone(),
                                        hosts_filtered,
                                        opt_comment.clone(),
                                    ),
                                ));
                                offset_remove += 1;
                            }
                            vec_remove.push(offset_remove + i);
                            // for h in hosts {
                            //     if h == host {
                            //     }
                            // }
                        }
                        _ => {}
                    }
                }
                // dbg!(&vec_insert);
                for (idx, part) in vec_insert {
                    hosts.insert(idx, part);
                }
                // dbg!(&vec_remove);
                // unimplemented!();
                for remove in vec_remove.iter().rev() {
                    hosts.remove(*remove);
                }
            }
        }
    }
    Ok(())
}

fn generate_hosts_file(len_content: usize, parsed: &Vec<HostsPart>) -> String {
    let mut buf_generate = String::with_capacity(len_content);

    // eprintln!("rendering: {:?}", parsed);

    fn render_entry<'a>(
        buf_generate: &mut String,
        ip: &IpAddr,
        hosts: &Vec<Cow<'a, str>>,
        opt_comment: &Option<Cow<'a, str>>,
    ) {
        use std::fmt::Write;

        write!(buf_generate, "{:20}\t", ip).expect("unable to format entry IP address");
        let max = hosts.iter().count() - 1;
        for (i, host) in hosts.iter().enumerate() {
            write!(buf_generate, "{}{}", host, if i < max { " " } else { "" })
                .expect("unable to format entry hostname");
        }
        if let Some(comment) = opt_comment {
            buf_generate.push_str(" #");
            buf_generate.push_str(comment);
        }
    }

    for part in parsed {
        // eprintln!("rendering: {:?}", part);
        match part {
            HostsPart::Empty(empty) => {
                buf_generate.push_str(empty);
            }
            HostsPart::Comment(comment) => {
                buf_generate.push_str("#");
                buf_generate.push_str(comment);
            }
            HostsPart::CommentedEntry(ip, hosts, opt_comment) => {
                buf_generate.push_str("# ");
                render_entry(&mut buf_generate, ip, hosts, opt_comment)
            }
            HostsPart::Entry(ip, hosts, opt_comment) => {
                render_entry(&mut buf_generate, ip, hosts, opt_comment)
            }
        }
        buf_generate.push_str("\n");
    }
    // buf_generate.pop();
    buf_generate
}
