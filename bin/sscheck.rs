use std::{
    fs::File,
    io::{self, BufRead},
    path::{Path, PathBuf},
    process::ExitCode,
    str::FromStr,
};

use clap::{Arg, ArgAction, Command, ValueHint};
use shadowsocks_service::{decrypt, shadowsocks::ServerConfig};

fn main() -> ExitCode {
    let mut app = Command::new("shadowsocks")
        .version(shadowsocks_rust::VERSION)
        .about("A fast tunnel proxy that helps you bypass firewalls. (https://shadowsocks.org)");
    app = app.arg(
        Arg::new("INPUT_FILE")
            .short('f')
            .num_args(1)
            .action(ArgAction::Set)
            .value_parser(clap::value_parser!(PathBuf))
            .value_hint(ValueHint::FilePath)
            .help("Shadowsocks configuration file (https://shadowsocks.org/guide/configs.html)"),
    );

    let matches = app.get_matches();

    let path = matches.get_one::<PathBuf>("INPUT_FILE").unwrap();

    let lines = read_lines(path).unwrap();

    let mut error_count = 0;
    for line in lines {
        if let Ok(network) = line {
            let decrypt_network = match decrypt(&network) {
                Ok(s) => s,
                Err(err) => {
                    println!("{}: decrypt error {}", network, err);
                    error_count = error_count + 1;
                    continue;
                }
            };

            match ServerConfig::from_str(&decrypt_network.as_str()) {
                Ok(_s) => {}
                Err(err) => {
                    println!("{}: {}: {:?}", network, decrypt_network, err);
                    error_count = error_count + 1;
                    continue;
                }
            };
        }
    }

    if error_count > 0 {
        println!("total error: {}", error_count);
        ExitCode::FAILURE
    } else {
        println!("success");
        ExitCode::SUCCESS
    }
}

fn read_lines<P>(filename: P) -> io::Result<io::Lines<io::BufReader<File>>>
where
    P: AsRef<Path>,
{
    let file = File::open(filename)?;
    Ok(io::BufReader::new(file).lines())
}
