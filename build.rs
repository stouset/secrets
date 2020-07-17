#[cfg(not(feature = "use-libsodium-sys"))]
use pkg_config::{Config as PkgConfig, Error};

use std::env;
use std::fmt;

#[derive(PartialEq, Eq)]
enum Profile {
    Debug,
    Coverage,
    Release,
}

impl Profile {
    fn infer() -> Self {
        let profile = match (
            env::var("COVERAGE").is_ok(),
            env::var("PROFILE").as_ref().map(String::as_str),
        ) {
            (true, _)              => Profile::Coverage,
            (false, Ok("release")) => Profile::Release,
            (false, Ok("debug"))   => Profile::Debug,

            // unknown profile
            (false, Ok(profile)) => {
                println!("cargo:warning=\"unknown profile {}, defaulting to debug\"", profile);
                Profile::Debug
            },

            // this should only happen if we typo'd an env key
            (false, Err(err)) => {
                panic!("build.rs failed to determine profile: {}", err);
            }
        };

        println!("cargo:rerun-if-env-changed=COVERAGE");
        println!("cargo:rerun-if-env-changed=PROFILE");
        println!("cargo:rustc-cfg=profile=\"{}\"", profile);

        profile
    }
}

impl fmt::Display for Profile {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Profile::Debug    => write!(f, "debug"),
            Profile::Coverage => write!(f, "coverage"),
            Profile::Release  => write!(f, "release"),
        }
    }
}

fn main() {
    let _profile = Profile::infer();

    // 1.0.8 was chosen (IIRC) because this is when the garbage byte
    // value was fixed at 0xdb
    if link("libsodium", "1.0.8").is_none() {
        // if pkg-config is disabled or failed to run, try and link
        // naïvely
        println!("cargo:rustc-link-lib=dylib=sodium");
    };
}

#[cfg(feature = "use-libsodium-sys")]
fn link(_name: &str, _version: &str) -> Option<()> {
    Some(())
}

#[cfg(not(feature = "use-libsodium-sys"))]
fn link(name: &str, version: &str) -> Option<()> {
    let library = PkgConfig::new()
        .env_metadata(true)
        .atleast_version(version)
        .probe(name);

    match library {
        Err(Error::Command { command, .. }) => {
            // The `pkg-config` invocation has extra quotes around it
            // (most egregiously around the command itself). This is
            // maybe overly pedantic but cleaning the extra quotes
            // produces noticeably better printed output.
            //
            // The algorithm is a bit dumb. We split on spaces and trim
            // quotes from both sides if and only if quotes are present
            // on both sides. This definitely fails in the generic case
            // (`command "--flag" "\"quoted args\""`) but in the
            // specific case of pkg-config, it's probably never going to
            // produce incorrect output in practice.
            let cmd = command.split(' ').map(|s| {
                match s.starts_with('"') && s.ends_with('"') {
                    true  => s.trim_matches('"'),
                    false => s
                }
            }).collect::<Vec<&str>>().join(" ");

            println!("cargo:warning=failed to run `{}`; is pkg-config in your PATH?", cmd);
            println!("cargo:warning=using default linker options");
        },
        Err(Error::EnvNoPkgConfig(_)) => (),
        Err(err)                      => panic!("failed to link against {}: {}", name, err),
        Ok(_)                         => return Some(()),
    };

    None
}
