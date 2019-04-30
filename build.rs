use ctest::TestGenerator;
use pkg_config::{Config as PkgConfig, Library, Error};

fn main() {
    TestGenerator::new()
        .header("sodium.h")
        .generate("src/ffi/sodium.rs", "sodium_ctest.rs");

    if link("libsodium", "1.0.8").is_none() {
        // if pkg-config is disabled or failed to run, try and link
        // naïvely
        println!("cargo:rustc-link-lib=dylib=sodium");
    };
}

fn link(name: &str, version: &str) -> Option<Library> {
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
        Ok(lib)                       => return Some(lib),
    };

    None
}
