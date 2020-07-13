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
}
