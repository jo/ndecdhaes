mod cli;
mod ndecdhaes;

use clap::Parser;
use std::io::Error;

use crate::cli::Args;
use crate::ndecdhaes::Ndecdhaes;

fn main() -> Result<(), Error> {
    let args = Args::parse();
    let ndecdhaes = Ndecdhaes::new(args);
    ndecdhaes.run()
}
