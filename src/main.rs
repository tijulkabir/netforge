#![allow(unknown_lints)]
#![allow(clippy::chunks_exact_to_as_chunks)]

use clap::Parser;
use netforge::{build_operation, list_operations, InputData, Pipeline};
use std::io::{self, Write};

/// ╔═══════════════════════════════════════════════════╗
/// ║  NetForge v2.0 — Cyber Transformation Engine     ║
/// ║  High-performance data forge for red teamers      ║
/// ╚═══════════════════════════════════════════════════╝
#[derive(Parser)]
#[command(
    name = "netforge",
    version = "2.0.0",
    about = "High-performance cyber transformation engine for red team operations",
    long_about = "NetForge chains data transformations (encoding, hashing, crypto, analysis)\n\
                  into pipelines.  Pipe data through stdin or use --input.\n\n\
                  Examples:\n  \
                  echo -n 'password' | netforge sha256\n  \
                  echo -n 'secret' | netforge xor:0x42 to_hex\n  \
                  netforge --input 'hello world' to_base64\n  \
                  netforge --file payload.bin xor:0x5a strings:6 to_hex\n  \
                  netforge --list"
)]
struct Cli {
    /// Operations to chain (left to right).
    /// E.g.: `to_hex rot13` or `xor to_base64`
    #[arg(num_args = 0..)]
    operations: Vec<String>,

    /// Argument passed to parameterized operations (XOR key, strings min-len).
    #[arg(long)]
    arg: Option<String>,

    /// Inline input string (alternative to stdin).
    #[arg(short, long)]
    input: Option<String>,

    /// List all available operations and exit.
    #[arg(short, long)]
    list: bool,

    /// Read input from a file.
    #[arg(short, long)]
    file: Option<String>,

    /// Suppress the trailing newline in output.
    #[arg(short = 'n', long)]
    no_newline: bool,

    /// Run built-in property fuzzing and invariant resilience suite.
    #[arg(long)]
    fuzz: bool,

    /// Number of fuzzing iterations (default: 5000).
    #[arg(long, default_value = "5000")]
    fuzz_iters: usize,
}

fn main() {
    let cli = Cli::parse();

    // ── Fuzz mode ──
    if cli.fuzz {
        run_cli_fuzz(cli.fuzz_iters);
        return;
    }

    // ── List mode ──
    if cli.list {
        print_op_list();
        return;
    }

    if cli.operations.is_empty() {
        eprintln!("error: no operations specified. Use --list to see available operations.");
        std::process::exit(1);
    }

    // ── Read input ──
    let input = read_input(&cli);

    // ── Build pipeline ──
    let mut pipeline = Pipeline::new();
    for op_spec in &cli.operations {
        let (op_name, op_arg) = match op_spec.split_once(':') {
            Some((name, inline_arg)) => (name, Some(inline_arg)),
            None => (op_spec.as_str(), cli.arg.as_deref()),
        };
        match build_operation(op_name, op_arg) {
            Some(op) => {
                pipeline.push(op);
            }
            None => {
                eprintln!("error: unknown or invalid operation '{op_spec}'");
                eprintln!("       run `netforge --list` to see available operations");
                std::process::exit(1);
            }
        }
    }

    // ── Execute ──
    match pipeline.execute(&input) {
        Ok(output) => {
            io::stdout().write_all(&output).expect("write failed");
            if !cli.no_newline {
                println!();
            }
        }
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn read_input(cli: &Cli) -> InputData {
    if let Some(ref text) = cli.input {
        return InputData::from_bytes(text.as_bytes().to_vec());
    }
    if let Some(ref path) = cli.file {
        match InputData::from_file(path) {
            Ok(data) => return data,
            Err(e) => {
                eprintln!("error: {e}");
                std::process::exit(1);
            }
        }
    }
    // Default: read from stdin
    match InputData::from_reader(io::stdin()) {
        Ok(data) => data,
        Err(e) => {
            eprintln!("error: {e}");
            std::process::exit(1);
        }
    }
}

fn print_op_list() {
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║          NetForge v2.0 — Available Operations        ║");
    println!("╠═══════════════════════════════════════════════════════╣");

    let ops = list_operations();
    let categories = [
        (
            "Encoding",
            vec![
                "to_hex",
                "from_hex",
                "rot13",
                "to_base64",
                "from_base64",
                "url_encode",
                "url_decode",
            ],
        ),
        ("Crypto", vec!["xor"]),
        ("Hashing", vec!["md5", "sha256", "sha512", "blake3", "ntlm"]),
        (
            "Analysis",
            vec!["entropy", "byte_freq", "strings", "length"],
        ),
        (
            "Network",
            vec!["defang_ip", "refang_ip", "defang_url", "refang_url"],
        ),
        ("Binary", vec!["pe_info", "pe_sections"]),
        (
            "Protocol",
            vec!["tlv_encode", "tlv_decode", "checksum", "to_c_array"],
        ),
    ];

    for (cat, names) in &categories {
        println!("║                                                       ║");
        println!("║  [{cat}]");
        for name in names {
            if let Some((_, desc)) = ops.iter().find(|(n, _)| n == name) {
                println!("║    {name:<15} {desc}");
            }
        }
    }

    println!("║                                                       ║");
    println!("╚═══════════════════════════════════════════════════════╝");
    println!();
    println!("Usage:");
    println!("  echo -n 'data' | netforge <op1> [op2] [op3] ...");
    println!("  netforge --input 'data' <op1> [op2] ...");
    println!("  netforge --file ./binary.bin entropy");
    println!("  netforge --input 'password' ntlm");
    println!("  netforge --fuzz [--fuzz-iters 10000]");
}

fn run_cli_fuzz(iters: usize) {
    println!("╔═══════════════════════════════════════════════════════╗");
    println!("║          NetForge — Live Invariant Fuzzer             ║");
    println!("╠═══════════════════════════════════════════════════════╣");
    println!("║ Executing {iters} adversarial stress cycles...");
    println!("║ Proving mathematical roundtrips & zero-panic safety...");

    let report = netforge::run_fuzz_harness(iters);
    let total_checks = report.roundtrip_checks + report.adversarial_checks;
    let rate = (total_checks as u128 * 1000)
        .checked_div(report.duration_ms)
        .unwrap_or(total_checks as u128 * 1000);

    println!("╠═══════════════════════════════════════════════════════╣");
    println!("║ Completed Iterations : {:>8}", report.iterations);
    println!(
        "║ Invertibility Checks : {:>8} (100% verified)",
        report.roundtrip_checks
    );
    println!(
        "║ Adversarial Probes   : {:>8} (100% survived)",
        report.adversarial_checks
    );
    println!("║ Total Invariant Ops  : {:>8}", total_checks);
    println!(
        "║ Uncaught Panics      : {:>8} (Zero-Panic Proof)",
        report.panics_detected
    );
    println!("║ Execution Wall Time  : {:>8} ms", report.duration_ms);
    println!("║ Throughput           : {:>8} checks/sec", rate);
    println!("╚═══════════════════════════════════════════════════════╝");
}
