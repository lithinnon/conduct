mod askpass;
mod notify;
mod proc;

use askpass::AskpassOptions;
use clap::{Args, Parser, Subcommand};
use proc::ElevationContext;
use std::process::ExitCode;

#[derive(Parser, Debug)]
#[command(
    name = "conduct",
    about = "Context-aware, notification-driven askpass and privilege orchestrator",
    version
)]
struct Cli {
    #[command(subcommand)]
    command: Option<Commands>,

    /// Prompt text (used in default askpass mode when invoked by sudo/ssh)
    #[arg(value_name = "PROMPT")]
    prompt: Option<String>,

    /// Inspect a specific PID instead of parent process
    #[arg(short, long, global = true)]
    pid: Option<u32>,

    /// Disable desktop notification
    #[arg(long, global = true)]
    no_notify: bool,

    /// Disable terminal banner
    #[arg(long, global = true)]
    no_banner: bool,
}

#[derive(Subcommand, Debug)]
enum Commands {
    /// Execute askpass credential prompt (default)
    Askpass(AskpassArgs),

    /// Send a desktop notification without prompting for credentials
    Notify(NotifyArgs),

    /// Inspect and display process context for a PID
    Inspect(InspectArgs),
}

#[derive(Args, Debug)]
struct AskpassArgs {
    /// Prompt text provided by caller
    #[arg(value_name = "PROMPT")]
    prompt: Option<String>,
}

#[derive(Args, Debug)]
struct NotifyArgs {
    /// Custom summary text for notification
    #[arg(short, long, default_value = "Privilege Elevation Requested")]
    summary: String,

    /// Custom notification body (overrides automatic context)
    #[arg(short, long)]
    body: Option<String>,
}

#[derive(Args, Debug)]
struct InspectArgs {}

fn main() -> ExitCode {
    let cli = Cli::parse();

    match cli.command {
        Some(Commands::Askpass(args)) => {
            let prompt = args.prompt.or(cli.prompt);
            let opts = AskpassOptions {
                prompt,
                target_pid: cli.pid,
                send_notification: !cli.no_notify,
                show_banner: !cli.no_banner,
            };
            if let Err(e) = askpass::run_askpass(opts) {
                eprintln!("conduct: askpass error: {}", e);
                return ExitCode::FAILURE;
            }
        }
        Some(Commands::Notify(args)) => {
            let context = match cli.pid {
                Some(pid) => ElevationContext::inspect_pid(pid),
                None => ElevationContext::inspect_current_caller(),
            };

            let body = match args.body {
                Some(custom_body) => custom_body,
                None => match &context {
                    Ok(ctx) => ctx.format_notification_body(),
                    Err(e) => format!("Caller context unavailable: {}", e),
                },
            };

            match notify::send_notification(
                "conduct",
                &args.summary,
                &body,
                "dialog-password",
                notify::NotificationUrgency::Critical,
                15_000,
            ) {
                Ok(id) => {
                    println!("Notification dispatched (ID: {})", id);
                }
                Err(e) => {
                    eprintln!("conduct: notification error: {}", e);
                    return ExitCode::FAILURE;
                }
            }
        }
        Some(Commands::Inspect(_args)) => {
            let context = match cli.pid {
                Some(pid) => ElevationContext::inspect_pid(pid),
                None => ElevationContext::inspect_current_caller(),
            };

            match context {
                Ok(ctx) => {
                    println!("{}", ctx.format_terminal_banner());
                    println!("\nDetailed Breakdown:");
                    println!(
                        "  Primary Requester: {} (PID {})",
                        ctx.primary_requester().comm,
                        ctx.primary_requester().pid
                    );
                    println!(
                        "  Target Command:    {}",
                        ctx.target_command.as_deref().unwrap_or("None")
                    );
                    println!(
                        "  Working Directory: {}",
                        ctx.primary_requester()
                            .cwd
                            .as_ref()
                            .map(|p| p.display().to_string())
                            .unwrap_or_else(|| "Unknown".to_string())
                    );
                    println!(
                        "  Ancestry Chain:    {}",
                        ctx.ancestry
                            .iter()
                            .map(|p| format!("{}({})", p.comm, p.pid))
                            .collect::<Vec<_>>()
                            .join(" -> ")
                    );
                }
                Err(e) => {
                    eprintln!("conduct: failed to inspect process: {}", e);
                    return ExitCode::FAILURE;
                }
            }
        }
        None => {
            // Default askpass mode (e.g. called as `conduct "[sudo] password for alice: "`)
            let opts = AskpassOptions {
                prompt: cli.prompt,
                target_pid: cli.pid,
                send_notification: !cli.no_notify,
                show_banner: !cli.no_banner,
            };
            if let Err(e) = askpass::run_askpass(opts) {
                eprintln!("conduct: askpass error: {}", e);
                return ExitCode::FAILURE;
            }
        }
    }

    ExitCode::SUCCESS
}
