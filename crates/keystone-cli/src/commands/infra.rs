//! `keystone infra cdk init|print|render|sync-profile`.
//!
//! Generation only. Per the design, "Keystone source generation must not
//! automatically run `cdk deploy`" — every path here ends by telling the user
//! what to run, never by running it.

use keystone_core::error::{KeystoneError, Result};
use keystone_infra::{GeneratedProject, StackOutputs, WriteOutcome, WriteReport};

use crate::cli::{CdkCommand, CdkInitArgs, CdkPrintArgs, CdkRenderArgs, CdkSyncProfileArgs};
use crate::context::{print_line, Context};

pub fn run(context: &Context, command: &CdkCommand) -> Result<()> {
    match command {
        CdkCommand::Init(args) => init(context, args),
        CdkCommand::Print(args) => print(context, args),
        CdkCommand::Render(args) => render(context, args),
        CdkCommand::SyncProfile(args) => sync_profile(context, args),
    }
}

fn init(context: &Context, args: &CdkInitArgs) -> Result<()> {
    let profile = context.load_profile(&args.plan.profile)?;
    let plan = crate::plan::build(context, &args.plan, &profile)?;
    let project = GeneratedProject::render(&plan, context.now())?;

    let report = project.write(&args.output, args.force)?;
    report_written(context, &report);
    if report.has_conflicts() {
        // Not an error: the files that were not modified are up to date, and the
        // user may well want to keep their edits. But the exit status has to say
        // the project is not fully what Keystone would generate.
        return Err(KeystoneError::InvalidConfiguration(format!(
            "{} generated file(s) have local modifications and were left alone. Re-run with \
             --force to overwrite them.",
            report.skipped().len()
        )));
    }

    context.note("");
    context.note("Review the stack, then deploy it yourself:");
    context.note(format!("    cd {} && npm install", args.output.display()));
    context.note("    npx cdk deploy --outputs-file cdk-outputs.json");
    context.note(format!(
        "    keystone infra cdk sync-profile --profile {} --outputs {}",
        args.plan.profile,
        args.output.join("cdk-outputs.json").display()
    ));
    Ok(())
}

/// Print every generated file to standard output, with a header per file.
fn print(context: &Context, args: &CdkPrintArgs) -> Result<()> {
    let profile = context.load_profile(&args.plan.profile)?;
    let plan = crate::plan::build(context, &args.plan, &profile)?;
    let project = GeneratedProject::render(&plan, context.now())?;

    for (path, contents) in project.as_map() {
        print_line(&format!("===== {path} ====="))?;
        print_line(contents.trim_end())?;
        print_line("")?;
    }
    Ok(())
}

/// Print one generated file, unadorned, so it can be diffed or piped.
fn render(context: &Context, args: &CdkRenderArgs) -> Result<()> {
    let profile = context.load_profile(&args.plan.profile)?;
    let plan = crate::plan::build(context, &args.plan, &profile)?;
    let project = GeneratedProject::render(&plan, context.now())?;

    let file = project.file(&args.file).ok_or_else(|| {
        KeystoneError::InvalidConfiguration(format!(
            "no generated file named {:?}. This project contains: {}",
            args.file,
            project
                .files
                .iter()
                .map(|file| file.path.as_str())
                .collect::<Vec<_>>()
                .join(", ")
        ))
    })?;
    print_line(file.contents.trim_end())
}

fn sync_profile(context: &Context, args: &CdkSyncProfileArgs) -> Result<()> {
    let outputs = StackOutputs::read(&args.outputs, args.stack_name.as_deref())?;
    let report = keystone_infra::sync_profile(&context.store, &args.profile, &outputs, args.force)?;

    for (field, outcome) in &report.fields {
        match outcome {
            keystone_infra::FieldOutcome::Filled { value } => {
                context.note(format!("{field}: set to {value}"));
            }
            keystone_infra::FieldOutcome::Unchanged { value } => {
                context.detail(format!("{field}: already {value}"));
            }
            keystone_infra::FieldOutcome::Overwritten { previous, value } => {
                context.note(format!("{field}: {previous} -> {value}"));
            }
            keystone_infra::FieldOutcome::Conflict { existing, incoming } => {
                context.note(format!(
                    "{field}: conflict — profile has {existing}, stack {} reports {incoming}",
                    report.stack_name
                ));
            }
        }
    }

    if report.has_conflicts() {
        // Nothing was written: a partial merge would leave the profile holding a
        // trust anchor from one deployment and a role from another.
        return Err(KeystoneError::InvalidConfiguration(format!(
            "profile {:?} already records different values for {}. Nothing was changed. Re-run \
             with --force to replace them, or check that {} is the deployment this profile \
             belongs to.",
            report.profile_name,
            report
                .conflicts()
                .iter()
                .map(|(field, _)| *field)
                .collect::<Vec<_>>()
                .join(", "),
            report.stack_name
        )));
    }

    if report.saved {
        context.note(format!(
            "Profile {:?} updated from stack {}.",
            report.profile_name, report.stack_name
        ));
        context.note(format!("    keystone test --profile {}", args.profile));
    } else {
        context.note(format!(
            "Profile {:?} already matches stack {}; nothing to do.",
            report.profile_name, report.stack_name
        ));
    }
    Ok(())
}

/// Summarize what a project write did, one line per changed file.
pub fn report_written(context: &Context, report: &WriteReport) {
    for (path, outcome) in &report.outcomes {
        match outcome {
            WriteOutcome::Created => context.note(format!("  create  {path}")),
            WriteOutcome::Replaced => context.note(format!("  update  {path}")),
            WriteOutcome::Unchanged => context.detail(format!("  ok      {path}")),
            WriteOutcome::SkippedModified => {
                context.note(format!("  skip    {path} (modified locally)"));
            }
        }
    }
    context.note(format!(
        "{} file(s) written to {} ({} unchanged)",
        report.count(WriteOutcome::Created) + report.count(WriteOutcome::Replaced),
        report.root.display(),
        report.count(WriteOutcome::Unchanged)
    ));
}
