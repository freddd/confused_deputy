use std::path::Path;
use std::{env, fs};

use hcl::Expression;

fn main() {
    let args: Vec<String> = env::args().collect();

    if args.len() < 2 {
        println!("Usage: {} <directory>", args[0]);
        return;
    }

    let directory = &args[1];

    if let Err(e) = find_terraform_files(directory) {
        println!("Error: {}", e);
    }
}

fn find_terraform_files(dir: &str) -> Result<(), Box<dyn std::error::Error>> {
    let path = Path::new(dir);

    if path.is_dir() {
        for entry in fs::read_dir(path)? {
            let entry = entry?;
            let path = entry.path();
            if path.is_dir() {
                find_terraform_files(path.to_str().unwrap())?;
            } else if path.is_file() && path.extension().unwrap_or_default() == "tf" {
                check_terraform_file(path.to_str().unwrap())?;
            }
        }
    }
    Ok(())
}

fn check_terraform_file(filepath: &str) -> Result<(), Box<dyn std::error::Error>> {
    let content: String = fs::read_to_string(filepath)?;
    let body = hcl::parse(&content).unwrap();

    for block in body.blocks() {
        if block.identifier == "data".into()
            && !block.labels.is_empty()
            && block.labels[0] =="aws_iam_policy_document".into()
        {
            block.body.iter().for_each(|structure| {
                let mut is_deny = false;
                let mut is_service = false;
                let mut has_condition = false;

                match structure {
                    hcl::Structure::Attribute(_) => {}
                    hcl::Structure::Block(block) => {
                        block.body.iter().for_each(|inner: &hcl::Structure| {
                            match inner {
                                hcl::Structure::Attribute(attribute) => {
                                    if attribute.key() == "effect"
                                        && attribute.expr == Expression::String("Deny".into())
                                    {
                                        is_deny = true;
                                    }
                                }
                                hcl::Structure::Block(block) => {
                                    match block.identifier().to_lowercase().as_str() {
                                        "principals" => {
                                            block.body().iter().for_each(|structure| {
                                                if structure.is_attribute() {
                                                    let principal = structure.as_attribute().unwrap();
                                                    if principal.key() == "type"
                                                        && principal.expr
                                                            == Expression::String("Service".into())
                                                    {
                                                        is_service = true;
                                                    }
                                                }
                                            });
                                        }
                                        "condition" => {
                                            has_condition = true;
                                        }
                                        _ => return,
                                    }
                                }
                            }
                        });
                    }
                }

                if !is_deny && is_service && !has_condition {
                    println!("{}, {}", filepath, block.labels[1].as_str());
                }
            });
        }
    }

    Ok(())
}
