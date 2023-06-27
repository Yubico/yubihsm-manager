extern crate yubihsmrs;

use std::fmt::Display;
use std::{fs, io, process, thread};
use std::convert::TryFrom;
use std::io::{BufRead, Cursor, stdin, stdout, Write};
use std::panic::resume_unwind;
use std::ptr::write;
use std::thread::sleep;
use std::time::Duration;
use clap::ErrorKind;
use yubihsmrs::object::{ObjectCapability, ObjectDescriptor, ObjectHandle};
use crossterm::{ExecutableCommand, execute, cursor::{DisableBlinking, EnableBlinking, MoveTo, RestorePosition, SavePosition}, event, cursor};
use crossterm::cursor::{MoveRight, MoveUp};
use crossterm::event::{Event, KeyCode, KeyEventKind, KeyModifiers, read};
use crossterm::style::Stylize;
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm_input::{input, InputEvent};
use yubihsmrs::{exit, Session};
/*
struct multi_select_item<T:Display> {
    item: T,
    selected:bool,
}
*/
#[derive(Debug)]
pub enum BooleanAnswer {
    Yes,
    No,
}

impl BooleanAnswer {
    fn from_str(value: &str) -> Result<BooleanAnswer, String> {
        let lowercase = value.to_lowercase();
        match lowercase.as_ref() {
            "y" | "yes" => Ok(BooleanAnswer::Yes),
            "n" | "no" => Ok(BooleanAnswer::No),
            _ => Err(format!("Unable to parse {}", value))
        }
    }
}

impl From<BooleanAnswer> for bool {
    fn from(ba: BooleanAnswer) -> bool {
        match ba {
            BooleanAnswer::Yes => true,
            BooleanAnswer::No => false,
        }
    }
}

fn read_line_or_die() -> String {
    let mut line = String::new();
    match stdin().read_line(&mut line) {
        Ok(_) => line.trim().to_owned(),
        Err(err) => {
            writeln!(stdout(), "Unable to read from stdin: {}", err);
            std::process::exit(1)
        }
    }
    /*
    let mut stdin_lock = stdin.lock();
    let line;
    if is_password {
        line = stdin_lock.read_passwd(stdout);
    } else {
        line = stdin_lock.read_line();
    }


    if let Ok(Some(line)) = line {
        line
    } else {
        stdout.write_all(b"Error\n").unwrap();
        //writeln!(stdout, "Unable to read from stdin: {}", err);
        std::process::exit(1)
    }
    */
}

pub fn get_string(prompt: &str, default_value: &str) -> String {
    write!(stdout(), "  {}", prompt);
    stdout().flush().unwrap();
    let line = read_line_or_die();
    //writeln!(stdout, "");
    //stdout.flush().unwrap();
    if line == String::from("") {
        String::from(default_value)
    } else {
        line
    }
}


pub fn get_integer<T>(prompt: &str, has_default_value: bool, default_value:T) -> T
    where
        T: std::str::FromStr,
        T: std::convert::From<u16>, // NOTE(adma): a FromStrRadix trait would be better
{
    loop {
        write!(stdout(), "  {}", prompt);
        stdout().flush().unwrap();
        let line = read_line_or_die();
        if line == "" && has_default_value {
            return default_value;
        }

        let parsed = if line.starts_with("0x") {
            u16::from_str_radix(&line[2..], 16)
        } else {
            line.parse()
        };

        match parsed {
            Ok(a) => {
                break a.into();
            }
            _ => {
                continue;
            }
        }
    }
}

pub fn parse_id(value: &str) -> Result<u16, String> {
    let id = if value.starts_with("0x") {
        u16::from_str_radix(&value[2..], 16)
    } else {
        value.parse()
    };

    if id.is_ok() {
        let id = id.unwrap();
        if id != 0 {
            return Ok(id);
        }
    }

    Err("ID must be a number in [1, 65535]".to_string())
}

pub fn get_boolean_answer(prompt: &str) -> BooleanAnswer {
    loop {
        write!(stdout(), "{} (y/n) ", prompt);
        stdout().flush().expect("Unable to flush stdout");
        match BooleanAnswer::from_str(&read_line_or_die()) {
            Ok(a) => {
                break a;
            }
            _ => {
                continue;
            }
        }
    }
}

pub fn get_domains(prompt: &str) -> Vec<yubihsmrs::object::ObjectDomain> {
    loop {
        write!(stdout(), "  {} ", prompt);
        stdout().flush().expect("Unable to flush stdout");
        match yubihsmrs::object::ObjectDomain::vec_from_str(&read_line_or_die()) {
            Ok(a) => {
                if a.is_empty() {
                    writeln!(stdout(), "You must select at least one domain");
                    continue;
                }

                if a.len() != 1
                    && !bool::from(get_boolean_answer(
                    "You have selected more than one domain, are you sure?",
                )) {
                    continue;
                }
                //writeln!("Using domains:");
                //a.iter().for_each(|domain| writeln!("\t {}", domain).unwrap());
                break a;
            }
            _ => {
                writeln!(stdout(), "Domains format is \"all\" or 1:2:3:...");
                continue;
            }
        }
    }
}

pub fn get_menu_option<T:Copy>(items: &[(String, T)]) -> T {
    for i in 0..items.len() {
        writeln!(stdout(), "  ({}) {}", i+1, items[i].0);
    }
    let mut choice: u16 = 0;
    while choice < 1 || choice > u16::try_from(items.len()).unwrap() {
        choice = get_integer("Your choice: ", false, 0);
    }
    items[usize::try_from(choice-1).unwrap()].1
}

pub fn get_multiselect_options<T:Display>(items: &mut Vec<(T, bool)>){
    // Get the number of capabilities
    let items_len = u16::try_from(items.len()).unwrap();

    // Print out the options
    writeln!(stdout(), "\n  Click space to select and unselect. Click 'Enter' when done.");
    for item in &mut *items {
        writeln!(stdout(), "  ( ) {}", item.0);
    }

    // Use these coordinates to restore position afterwards instead of the restore function because
    // Powershell calculates these positions differently from POSIX terminals
    let (current_x, current_y) = cursor::position().unwrap();

    let mut x = 3;
    let mut y = current_y - items_len;
    let y_offset = y;


    enable_raw_mode().expect("can run in raw mode");

    let input = input();
    let mut reader = input.read_sync();

    loop {

        execute!(stdout(), MoveTo(x, y)).unwrap();

        if let Some(input_event) = reader.next() {
            match input_event {
                InputEvent::Keyboard(crossterm_input::KeyEvent::Char(c)) => {
                    match c {
                        ' ' => {
                            let index = usize::try_from(y - y_offset).unwrap();
                            if items[index].1 {
                                write!(stdout(), " ").expect("Unable to print message!");
                                //items[index].1 = false;
                            } else {
                                write!(stdout(), "*").expect("Unable to print message!");
                                //items[index].1 = true;
                            }
                            items[index].1 = !items[index].1;
                        },
                        'q' => break,
                        _ => {},
                    }
                },
                InputEvent::Keyboard(crossterm_input::KeyEvent::Ctrl('c')) => {
                    execute!(stdout(), MoveTo(current_x, current_y)).unwrap();
                    disable_raw_mode().unwrap();
                    process::exit(1)
                },
                InputEvent::Keyboard(crossterm_input::KeyEvent::Enter) => break,
                InputEvent::Keyboard(crossterm_input::KeyEvent::Up) => {
                    y -= 1;
                    if y < y_offset {
                        y += items_len;
                    }
                },
                InputEvent::Keyboard(crossterm_input::KeyEvent::Down) => {
                    y += 1;
                    if y >= y_offset + items_len {
                        y = y_offset;
                    }
                },
                _ => {}, // Do nothing
            }
        }
    }

    //execute!(stdout(), RestorePosition).unwrap();
    execute!(stdout(), MoveTo(current_x, current_y)).unwrap();
    disable_raw_mode().unwrap();
}

pub fn get_selected_items<T:Copy>(items: &Vec<(T, bool)>) -> Vec<T>{
    // Return the selected items
    let mut selected_items: Vec<T> = Vec::new();
    for c in items {
        if c.1 {
            selected_items.push(c.0);
        }
    }
    selected_items
}

pub fn delete_objects(session:&Session, object_handles:Vec<ObjectHandle>) {
    if object_handles.len() == 1 {
        match session.delete_object(object_handles[0].object_id, object_handles[0].object_type) {
            Ok(..) => writeln!(stdout(), "Deleted {} with ID 0x{:x}", object_handles[0].object_type, object_handles[0].object_id),
            Err(_) => writeln!(stdout(), "Operation failed!"),
        };
    } else {
        let mut objects_options:Vec<(ObjectDescriptor, bool)> = Vec::new();
        for h in object_handles {
            objects_options.push((session.get_object_info(h.object_id, h.object_type).unwrap(), false));
        }
        get_multiselect_options(&mut objects_options);
        for object in objects_options {
            if object.1 {
                match session.delete_object(object.0.id, object.0.object_type) {
                    Ok(..) => writeln!(stdout(), "Deleted {} with id 0x{:x}", object.0.object_type,  object.0.id),
                    Err(_) => continue,
                };
            }
        }
    }
}

pub fn read_file() -> String {
    let mut file_path = get_string("Enter absolute path to PEM file: ", "");
    while file_path == "" {
        file_path = get_string("Enter absolute path to PEM file: ", "");
    }
    let contents = fs::read_to_string(file_path);
    match contents {
        Ok(..) => contents.unwrap(),
        Err(_) => {
            writeln!(stdout(), "Failed to read file.");
            read_file()
        }
    }
}
