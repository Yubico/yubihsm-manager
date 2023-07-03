extern crate yubihsmrs;

use std::fmt::Display;
use std::{fmt, fs, process};
use std::convert::TryFrom;
use std::fs::File;
use std::io::{stdin, stdout, Write};
use std::num::IntErrorKind;
use std::ops::Deref;
use yubihsmrs::object::{ObjectDescriptor, ObjectDomain, ObjectHandle};
use crossterm::{execute, cursor::{MoveTo}, cursor};
use crossterm::terminal::{disable_raw_mode, enable_raw_mode};
use crossterm_input::{input, InputEvent};
use crossterm_screen::RawScreen;
use crossterm_utils::ErrorKind::ParseIntError;
use yubihsmrs::{Session};
use error::MgmError;

pub struct MultiSelectItem<T:Display> {
    pub item: T,
    pub selected:bool,
}

#[derive(Debug, Clone)]
pub struct BasicDiscriptor {
    pub object_id: u16,
    pub object_label:String,
}

impl Display for BasicDiscriptor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "0x{:04x} : {}", self.object_id, self.object_label)
    }
}


#[derive(Debug)]
pub enum BooleanAnswer {
    Yes,
    No,
}

impl BooleanAnswer {
    fn from_str(value: &str) -> Result<BooleanAnswer, MgmError> {
        let lowercase = value.to_lowercase();
        match lowercase.as_ref() {
            "y" | "yes" => Ok(BooleanAnswer::Yes),
            "n" | "no" => Ok(BooleanAnswer::No),
            _ => Err(MgmError::InvalidInput(value.to_string()))
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
        Err(err) => panic!("Unable to read from stdin: {}", err),
    }
}

pub fn get_string(prompt: &str) -> String {
    print!("  {}", prompt);
    stdout().flush().expect("Unable to flush stdout");
    read_line_or_die()
}

pub fn get_string_or_default(prompt: &str, default_value: &str) -> String {
    let line = get_string(prompt);
    if line == *"" {
        default_value.to_string()
    } else {
        line
    }
}


fn get_integer<T>(prompt: &str) -> T
    where
        T: std::str::FromStr,
        T: From<u16>, // NOTE(adma): a FromStrRadix trait would be better
{
    loop {
        print!("  {} ", prompt);
        stdout().flush().expect("Unable to flush stdout");
        let line = read_line_or_die();

        let parsed = if line.starts_with("0x") {
            u16::from_str_radix(&line[2..], 16)
        } else {
            line.parse()
        };

        match parsed {
            Ok(a) => break a.into(),
            Err(err) => {
                match err.kind() {
                    IntErrorKind::Empty => break 0.into(),
                    _ => continue,
                }
            },
        }
    }
}

pub fn get_integer_or_default<T:std::str::FromStr+From<u16>>(prompt: &str, default_value:T) -> T {
    let integer:u16 = get_integer(prompt);
    if integer == 0 {
        default_value
    } else {
        integer.into()
    }
}

pub fn parse_id(value: &str) -> Result<u16, String> {
    let id = if value.starts_with("0x") {
        u16::from_str_radix(&value[2..], 16)
    } else {
        value.parse()
    };

    match id {
        Ok(id) => Ok(id),
        Err(err) => Err("ID must be a number in [1, 65535]".to_string()),
    }
}

pub fn get_boolean_answer(prompt: &str) -> BooleanAnswer {
    loop {
        print!("{} (y/n) ", prompt);
        stdout().flush().expect("Unable to flush stdout");
        match BooleanAnswer::from_str(&read_line_or_die()) {
            Ok(a) => break a,
            _ => continue,
        }
    }
}

pub fn get_domains(prompt: &str) -> Vec<ObjectDomain> {
    loop {
        print!("  {} ", prompt);
        stdout().flush().expect("Unable to flush stdout");
        match ObjectDomain::vec_from_str(&read_line_or_die()) {
            Ok(a) => {
                if a.is_empty() {
                    println!("You must select at least one domain");
                    continue;
                }
                break a;
            }
            _ => {
                println!("Domains format is \"all\" or 1:2:3:...");
                continue;
            }
        }
    }
}

pub fn get_common_properties() -> (u16, String, Vec<ObjectDomain>) {
    let mut key_id: u16 = get_integer_or_default("Enter key ID [Default 0]: ", 0);
    let label = get_string_or_default("Enter key label [Default empty]: ", "");
    let domains = get_domains("Enter domain(s), multiple domains are separated by ',' [1-16]: ");
    (key_id, label, domains)
}

pub fn get_menu_option<T:Clone>(items: &Vec<(String, T)>) -> T {
    for i in 0..items.len() {
        println!("  ({}) {}", i+1, items[i].0);
    }
    let mut choice: u16 = 0;
    while choice < 1 || choice > u16::try_from(items.len()).unwrap() {
        choice = get_integer("Your choice: ");
    }
    items[usize::try_from(choice-1).unwrap()].1.clone()
}

pub fn get_multiselect_options<T:Display>(items: &mut Vec<MultiSelectItem<T>>){
    // Get the number of capabilities
    let items_len = u16::try_from(items.len()).unwrap();

    // Print out the options
    println!("\n  Click space to select and unselect. Click 'Enter' when done.");
    for item in &mut *items {
        println!("  [ ] {}", item.item);
    }

    // Use these coordinates to restore position afterwards instead of the restore function because
    // Powershell calculates these positions differently from POSIX terminals
    let (current_x, current_y) = cursor::position().expect("Unable to read cursor position");

    let x = 3;
    let mut y = current_y - items_len;
    let y_offset = y;

    stdout().flush().expect("Unable to flush stdout");

    //enable_raw_mode().expect("Unable to run in raw mode");
    let raw = RawScreen::into_raw_mode();

    //let input = input();
    let mut reader = input().read_sync();

    loop {

        execute!(stdout(), MoveTo(x, y)).expect("Unable to move cursor");

        if let Some(input_event) = reader.next() {
            match input_event {
                InputEvent::Keyboard(crossterm_input::KeyEvent::Char(c)) => {
                    match c {
                        ' ' => {
                            let index = usize::try_from(y - y_offset).unwrap();
                            if items[index].selected {
                                print!(" ");
                                //items[index].1 = false;
                            } else {
                                print!("*");
                                //items[index].1 = true;
                            }
                            items[index].selected = !items[index].selected;
                        },
                        'q' => break,
                        _ => {},
                    }
                },
                InputEvent::Keyboard(crossterm_input::KeyEvent::Ctrl('c')) => {
                    execute!(stdout(), MoveTo(current_x, current_y)).expect("Unable to restore cursor");
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
    execute!(stdout(), MoveTo(current_x, current_y)).expect("Unable to restore cursor");
    //disable_raw_mode().unwrap();
    drop(raw);
    stdout().flush().expect("Unable to flush stdout()");
}

pub fn get_selected_items<T:Copy+Display>(items: &Vec<MultiSelectItem<T>>) -> Vec<T>{
    let mut selected_items: Vec<T> = Vec::new();
    for c in items {
        if c.selected {
            selected_items.push(c.item);
        }
    }
    selected_items
}

pub fn delete_objects(session: Option<&Session>, object_handles:Vec<ObjectHandle>) -> Result<(), MgmError> {
    match session {
        None => {
            if object_handles.len() == 1 {
                println!("  > yubihsm-shell -a delete-object -i {} -t {}", object_handles[0].object_id, object_handles[0].object_type);
            } else {
                println!("  > yubihsm-shell -a delete-object -i <OBJECT_ID> -t <OBJECT_TYPE>");
            }
        },
        Some(session) => {
            if object_handles.len() == 1 {
                session.delete_object(object_handles[0].object_id, object_handles[0].object_type)?;
                println!("Deleted {} with ID 0x{:x}", object_handles[0].object_type, object_handles[0].object_id);
            } else {
                let mut objects_options:Vec<MultiSelectItem<ObjectDescriptor>> = Vec::new();
                for h in object_handles {
                    objects_options.push(MultiSelectItem{item: session.get_object_info(h.object_id, h.object_type)?, selected: false});
                }
                get_multiselect_options(&mut objects_options);
                for object in objects_options {
                    if object.selected {
                        session.delete_object(object.item.id, object.item.object_type)?;
                        println!("Deleted {} with id 0x{:x}", object.item.object_type,  object.item.id);
                    }
                }
            }
        }
    }
    Ok(())
}

pub fn read_file(prompt:&str) -> String {
    let mut file_path = "".to_string();
    while file_path == "" {
        file_path = get_string(prompt);
    }
    match fs::read_to_string(file_path) {
        Ok(content) => content,
        Err(error) => {
            println!("Failed to read file: {}", error);
            read_file(prompt)
        }
    }
}

pub fn write_file(content: Vec<u8>, filename:String) -> Result<(), MgmError> {
    let mut file = File::create(filename)?;
    file.write_all(content.deref())?;
    Ok(())
}
