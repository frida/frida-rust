use frida_gum::DebugSymbol;
use frida_gum::{Gum, Module};
use lazy_static::lazy_static;

lazy_static! {
    static ref GUM: Gum = unsafe { Gum::obtain() };
}

fn main() {
    lazy_static::initialize(&GUM);

    let symbol = Module::find_export_by_name(None, "mmap").unwrap();
    let symbol_details = DebugSymbol::from_address(symbol).unwrap();
    println!(
        "address={:#x?} module_name={:?} symbol_name={:?} file_name={:?} line_number={:?}",
        symbol_details.address(),
        symbol_details.module_name(),
        symbol_details.symbol_name(),
        symbol_details.file_name(),
        symbol_details.line_number()
    );
    println!("{:?}", symbol_details);

    let symbol_details = DebugSymbol::from_name("open").unwrap();
    println!(
        "address={:#x?} module_name={:?} symbol_name={:?} file_name={:?} line_number={:?}",
        symbol_details.address(),
        symbol_details.module_name(),
        symbol_details.symbol_name(),
        symbol_details.file_name(),
        symbol_details.line_number()
    );
    println!("{:?}", symbol_details);
}
