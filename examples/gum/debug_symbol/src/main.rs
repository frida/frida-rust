use frida_gum::DebugSymbol;
use frida_gum::{Gum, Module};
use std::sync::OnceLock;

fn main() {
    static CELL: OnceLock<Gum> = OnceLock::new();
    let _gum = CELL.get_or_init(|| Gum::obtain());

    let symbol = Module::find_global_export_by_name("mmap").unwrap();
    let symbol_details = DebugSymbol::from_address(symbol).unwrap();
    println!(
        "address={:#x?} module_name={:?} symbol_name={:?} file_name={:?} line_number={:?}",
        symbol_details.address(),
        symbol_details.module_name(),
        symbol_details.symbol_name(),
        symbol_details.file_name(),
        symbol_details.line_number()
    );
    println!("{symbol_details:?}");

    let symbol_details = DebugSymbol::from_name("open").unwrap();
    println!(
        "address={:#x?} module_name={:?} symbol_name={:?} file_name={:?} line_number={:?}",
        symbol_details.address(),
        symbol_details.module_name(),
        symbol_details.symbol_name(),
        symbol_details.file_name(),
        symbol_details.line_number()
    );
    println!("{symbol_details:?}");
}
