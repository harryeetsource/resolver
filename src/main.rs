use windows::Win32::System::LibraryLoader::{GetProcAddress, LoadLibraryA};
use windows::Win32::Foundation::{FreeLibrary, HMODULE};
use windows::core::PCSTR;
use std::ffi::CString;

fn main() {
    // Print program information
    println!("arwin - win32 address resolution program - Rust edition");

    // Parse command-line arguments
    let args: Vec<String> = std::env::args().collect();
    if args.len() < 3 {
        eprintln!("Usage: {} <Library Name> <Function Name>", args[0]);
        std::process::exit(1);
    }

    let library_name = &args[1];
    let function_name = &args[2];

    // Convert library name and function name to C-compatible strings
    let library_name_cstr = CString::new(library_name.as_str())
        .expect("Failed to convert library name to CString");
    let function_name_cstr = CString::new(function_name.as_str())
        .expect("Failed to convert function name to CString");

    // Load the specified library
    let hmod_libname: HMODULE = unsafe {
        LoadLibraryA(PCSTR(library_name_cstr.as_ptr() as *const u8))
            .expect("Error: could not load library!")
    };

    // Get the address of the specified function
    let fprc_func = unsafe {
        GetProcAddress(hmod_libname, PCSTR(function_name_cstr.as_ptr() as *const u8))
            .expect("Error: could not find the function in the library!")
    };

    // Print the resolved function address
    println!(
        "{} is located at 0x{:08X} in {}",
        function_name,
        fprc_func as usize,
        library_name
    );

    // Free the loaded library
    unsafe { let _ = FreeLibrary(hmod_libname); };
}
