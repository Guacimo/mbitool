# Mbitool
This is meant to be a builder for NXP mbi images.
The tool is based on other code that was made to perform this task.
The goal is to use define the entire mbi structure as Rust types.
BinRW is meant to serialize and deserialize the structures into the actual binary format.
The original code it was based on is in the `original_code.rs` file.
The `mbi.rs` file contains the data structures that were made to copy that functionality.
It is still in a rough shape but should be a good basis for making the mbi images serializable and deserializable.
