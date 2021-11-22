# dolphin-memory-rs

A crate for reading from and writing to the emulated memory of Dolphin in rust. A lot of internals here are directly based on [aldelaro5's Dolphin Memory Engine](https://github.com/aldelaro5/Dolphin-memory-engine).

Currently the only platform supported is Windows, though it should be possible to port it to other platforms.

## Examples

### Reading from Memory

A simplified example of reading the Game ID, using the GCM format.

```rust
use dolphin_memory::Dolphin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Searches for the dolphin process on loop. Dolphin::new will error
    // when the process isn't found, so you could choose to handle that however.
    let dolphin = loop {
        if let Ok(dolphin) = Dolphin::new() {
            break dolphin;
        }
    };

    // Reads the value at 0x80000000, which is the gcm header address.
    let header_address = 0x80000000;
    // The first 6 bytes of the header include the Game ID, which is a string.
    let game_id = dolphin.read_string(6, header_address, None)?;

    println!("Game ID: {}", game_id);

    Ok(())
}
```

### Bytes

Sometimes you want to read a specific number of bytes. All the convenience functions actually just wrap a call to `read` with a set number of bytes.

```rust
use dolphin_memory::Dolphin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dolphin = loop {
        if let Ok(dolphin) = Dolphin::new() {
            break dolphin;
        }
    };

    // The crate provides convenience functions for most common types, but you can also
    // use it to read raw bytes yourself. Note that when reading raw bytes it's up
    // to you to determine how to parse them (eg. if you're dealing with BigEndian data).
    let header_address = 0x80000000;
    let game_id_bytes = dolphin.read(6, header_address, None)?;

    println!(
        "Game ID: {}",
        String::from_utf8(game_id_bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::Other, e))?
    );

    Ok(())
}
```

### Pointers

It's not uncommon to have to deal with pointers in memory. Thankfully this crate makes that process easy.

```rust
use dolphin_memory::Dolphin;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dolphin = loop {
        if let Ok(dolphin) = Dolphin::new() {
            break dolphin;
        }
    };

    // Every call can also optionally follow a chain of pointer addresses.
    // To specify a list of pointers, supply a list of addresses in the
    // order that they need to be chained. The last address will read the actual
    // value at the end of the pointer chain.
    let some_ptr_addr = 0x81234567;
    let some_value_offset = 0xA4;
    let game_id_bytes = dolphin.read(6, some_ptr_addr, Some(&[some_value_offset]))?;

    Ok(())
}
```
