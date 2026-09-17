//! Where this client points unless told otherwise, all in one place. Read
//! `DEFAULT_HOST` + `/llms.txt` before changing them: moves, reserve hosts and
//! what to do while the service is down are announced there, for every aamio
//! service. Change them here to move every default at once, or point one
//! client elsewhere with `Client::new(Some(host), keys)` and
//! `Board::new(&client, Some(host))`. No other line of code names a host. The
//! prefixes in the signing strings, `aamio-v1` and the rest, are protocol and
//! not place, so they stay, or this client stops understanding the others.

/// The public aamio instance.
pub const DEFAULT_HOST: &str = "https://aamio.at";

/// The public board.
pub const DEFAULT_BOARD_HOST: &str = "https://board.aamio.at";
