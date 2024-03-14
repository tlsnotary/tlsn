use std::collections::VecDeque;

pub struct Args {
    pub defer_decryption: bool,
    pub sizes: VecDeque<usize>,
}

pub struct BenchOptions {
    pub defer_decryption: bool,
    pub size: usize,
}

impl Args {
    pub fn split_off(&mut self) -> Option<BenchOptions> {
        if self.sizes.is_empty() {
            return None;
        }

        let options = BenchOptions {
            defer_decryption: self.defer_decryption,
            size: self.sizes.pop_front().unwrap(),
        };

        Some(options)
    }
}

// Parse command line arguments
pub fn arg_parse() -> Args {
    let args: Vec<String> = std::env::args().into_iter().collect();

    let defer_decryption = args.iter().any(|arg| arg == "--defer");

    let sizes_arg_position = args.iter().position(|arg| arg == "--size");
    let sizes = if let Some(pos) = sizes_arg_position {
        let sizes = args
            .iter()
            .nth(pos + 1)
            .expect("Should specify traffic size in bytes");

        sizes
            .split(',')
            .map(|size| {
                size.parse::<usize>()
                    .expect("Size arguments should be parsable to usize")
            })
            .collect::<VecDeque<usize>>()
    } else {
        VecDeque::from([2048, 4096, 8192])
    };

    Args {
        defer_decryption,
        sizes,
    }
}
